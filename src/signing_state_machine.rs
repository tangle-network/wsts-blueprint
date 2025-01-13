use rand::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, MessageDestination, Mpc, MpcParty, ProtocolMessage,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::keygen_state_machine::{HasRecipient, WstsState};
use crate::signing::SigningError;
use frost_secp256k1_tr::{Ciphersuite, Secp256K1Sha256TR, VerifyingKey};
use itertools::Itertools;
use p256k1::point::Point;
use p256k1::scalar::Scalar;
use round_based::SinkExt;
use serde::{Deserialize, Serialize};
use wsts::common::Signature;
use wsts::v2::Party;
use wsts::{
    common::{PublicNonce, SignatureShare},
    v2::{PartyState, SignatureAggregator},
};

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct WstsSigningState {
    pub party_id: u32,
    pub party_key_ids: HashMap<u32, Vec<u32>>,
    pub party_nonces: HashMap<u32, PublicNonce>,
    pub signature_shares: HashMap<u32, SignatureShare>,
    pub n_signers: usize,
    pub threshold: u32,
    pub message: Vec<u8>,
    pub public_key_frost_format: Vec<u8>,
    pub party: Arc<parking_lot::Mutex<Option<PartyState>>>,
    pub aggregated_signature: Option<Arc<SerializeableSignature>>,
    pub signature_frost_format: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[allow(non_snake_case)]
pub struct SerializeableSignature {
    pub R: Point,
    /// The sum of the party signatures
    pub z: Scalar,
}

impl From<Signature> for SerializeableSignature {
    fn from(sig: Signature) -> Self {
        SerializeableSignature { R: sig.R, z: sig.z }
    }
}

impl From<SerializeableSignature> for Signature {
    fn from(sig: SerializeableSignature) -> Self {
        Signature { R: sig.R, z: sig.z }
    }
}

impl WstsSigningState {
    pub fn new(
        party_id: u32,
        n_signers: usize,
        threshold: u32,
        message: Vec<u8>,
        public_key_frost_format: Vec<u8>,
    ) -> Self {
        WstsSigningState {
            party_id,
            n_signers,
            threshold,
            message,
            public_key_frost_format,
            ..Default::default()
        }
    }
}

#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Msg {
    Round1(Round1Msg),
    Round2(Round2Msg),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Round1Msg {
    source: u32,
    key_ids: Vec<u32>,
    nonce: PublicNonce,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Round2Msg {
    source: u32,
    signature_share: SignatureShare,
}

pub async fn wsts_signing_protocol<M, R: CryptoRng + RngCore>(
    network: M,
    keygen_state: &WstsState,
    message: Vec<u8>,
    rng: &mut R,
) -> Result<WstsSigningState, SigningError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let (mut signer, threshold) = {
        let lock = keygen_state.party.lock();
        let state = lock
            .as_ref()
            .ok_or_else(|| SigningError::ContextError("Party not found".to_string()))?;
        let threshold = state.threshold;
        let signer = Party::load(state);
        drop(lock);
        (signer, threshold)
    };

    let n_signers = keygen_state.n_signers;
    let MpcParty { delivery, .. } = network.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut state = WstsSigningState::new(
        signer.party_id,
        n_signers,
        threshold,
        message.clone(),
        keygen_state.public_key_frost_format.clone(),
    );

    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<Round1Msg>::broadcast(
        state.party_id as _,
        n_signers as _,
    ));
    let round2 = rounds.add_round(RoundInput::<Round2Msg>::broadcast(
        state.party_id as _,
        n_signers as _,
    ));
    let mut rounds = rounds.listen(incomings);

    // Round 1: Generate and broadcast nonce
    let nonce = signer.gen_nonce(rng);
    let key_ids = signer.key_ids.clone();

    let my_round1 = Round1Msg {
        source: signer.party_id,
        key_ids: key_ids.clone(),
        nonce: nonce.clone(),
    };

    let msg = Msg::Round1(my_round1.clone());
    send_message::<M, _>(msg, &mut outgoings).await?;

    let round1_msgs = rounds
        .complete(round1)
        .await
        .map_err(|err| SigningError::MpcError(err.to_string()))?;

    let round1_msgs: HashMap<u32, Round1Msg> = round1_msgs
        .into_iter_including_me(my_round1)
        .map(|r| (r.source, r))
        .collect();

    // Process round 1 messages
    for (party_id, msg) in round1_msgs {
        state.party_key_ids.insert(party_id, msg.key_ids);
        state.party_nonces.insert(party_id, msg.nonce);
    }

    // Sort and prepare for signing
    let party_ids = state
        .party_key_ids
        .keys()
        .copied()
        .sorted_by(|a, b| a.cmp(b))
        .collect_vec();
    let party_key_ids = state
        .party_key_ids
        .clone()
        .into_iter()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .flat_map(|r| r.1)
        .collect_vec();
    let party_nonces = state
        .party_nonces
        .clone()
        .into_iter()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .map(|r| r.1)
        .collect_vec();

    // Round 2: Generate and broadcast signature share
    let signature_share = signer.sign(&message, &party_ids, &party_key_ids, &party_nonces);

    let my_round2 = Round2Msg {
        source: signer.party_id,
        signature_share: signature_share.clone(),
    };

    let msg = Msg::Round2(my_round2.clone());
    send_message::<M, _>(msg, &mut outgoings).await?;

    let round2_msgs = rounds
        .complete(round2)
        .await
        .map_err(|err| SigningError::MpcError(err.to_string()))?;

    let round2_msgs: HashMap<u32, Round2Msg> = round2_msgs
        .into_iter_including_me(my_round2)
        .map(|r| (r.source, r))
        .collect();

    // Process round 2 messages
    for (party_id, msg) in round2_msgs {
        state.signature_shares.insert(party_id, msg.signature_share);
    }

    // Sort signature shares and aggregate
    let signature_shares = state
        .signature_shares
        .clone()
        .into_iter()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .map(|r| r.1)
        .collect_vec();

    let public_key_comm = keygen_state
        .poly_commitments
        .iter()
        .sorted_by(|r1, r2| r1.0.cmp(r2.0))
        .map(|r| r.1.clone())
        .collect_vec();

    // Create signature aggregator
    let mut sig_agg =
        SignatureAggregator::new(state.n_signers as u32, state.threshold, public_key_comm)
            .map_err(|err| SigningError::MpcError(err.to_string()))?;

    // Generate final signature
    let wsts_sig = sig_agg
        .sign(&message, &party_nonces, &signature_shares, &party_key_ids)
        .map_err(|err| SigningError::MpcError(err.to_string()))?;

    // Verify WSTS signature
    let compressed_public_key =
        p256k1::point::Compressed::try_from(state.public_key_frost_format.as_slice())
            .map_err(|_| SigningError::InvalidPublicKey)?;

    let wsts_public_key = p256k1::point::Point::try_from(&compressed_public_key)
        .map_err(|_| SigningError::InvalidPublicKey)?;

    if !wsts_sig.verify(&wsts_public_key, &message) {
        return Err(SigningError::InvalidSignature);
    }

    // Convert to FROST format and verify
    let mut signature_bytes = [0u8; 33 + 32];
    let r = wsts_sig.R.compress();
    signature_bytes[0..33].copy_from_slice(&r.data);
    signature_bytes[33..].copy_from_slice(&wsts_sig.z.to_bytes());

    state.signature_frost_format = signature_bytes.to_vec();

    let frost_signature = frost_secp256k1_tr::Signature::deserialize(&signature_bytes)
        .map_err(|_| SigningError::InvalidFrostSignature)?;

    let frost_verifying_key =
        VerifyingKey::deserialize(state.public_key_frost_format.clone().try_into().unwrap())
            .map_err(|_| SigningError::InvalidFrostVerifyingKey)?;

    frost_verifying_key
        .verify(&message, &frost_signature)
        .map_err(|_| SigningError::InvalidFrostVerification)?;

    Secp256K1Sha256TR::verify_signature(&message, &frost_signature, &frost_verifying_key)
        .map_err(|_| SigningError::InvalidFrostVerification)?;

    state.party = Arc::new(parking_lot::Mutex::new(Some(signer.save())));
    state.aggregated_signature = Some(Arc::new(wsts_sig.into()));

    Ok(state)
}

impl HasRecipient for Msg {
    fn recipient(&self) -> MessageDestination {
        match self {
            Msg::Round1(_) | Msg::Round2(_) => MessageDestination::AllParties,
        }
    }
}

pub async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), SigningError>
where
    Msg: HasRecipient,
    M: Mpc<ProtocolMessage = Msg>,
{
    let recipient = msg.recipient();
    let msg = round_based::Outgoing { recipient, msg };
    tx.send(msg)
        .await
        .map_err(|e| SigningError::DeliveryError(e.to_string()))?;

    Ok(())
}
