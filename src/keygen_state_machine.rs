use rand::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, MessageDestination, Mpc, MpcParty, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::keygen::KeygenError;
use blueprint_sdk::logging::{info, trace};
use frost_secp256k1_tr::VerifyingKey;
use itertools::Itertools;
use round_based::SinkExt;
use std::sync::Arc;
use wsts::common::PolyCommitment;
use wsts::v2::{Party, PartyState};
use wsts::Scalar;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct WstsState {
    pub party_id: u32,
    pub shares: HashMap<u32, HashMap<u32, Scalar>>,
    pub key_ids: HashMap<u32, Vec<u32>>,
    pub poly_commitments: HashMap<u32, PolyCommitment>,
    pub n_signers: usize,
    pub party: Arc<parking_lot::Mutex<Option<PartyState>>>,
    pub public_key_frost_format: Vec<u8>,
}

impl WstsState {
    pub fn new(party_id: u32, n_signers: usize) -> Self {
        WstsState {
            party_id,
            n_signers,
            ..Default::default()
        }
    }
}

#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
pub enum Msg {
    KeygenBroadcast(KeygenMsg),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeygenMsg {
    source: u32,
    shares: HashMap<u32, Scalar>,
    key_ids: Vec<u32>,
    poly_commitment: PolyCommitment,
}

pub async fn wsts_protocol<M, R: CryptoRng + RngCore>(
    network: M,
    signer: &mut Party,
    n_signers: usize,
    rng: &mut R,
) -> Result<WstsState, KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let MpcParty { delivery, .. } = network.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut state = WstsState::new(signer.party_id, n_signers);

    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<KeygenMsg>::broadcast(
        state.party_id as _,
        n_signers as _,
    ));
    let mut rounds = rounds.listen(incomings);
    // Broadcast our keygen data
    let shares: HashMap<u32, Scalar> = signer.get_shares().into_iter().collect();
    let key_ids = signer.key_ids.clone();
    let poly_commitment = signer.get_poly_commitment(rng);

    let my_broadcast = KeygenMsg {
        source: signer.party_id,
        shares: shares.clone(),
        key_ids: key_ids.clone(),
        poly_commitment: poly_commitment.clone(),
    };
    let msg = Msg::KeygenBroadcast(my_broadcast.clone());

    send_message::<M, _>(msg, &mut outgoings).await?;
    let messages = rounds
        .complete(round1)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;

    let messages: HashMap<u32, KeygenMsg> = messages
        .into_iter_including_me(my_broadcast)
        .map(|r| ((r.source) as _, r))
        .collect();

    // Load the state
    for (party_id, msg) in messages {
        state.shares.insert(party_id, msg.shares);
        state.key_ids.insert(party_id, msg.key_ids);
        state.poly_commitments.insert(party_id, msg.poly_commitment);
    }

    trace!(
        "Received shares: {:?}",
        state.shares.keys().collect::<Vec<_>>()
    );
    // Generate the party_shares: for each key id we own, we take our received key share at that
    // index
    let party_shares = signer
        .key_ids
        .iter()
        .copied()
        .map(|key_id| {
            let mut key_shares = HashMap::new();

            for (id, shares) in &state.shares {
                key_shares.insert(*id, shares[&key_id]);
            }

            (key_id, key_shares.into_iter().collect())
        })
        .collect();

    let polys = state
        .poly_commitments
        .iter()
        .sorted_by(|a, b| a.0.cmp(b.0))
        .map(|r| r.1.clone())
        .collect_vec();

    signer
        .compute_secret(&party_shares, &polys)
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;

    let party = signer.save();

    // Convert the WSTS group key into a FROST-compatible format
    let group_point = party.group_key;
    let compressed_group_point = group_point.compress();
    let verifying_key = VerifyingKey::deserialize(&compressed_group_point.data).map_err(|e| {
        KeygenError::MpcError(format!("Failed to convert group key to VerifyingKey: {e}"))
    })?;

    let public_key_frost_format = verifying_key.serialize().expect("Failed to serialize key");
    state.public_key_frost_format = public_key_frost_format;
    state.party = Arc::new(parking_lot::Mutex::new(Some(party)));

    info!("Keygen finished computing secret");

    Ok(state)
}

pub trait HasRecipient {
    fn recipient(&self) -> MessageDestination;
}

impl HasRecipient for Msg {
    fn recipient(&self) -> MessageDestination {
        match self {
            Msg::KeygenBroadcast(_) => MessageDestination::AllParties,
        }
    }
}

pub async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), KeygenError>
where
    Msg: HasRecipient,
    M: Mpc<ProtocolMessage = Msg>,
{
    let recipient = msg.recipient();
    let msg = round_based::Outgoing { recipient, msg };
    tx.send(msg)
        .await
        .map_err(|e| KeygenError::DeliveryError(e.to_string()))?;

    Ok(())
}
