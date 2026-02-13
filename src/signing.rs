use crate::context::wsts_ctx;
use crate::{SignRequest, SignResult};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::info;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use round_based::PartyIndex;
use std::collections::HashMap;

const SIGNING_SALT: &str = "wsts-signing";

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("MPC protocol error: {0}")]
    MpcError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Delivery error: {0}")]
    DeliveryError(String),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid FROST signature")]
    InvalidFrostSignature,

    #[error("Invalid FROST verifying key")]
    InvalidFrostVerifyingKey,

    #[error("Invalid FROST verification")]
    InvalidFrostVerification,
}

/// Signs a message using the WSTS protocol with a previously generated key.
pub async fn sign(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<SignRequest>,
) -> Result<TangleResult<SignResult>, String> {
    let ctx = wsts_ctx();
    let keygen_call_id = request.keygen_call_id;
    let message = request.message.to_vec();

    // Get party info from connected peers
    let mut all_peers = ctx.network_backend.peers();
    let local_peer_id = ctx.network_backend.local_peer_id;
    if !all_peers.contains(&local_peer_id) {
        all_peers.push(local_peer_id);
    }
    all_peers.sort();

    let n = all_peers.len() as u16;
    let i = all_peers
        .iter()
        .position(|p| *p == local_peer_id)
        .ok_or_else(|| "Local peer not found in peer list".to_string())? as u16;

    let parties: HashMap<PartyIndex, libp2p::PeerId> = all_peers
        .into_iter()
        .enumerate()
        .map(|(idx, peer_id)| (idx as PartyIndex, peer_id))
        .collect();

    let blueprint_id = ctx.blueprint_id()?;

    // Compute hash for key retrieval using the keygen's call_id
    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, keygen_call_id, SIGNING_SALT);

    // Retrieve the key entry
    let store_key = hex::encode(meta_hash);
    let state = ctx
        .store
        .get(&store_key)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Key entry not found".to_string())?;

    info!(
        "Starting WSTS Signing for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<crate::signing_state_machine::Msg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let mut rng = rand::rngs::OsRng;
    let network = round_based::party::MpcParty::connected(network);

    let output =
        crate::signing_state_machine::wsts_signing_protocol(network, &state, message, &mut rng)
            .await
            .map_err(|e| e.to_string())?;

    let signature_frost_format = output.signature_frost_format.clone();
    Ok(TangleResult(SignResult {
        signature: signature_frost_format.into(),
    }))
}
