use crate::context::wsts_ctx;
use crate::keygen_state_machine::WstsState;
use crate::{KeygenRequest, KeygenResult};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::info;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use round_based::party::MpcParty;
use round_based::PartyIndex;
use std::collections::HashMap;
use wsts::v2::Party;

const KEYGEN_SALT: &str = "wsts-keygen";

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("MPC protocol error: {0}")]
    MpcError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Delivery error: {0}")]
    DeliveryError(String),
}

/// Runs a distributed key generation (DKG) process using the WSTS protocol.
pub async fn keygen(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<KeygenRequest>,
) -> Result<TangleResult<KeygenResult>, String> {
    let ctx = wsts_ctx();
    let t = request.t;

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
    let k = n;

    let parties: HashMap<PartyIndex, libp2p::PeerId> = all_peers
        .into_iter()
        .enumerate()
        .map(|(idx, peer_id)| (idx as PartyIndex, peer_id))
        .collect();

    let blueprint_id = ctx.blueprint_id()?;
    let call_id = 0u64; // Deterministic from on-chain context

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    info!(
        "Starting WSTS Keygen for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<crate::keygen_state_machine::Msg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let state = protocol(n as _, i as _, t as _, k as _, network)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "Ending WSTS Keygen for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let public_key_frost_format = state.public_key_frost_format.clone();
    let store_key = hex::encode(meta_hash);
    let _ = ctx.store.set(&store_key, state);

    Ok(TangleResult(KeygenResult {
        public_key: public_key_frost_format.into(),
    }))
}

async fn protocol(
    n: u32,
    party_id: u32,
    t: u32,
    k: u32,
    network: RoundBasedNetworkAdapter<crate::keygen_state_machine::Msg, K256Ecdsa>,
) -> Result<WstsState, KeygenError> {
    crate::utils::validate_parameters(n, k, t).map_err(KeygenError::ContextError)?;
    let mut rng = rand::rngs::OsRng;
    let key_ids = crate::utils::generate_party_key_ids(n, k);
    let our_key_ids = key_ids
        .get(party_id as usize)
        .ok_or_else(|| KeygenError::ContextError("Bad party_id".to_string()))?;

    let network = MpcParty::connected(network);
    let mut party = Party::new(party_id, our_key_ids, n, k, t, &mut rng);
    let state =
        crate::keygen_state_machine::wsts_protocol(network, &mut party, n as usize, &mut rng)
            .await?;

    info!(
        "Combined public key: {:?}",
        state.party.lock().as_ref().unwrap().group_key
    );

    Ok(state)
}
