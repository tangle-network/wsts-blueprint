use crate::keygen_state_machine;
use crate::utils::validate_parameters;
use crate::{context::WstsContext, keygen_state_machine::WstsState};
use blueprint_sdk::crypto::k256::K256VerifyingKey;
use blueprint_sdk::crypto::KeyEncoding;
use blueprint_sdk::event_listeners::tangle::events::TangleEventListener;
use blueprint_sdk::event_listeners::tangle::services::{
    services_post_processor, services_pre_processor,
};
use blueprint_sdk::logging::info;
use blueprint_sdk::macros::ext::contexts::tangle::TangleClientContext;
use blueprint_sdk::networking::round_based_compat::NetworkDeliveryWrapper;
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
use blueprint_sdk::*;
use gadget_macros::ext::clients::GadgetServicesClient;
use std::collections::BTreeMap;
use wsts::v2::Party;

#[job(
    id = 0,
    params(t),
    event_listener(
        listener = TangleEventListener<WstsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a distributed key generation (DKG) process using the WSTS protocol
///
/// # Arguments
/// * `t` - The threshold for the DKG
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the generated public key as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to get party information
/// - MPC protocol execution failed
/// - Serialization of results failed
pub async fn keygen(t: u16, context: WstsContext) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Get configuration and compute deterministic values
    let client = context.tangle_client().await?;
    let blueprint_id = client
        .blueprint_id()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;
    let call_id = context
        .call_id
        .ok_or_else(|| KeygenError::ContextError("Call_id not set".into()))?;

    // Setup party information
    let (i, operators) = client
        .get_party_index_and_operators()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, _> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| {
            (
                j as u16,
                K256VerifyingKey::from_bytes(&ecdsa.0).expect("33 byte compressed ECDSA key"),
            )
        })
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;
    let k = n;

    let (meta_hash, deterministic_hash) =
        crate::compute_execution_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    info!(
        "Starting WSTS Keygen for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let state = protocol(n as _, i as _, k as _, t as _, network).await?;

    info!(
        "Ending WSTS Keygen for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let public_key_frost_format = state.public_key_frost_format.clone();
    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(&store_key, state);

    Ok(public_key_frost_format)
}

/// Configuration constants for the WSTS keygen process
const KEYGEN_SALT: &str = "wsts-keygen";

/// Error type for keygen-specific operations
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

    #[error("Setup error: {0}")]
    SetupError(String),
}

async fn protocol(
    n: u32,
    party_id: u32,
    k: u32,
    t: u32,
    network: NetworkDeliveryWrapper<keygen_state_machine::Msg>,
) -> Result<WstsState, KeygenError> {
    validate_parameters(n, k, t)?;
    let mut rng = rand::rngs::OsRng;
    let key_ids = crate::utils::generate_party_key_ids(n, k);
    let our_key_ids = key_ids
        .get(party_id as usize)
        .ok_or_else(|| KeygenError::ContextError("Bad party_id".to_string()))?;

    let network = round_based::party::MpcParty::connected(network);
    let mut party = Party::new(party_id, our_key_ids, n, k, t, &mut rng);
    let state =
        keygen_state_machine::wsts_protocol(network, &mut party, n as usize, &mut rng).await?;

    info!(
        "Combined public key: {:?}",
        state.party.lock().as_ref().unwrap().group_key
    );

    Ok(state)
}
