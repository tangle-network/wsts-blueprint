use crate::keygen_state_machine;
use crate::utils::validate_parameters;
use crate::{context::WstsContext, keygen_state_machine::WstsState};
use gadget_sdk::contexts::MPCContext;
use gadget_sdk::{
    event_listener::tangle::{
        jobs::{services_post_processor, services_pre_processor},
        TangleEventListener,
    },
    job,
    network::round_based_compat::NetworkDeliveryWrapper,
    tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled,
    ByteBuf, Error as GadgetError,
};
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;
use wsts::v2::Party;

#[job(
    id = 0,
    params(n),
    event_listener(
        listener = TangleEventListener<WstsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a distributed key generation (DKG) process using the WSTS protocol
///
/// # Arguments
/// * `n` - Number of parties participating in the DKG
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
pub async fn keygen(n: u16, context: WstsContext) -> Result<ByteBuf, GadgetError> {
    let t = n - 1;
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;
    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    let i = i as u16;

    gadget_sdk::info!(
        "Starting WSTS Keygen for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let k = n;
    let state = protocol(n as _, i as _, t as _, k as _, network).await?;

    gadget_sdk::info!(
        "Ending WSTS Keygen for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(&store_key, state);

    Ok(ByteBuf::new())
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
}

impl From<KeygenError> for GadgetError {
    fn from(err: KeygenError) -> Self {
        GadgetError::Other(err.to_string())
    }
}

async fn protocol(
    n: u32,
    party_id: u32,
    k: u32,
    t: u32,
    network: NetworkDeliveryWrapper<keygen_state_machine::Msg>,
) -> Result<WstsState, GadgetError> {
    validate_parameters(n, k, t)?;
    let mut rng = rand::rngs::OsRng;
    let key_ids = crate::utils::generate_party_key_ids(n, k);
    let our_key_ids = key_ids
        .get(party_id as usize)
        .ok_or_else(|| KeygenError::ContextError("Bad party_id".to_string()))?;

    let network = round_based::party::MpcParty::connected(network);
    let mut party = Party::new(party_id, our_key_ids, n, k, t, &mut rng);
    let state =
        crate::keygen_state_machine::wsts_protocol(network, &mut party, n as usize, &mut rng)
            .await?;
    gadget_sdk::info!(
        "Combined public key: {:?}",
        state.party.lock().as_ref().unwrap().group_key
    );

    Ok(state)
}
