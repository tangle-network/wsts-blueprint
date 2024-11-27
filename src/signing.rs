use std::collections::BTreeMap;

use crate::context::WstsContext;
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

/// Configuration constants for the WSTS signing process
const SIGNING_SALT: &str = "wsts-signing";

#[job(
    id = 1,
    params(n, t, keygen_call_id, message),
    event_listener(
        listener = TangleEventListener<WstsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Signs a message using the WSTS protocol with a previously generated key
///
/// # Arguments
/// * `message` - The message to sign as a byte vector
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the signature as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to retrieve the key entry
/// - Signing process failed
pub async fn sign(
    n: u16,
    t: u16,
    keygen_call_id: u64,
    message: ByteBuf,
    context: WstsContext,
) -> Result<ByteBuf, GadgetError> {
    // let message = message.into_bytes();
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    // Compute hash for key retrieval. Must use the call_id of the keygen job
    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, keygen_call_id, SIGNING_SALT);

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    // Retrieve the key entry
    let store_key = hex::encode(meta_hash);
    let state = context
        .store
        .get(&store_key)
        .ok_or_else(|| SigningError::ContextError("Key entry not found".to_string()))?;

    let i = i as u16;

    gadget_sdk::info!(
        "Starting WSTS Signing for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let mut rng = rand::rngs::OsRng;

    let network = round_based::party::MpcParty::connected(network);

    let output = crate::signing_state_machine::wsts_signing_protocol(
        network,
        &state,
        t as _,
        message.into_vec(),
        &mut rng,
    )
    .await?;

    let signature = &**output
        .aggregated_signature
        .as_ref()
        .expect("Should have a signature");

    let signature = ByteBuf::from(
        bincode::serialize(signature)
            .map_err(|e| SigningError::SerializationError(e.to_string()))?,
    );

    Ok(signature)
}

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

impl From<SigningError> for gadget_sdk::Error {
    fn from(err: SigningError) -> Self {
        gadget_sdk::Error::Other(err.to_string())
    }
}
