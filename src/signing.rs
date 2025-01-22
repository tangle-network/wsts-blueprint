use crate::context::WstsContext;
use blueprint_sdk::crypto::k256::K256VerifyingKey;
use blueprint_sdk::crypto::KeyEncoding;
use blueprint_sdk::event_listeners::tangle::events::TangleEventListener;
use blueprint_sdk::event_listeners::tangle::services::{
    services_post_processor, services_pre_processor,
};
use blueprint_sdk::logging::info;
use blueprint_sdk::macros as gadget_macros;
use blueprint_sdk::macros::ext::contexts::tangle::TangleClientContext;
use blueprint_sdk::networking::round_based_compat::NetworkDeliveryWrapper;
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
use blueprint_sdk::*;
use gadget_macros::ext::clients::GadgetServicesClient;
use std::collections::BTreeMap;

/// Configuration constants for the WSTS signing process
const SIGNING_SALT: &str = "wsts-signing";

#[job(
    id = 1,
    params(keygen_call_id, message),
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
    keygen_call_id: u64,
    message: Vec<u8>,
    context: WstsContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // let message = message.into_bytes();
    // Get configuration and compute deterministic values
    let client = context.tangle_client().await?;
    let blueprint_id = client
        .blueprint_id()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let call_id = context
        .call_id
        .ok_or_else(|| SigningError::ContextError("call_id not set".into()))?;

    // Setup party information
    let (i, operators) = client
        .get_party_index_and_operators()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

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

    // Compute hash for key retrieval. Must use the call_id of the keygen job
    let (meta_hash, deterministic_hash) =
        crate::compute_execution_hashes(n, blueprint_id, keygen_call_id, SIGNING_SALT);

    // Retrieve the key entry
    let store_key = hex::encode(meta_hash);
    let state = context
        .store
        .get(&store_key)
        .ok_or_else(|| SigningError::ContextError("Key entry not found".to_string()))?;

    info!(
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

    let output =
        crate::signing_state_machine::wsts_signing_protocol(network, &state, message, &mut rng)
            .await?;

    let signature_frost_format = output.signature_frost_format.clone();
    Ok(signature_frost_format)
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
