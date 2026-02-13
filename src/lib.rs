pub mod context;
pub mod keygen;
pub(crate) mod keygen_state_machine;
pub mod signing;
pub(crate) mod signing_state_machine;
pub(crate) mod utils;

use blueprint_sdk::alloy::sol;
use blueprint_sdk::crypto::hashing::sha2_256;
use blueprint_sdk::tangle::TangleLayer;
use blueprint_sdk::{Job, Router};

pub const JOB_KEYGEN: u8 = 0;
pub const JOB_SIGN: u8 = 1;

const META_SALT: &str = "wsts-protocol";

sol! {
    struct KeygenRequest { uint16 t; }
    struct KeygenResult { bytes public_key; }
    struct SignRequest { uint64 keygen_call_id; bytes message; }
    struct SignResult { bytes signature; }
}

/// Helper function to compute deterministic hashes for the WSTS processes.
pub fn compute_deterministic_hashes(
    n: u16,
    blueprint_id: u64,
    call_id: u64,
    salt: &str,
) -> ([u8; 32], [u8; 32]) {
    let mut meta_input = Vec::new();
    meta_input.extend_from_slice(&n.to_be_bytes());
    meta_input.extend_from_slice(&blueprint_id.to_be_bytes());
    meta_input.extend_from_slice(&call_id.to_be_bytes());
    meta_input.extend_from_slice(META_SALT.as_bytes());
    let meta_hash = sha2_256(&meta_input);

    let mut det_input = Vec::new();
    det_input.extend_from_slice(&meta_hash);
    det_input.extend_from_slice(salt.as_bytes());
    let deterministic_hash = sha2_256(&det_input);

    (meta_hash, deterministic_hash)
}

pub fn router() -> Router {
    Router::new()
        .route(JOB_KEYGEN, keygen::keygen.layer(TangleLayer))
        .route(JOB_SIGN, signing::sign.layer(TangleLayer))
}
