pub mod context;
pub mod keygen;
pub(crate) mod keygen_state_machine;
pub mod signing;
pub(crate) mod signing_state_machine;
pub(crate) mod utils;

pub use blueprint_sdk::*;

const META_SALT: &str = "wsts-protocol";

#[macro_export]
macro_rules! compute_sha256_hash {
    ($($data:expr),*) => {
        {
            use k256::sha2::{Digest, Sha256};
            let mut hasher = Sha256::default();
            $(hasher.update($data);)*
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(result.as_slice());
            hash
        }
    };
}

/// Helper function to compute deterministic hashes for the WSTS processes.
/// Note: for signing, the "call_id" should be the call_id of the preceeding
/// keygen job
pub fn compute_execution_hashes(
    n: u16,
    blueprint_id: u64,
    call_id: u64,
    salt: &'static str,
) -> ([u8; 32], [u8; 32]) {
    let interexecution_hash = compute_sha256_hash!(
        n.to_be_bytes(),
        blueprint_id.to_be_bytes(),
        call_id.to_be_bytes(),
        META_SALT
    );

    let intraexecution_hash = compute_sha256_hash!(interexecution_hash.as_ref(), salt);

    (interexecution_hash, intraexecution_hash)
}
