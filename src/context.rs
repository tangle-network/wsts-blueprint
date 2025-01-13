use crate::keygen_state_machine::WstsState;
use color_eyre::eyre;
use gadget_config::StdGadgetConfiguration;
use gadget_crypto_tangle_pair_signer::sp_core::ecdsa;
use gadget_macros::contexts::{KeystoreContext, P2pContext, ServicesContext, TangleClientContext};
use gadget_networking::networking::NetworkMultiplexer;
use gadget_networking::setup::start_p2p_network;
use gadget_store_local_database::LocalDatabase;
use std::path::PathBuf;
use std::sync::Arc;

/// The network protocol version for the WSTS service
const NETWORK_PROTOCOL: &str = "/wsts/frost/1.0.0";

/// WSTS Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext, P2pContext)]
pub struct WstsContext {
    #[config]
    pub config: StdGadgetConfiguration,
    #[call_id]
    pub call_id: Option<u64>,
    pub network_backend: Arc<NetworkMultiplexer>,
    pub store: Arc<LocalDatabase<WstsState>>,
    pub identity: ecdsa::Pair,
}

// Core context management implementation
impl WstsContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub fn new(config: StdGadgetConfiguration) -> eyre::Result<Self> {
        let network_config = config
            .libp2p_network_config(NETWORK_PROTOCOL)
            .map_err(|err| eyre::eyre!("Failed to create network configuration: {err}"))?;

        let identity = network_config.ecdsa_key.clone();
        let gossip_handle = start_p2p_network(network_config)
            .map_err(|err| eyre::eyre!("Failed to start the P2P network: {err}"))?;

        let keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("wsts.json");
        let store = Arc::new(LocalDatabase::open(keystore_dir));

        Ok(Self {
            store,
            call_id: None,
            identity,
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }
}
