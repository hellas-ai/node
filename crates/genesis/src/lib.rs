//! Portable network identity and genesis configuration.
//!
//! This crate intentionally contains no consensus engine, transport, or key
//! implementation. It is the small document shared by validators, relays,
//! indexers, browsers, and deployment tooling. Cryptographic consumers decode
//! and validate the key strings at their own boundary.
//!
//! It is `std` and it is a crate, because the document is `String`s, `Vec`s
//! and a `BTreeSet` of them, and because the readers are not all nodes: a
//! `wasm32-unknown-unknown` browser build and a relay in another repository
//! read the same shipped bytes as the validator does. `hellas-chain`
//! re-exports it whole as `hellas_chain::genesis`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const GENESIS_SCHEMA_VERSION: u16 = 1;

/// The in-tree development network's document.
pub const HELLAS_DEVNET_1_JSON: &str = include_str!("../networks/hellas-devnet-1/genesis.json");

/// The id that document names.
pub const HELLAS_DEVNET_1_ID: &str = "hellas-devnet-1";

/// The in-tree test network's document.
pub const HELLAS_TESTNET_1_JSON: &str = include_str!("../networks/hellas-testnet-1/genesis.json");

/// The id that document names.
pub const HELLAS_TESTNET_1_ID: &str = "hellas-testnet-1";

/// A network whose genesis document ships inside the binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownNetwork {
    /// Short name to select it by, e.g. `devnet`.
    pub name: &'static str,
    /// Full network id the document declares, e.g. `hellas-devnet-1`.
    pub id: &'static str,
    /// The document itself.
    pub json: &'static str,
}

/// Every network this binary can join without being handed a file.
///
/// Compiled in on purpose: operators should not have to ship genesis
/// JSON around to talk to a network everyone already agrees on, and a
/// document passed by path is a document that can be swapped.
///
/// This is a *registry selected by name*, which is a different thing
/// from the constant it replaced. That one presented itself as "the
/// network", so editing one string silently re-domained every
/// signature in the tree — a mistake this repository has already made
/// once. Adding a network here adds an entry; it never moves an
/// existing one. Nothing reads this list to decide what network it is
/// on: a caller names one, or hands over a document.
pub const KNOWN_NETWORKS: &[KnownNetwork] = &[
    KnownNetwork {
        name: "devnet",
        id: HELLAS_DEVNET_1_ID,
        json: HELLAS_DEVNET_1_JSON,
    },
    KnownNetwork {
        name: "testnet",
        id: HELLAS_TESTNET_1_ID,
        json: HELLAS_TESTNET_1_JSON,
    },
];

/// Looks up a shipped network by its short name (`devnet`) or its full
/// id (`hellas-devnet-1`).
#[must_use]
pub fn known_network(selector: &str) -> Option<&'static KnownNetwork> {
    KNOWN_NETWORKS
        .iter()
        .find(|network| network.name == selector || network.id == selector)
}

/// The short names a caller may pass, for help text and error messages.
#[must_use]
pub fn known_network_names() -> Vec<&'static str> {
    KNOWN_NETWORKS.iter().map(|network| network.name).collect()
}

const PUBLIC_KEY_HEX_BYTES: usize = 64;
const MAX_NETWORK_ID_BYTES: usize = 63;
const MAX_LABEL_BYTES: usize = 63;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    pub network_id: String,
    pub validators: Vec<GenesisValidator>,
    #[serde(default)]
    pub allocations: Vec<GenesisAllocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisValidator {
    /// Canonical lowercase hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Stable human-facing route label; it is never an authentication secret.
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAllocation {
    pub address: String,
    pub balance: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GenesisError {
    #[error("unsupported genesis schema version {0}")]
    UnsupportedSchema(u16),
    #[error("network id must be 1..={MAX_NETWORK_ID_BYTES} lowercase ASCII token bytes")]
    InvalidNetworkId,
    #[error("genesis must contain at least one validator")]
    EmptyCommittee,
    #[error("validator public key must be exactly 64 lowercase hexadecimal characters")]
    InvalidValidatorKey,
    #[error("duplicate validator public key {0}")]
    DuplicateValidatorKey(String),
    #[error("validator label must be 1..={MAX_LABEL_BYTES} lowercase ASCII token bytes")]
    InvalidValidatorLabel,
    #[error("duplicate validator label {0}")]
    DuplicateValidatorLabel(String),
    #[error("genesis allocation address must not be empty")]
    EmptyAllocationAddress,
    #[error("duplicate genesis allocation address {0}")]
    DuplicateAllocationAddress(String),
}

impl Genesis {
    pub fn validate(&self) -> Result<(), GenesisError> {
        if self.schema_version != GENESIS_SCHEMA_VERSION {
            return Err(GenesisError::UnsupportedSchema(self.schema_version));
        }
        if !is_token(&self.network_id, MAX_NETWORK_ID_BYTES) {
            return Err(GenesisError::InvalidNetworkId);
        }
        if self.validators.is_empty() {
            return Err(GenesisError::EmptyCommittee);
        }

        let mut keys = BTreeSet::new();
        let mut labels = BTreeSet::new();
        for validator in &self.validators {
            if validator.public_key.len() != PUBLIC_KEY_HEX_BYTES
                || !validator
                    .public_key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(GenesisError::InvalidValidatorKey);
            }
            if !keys.insert(validator.public_key.as_str()) {
                return Err(GenesisError::DuplicateValidatorKey(
                    validator.public_key.clone(),
                ));
            }
            if !is_token(&validator.label, MAX_LABEL_BYTES) {
                return Err(GenesisError::InvalidValidatorLabel);
            }
            if !labels.insert(validator.label.as_str()) {
                return Err(GenesisError::DuplicateValidatorLabel(
                    validator.label.clone(),
                ));
            }
        }

        let mut allocations = BTreeSet::new();
        for allocation in &self.allocations {
            if allocation.address.is_empty() {
                return Err(GenesisError::EmptyAllocationAddress);
            }
            if !allocations.insert(allocation.address.as_str()) {
                return Err(GenesisError::DuplicateAllocationAddress(
                    allocation.address.clone(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn validator(&self, public_key: &str) -> Option<&GenesisValidator> {
        self.validators
            .iter()
            .find(|validator| validator.public_key == public_key)
    }
}

const fn default_schema_version() -> u16 {
    GENESIS_SCHEMA_VERSION
}

fn is_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Genesis {
        Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: HELLAS_DEVNET_1_ID.to_string(),
            validators: vec![
                GenesisValidator {
                    public_key: "11".repeat(32),
                    label: "validator-a".to_string(),
                },
                GenesisValidator {
                    public_key: "22".repeat(32),
                    label: "validator-b".to_string(),
                },
            ],
            allocations: vec![GenesisAllocation {
                address: "example-address".to_string(),
                balance: 100,
            }],
        }
    }

    /// The id constant and the document are two copies of one fact;
    /// this is what keeps them from drifting apart.
    /// Every shipped document must parse, validate, and declare the id
    /// the registry claims for it. A registry entry that lies about its
    /// own id would put a node on a network it did not ask for.
    #[test]
    fn every_known_network_document_declares_the_id_the_registry_claims() {
        assert!(!KNOWN_NETWORKS.is_empty());
        for network in KNOWN_NETWORKS {
            let genesis: Genesis = serde_json::from_str(network.json)
                .unwrap_or_else(|err| panic!("{} document parses: {err}", network.name));
            genesis
                .validate()
                .unwrap_or_else(|err| panic!("{} document validates: {err}", network.name));
            assert_eq!(genesis.network_id, network.id, "{}", network.name);
            assert_eq!(known_network(network.name), Some(network));
            assert_eq!(known_network(network.id), Some(network));
        }
        assert_eq!(known_network("mainnet"), None);
        assert_eq!(known_network(""), None);
    }

    /// No two shipped networks may share a name, an id, or — the one
    /// that actually matters — a validator committee. Two networks with
    /// the same committee are one network wearing two names, and every
    /// separation argument above it is decoration.
    #[test]
    fn shipped_networks_share_no_name_id_committee_or_account() {
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut addresses = BTreeSet::new();

        for network in KNOWN_NETWORKS {
            assert!(
                names.insert(network.name),
                "duplicate name {}",
                network.name
            );
            assert!(ids.insert(network.id), "duplicate id {}", network.id);

            let genesis: Genesis = serde_json::from_str(network.json).unwrap();
            for validator in &genesis.validators {
                assert!(
                    keys.insert(validator.public_key.clone()),
                    "{} reuses validator key {}",
                    network.name,
                    validator.public_key,
                );
            }
            for allocation in &genesis.allocations {
                assert!(
                    addresses.insert(allocation.address.clone()),
                    "{} reuses funded account {}",
                    network.name,
                    allocation.address,
                );
            }
        }
    }

    /// The shipped documents are pinned by their bytes, not by the
    /// facts a parser can be talked into agreeing with. `include_str!`
    /// takes a path, and a path is a thing that can be re-pointed by a
    /// move, a symlink, or a directory rename — after which every
    /// assertion above still passes while the committee has changed.
    /// Two networks differing in one hex digit are two networks, and a
    /// node that joined the wrong one has forked.
    #[test]
    fn shipped_documents_hash_to_the_bytes_that_were_reviewed() {
        use sha2::{Digest as _, Sha256};

        for (json, expected) in [
            (
                HELLAS_DEVNET_1_JSON,
                "caab04a9350edbe0d50aa9375dcee2742145cf5c24c57f42c844ebf4f27aa4b6",
            ),
            (
                HELLAS_TESTNET_1_JSON,
                "2c845c34455dc96e818ce40f4200edac79e6fb43f3e68a24e522d2030c3d8680",
            ),
        ] {
            let digest = Sha256::digest(json.as_bytes());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected);
        }
    }

    #[test]
    fn canonical_devnet_genesis_is_valid_and_matches_its_id_constant() {
        let genesis: Genesis = serde_json::from_str(HELLAS_DEVNET_1_JSON).unwrap();
        genesis.validate().unwrap();
        assert_eq!(genesis.network_id, HELLAS_DEVNET_1_ID);
        assert_eq!(genesis.validators.len(), 6);
        assert_eq!(genesis.allocations.len(), 2);
    }

    #[test]
    fn json_and_toml_round_trip_the_same_document() {
        let genesis = fixture();
        genesis.validate().unwrap();

        let json = serde_json::to_string(&genesis).unwrap();
        let from_json: Genesis = serde_json::from_str(&json).unwrap();
        let toml = toml::to_string(&genesis).unwrap();
        let from_toml: Genesis = toml::from_str(&toml).unwrap();

        assert_eq!(from_json, genesis);
        assert_eq!(from_toml, genesis);
    }

    #[test]
    fn rejects_duplicate_committee_identity_or_label() {
        let mut duplicate_key = fixture();
        duplicate_key.validators[1].public_key = duplicate_key.validators[0].public_key.clone();
        assert!(matches!(
            duplicate_key.validate(),
            Err(GenesisError::DuplicateValidatorKey(_))
        ));

        let mut duplicate_label = fixture();
        duplicate_label.validators[1].label = duplicate_label.validators[0].label.clone();
        assert!(matches!(
            duplicate_label.validate(),
            Err(GenesisError::DuplicateValidatorLabel(_))
        ));
    }

    #[test]
    fn rejects_short_or_noncanonical_public_keys() {
        for key in ["11".repeat(31), "AA".repeat(32), "gg".repeat(32)] {
            let mut genesis = fixture();
            genesis.validators[0].public_key = key;
            assert_eq!(genesis.validate(), Err(GenesisError::InvalidValidatorKey));
        }
    }
}
