//! Portable network identity and genesis configuration.
//!
//! This crate intentionally contains no consensus engine, transport, or key
//! implementation. It is the small document shared by validators, relays,
//! indexers, browsers, and deployment tooling. Cryptographic consumers decode
//! and validate the key strings at their own boundary.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const GENESIS_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_NETWORK_ID: &str = "hellas-devnet-1";

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
            network_id: DEFAULT_NETWORK_ID.to_string(),
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
