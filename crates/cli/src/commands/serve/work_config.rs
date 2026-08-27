//! The paid-work configuration file: what an operator writes down, and
//! what a node refuses to start without.
//!
//! `--work-config` was a path whose *presence* advertised two ALPNs and
//! whose contents were never opened. A node cannot mount a channel from
//! a path, so this is the schema and the loader for what is in it: the
//! three-part chain cross-check, the six validator URLs a write is
//! fanned to, the journal root and its caps, the two policies this
//! provider works under, the watcher's poll cadence, the response
//! alarm's margin, and the identity of the measured artifact.
//!
//! # The cross-check is not an anchor
//!
//! `(network_id, genesis_payload_digest, threshold_identity)` is a
//! fail-fast configuration cross-check. Only the threshold identity ever
//! authenticates a finalized block; the other two are how a node started
//! against the wrong chain says so at startup instead of at the first
//! settlement. The identity is decoded here, by the same constructor
//! consensus verification uses, so a typo is a startup error and not a
//! block that never verifies.
//!
//! # What is deliberately not here
//!
//! There is no Start-span field and no mutual-margin field. Both were
//! deleted: the Start span is fixed at 64 and a work-payment edge has no
//! Mutual route, so either one appearing in a file is an operator
//! configuring something that does not exist. Every struct below denies
//! unknown fields, which is what turns that into an error naming the
//! field.
//!
//! The **measured-artifact gate** is not here either. The artifact's
//! *identity* is loaded, because that is a field of the configuration;
//! the `64 >= T` floor arithmetic and the Clopper–Pearson confidence
//! test consume timings no producer in this tree yet emits. Until that
//! lands, a configuration with no artifact is a node with no paid
//! admission — [`WorkConfig::measured_artifact`] is how the serve path
//! asks, and it answers `None` rather than inventing a measurement.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use hellas_kernel::NetworkId;
use hellas_rpc::ContentId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, check_execution_policy,
};
use hellas_rpc::work_store::journal::MAX_RECORD_BYTES;
use serde::Deserialize;

use crate::commands::CliResult;

/// How many validator RPCs a write names.
///
/// Reads come from a follower and writes are fanned to all six; a
/// configuration naming five has one validator whose acceptance this
/// node can never win, and one naming seven names something this
/// deployment does not have.
pub const VALIDATOR_COUNT: usize = 6;

/// One operator's complete paid-work configuration, loaded and checked.
///
/// A plain record with public fields, for [`WorkChannelConfig`]'s
/// reason: this is the shape a file fills in, and every gate it has to
/// pass has already been run by [`load_work_config`].
///
/// [`WorkChannelConfig`]: hellas_rpc::protocol::work_setup::WorkChannelConfig
#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "the fields a mount consumes are read by the node runner; loading and checking them is this half"
)]
pub struct WorkConfig {
    /// The chain this node believes it is configured against.
    pub chain: ChainCrossCheck,
    /// The six validator RPC URLs every write is fanned to.
    pub validators: Vec<String>,
    /// Where the work journals live, and how large they may grow.
    pub journal: JournalLimits,
    /// Salt of the private credit-policy commitment.
    pub policy_salt: [u8; 32],
    /// The credit policy this provider will work under.
    pub channel_policy: PaidChannelPolicyV1,
    /// The execution policy this provider will run jobs under.
    pub execution_policy: PaidExecutionPolicyV1,
    /// How often the watcher asks the chain for the next block.
    pub poll: Duration,
    /// Blocks of margin the response alarm fires inside.
    pub response_alarm_margin_blocks: u64,
    /// The measured artifact this node's admission would rest on.
    pub artifact: Option<ArtifactIdentity>,
}

impl WorkConfig {
    /// Returns the measured artifact, or `None` when this node admits no
    /// paid work.
    ///
    /// The floor arithmetic that would *grade* the artifact is not
    /// implemented, and this does not pretend otherwise: it answers
    /// which of the two configurations this is, and a `None` is the
    /// fail-closed one. Recovery is unaffected either way — §4 disables
    /// setup and new work on missing evidence, never recovery.
    #[must_use]
    pub const fn measured_artifact(&self) -> Option<&ArtifactIdentity> {
        self.artifact.as_ref()
    }

    /// The one line the operator gets at startup about paid admission.
    ///
    /// A method rather than a string built at the log site, so what the
    /// node says is the same thing a test can read back. It says which
    /// of the two configurations this is and nothing more: grading the
    /// artifact is the measured gate's job, not this one's.
    #[must_use]
    pub const fn admission_summary(&self) -> &'static str {
        if self.artifact.is_some() {
            "paid admission rests on the configured measured artifact"
        } else {
            "no paid admission: no measured artifact is configured"
        }
    }
}

/// The three fields that say which chain this is.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the fields a mount consumes are read by the node runner; loading and checking them is this half"
)]
pub struct ChainCrossCheck {
    /// The network every signature on this node's channels is bound to.
    pub network: NetworkId,
    /// Payload digest of the genesis block this deployment began at.
    pub genesis_payload_digest: Digest,
    /// The threshold identity finalized blocks are verified under.
    pub threshold_identity: Vec<u8>,
}

/// Where the work journals live and how large they may grow.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the fields a mount consumes are read by the node runner; loading and checking them is this half"
)]
pub struct JournalLimits {
    /// Directory holding the setup and channel journals.
    pub root: PathBuf,
    /// Soft cap on one active journal file.
    pub max_active_bytes: u64,
    /// Soft cap on frames in one active journal file.
    pub max_active_frames: u64,
    /// Largest checkpoint a rotation may write.
    pub max_checkpoint_bytes: u64,
}

/// Which measured artifact this node's admission rests on.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the fields a mount consumes are read by the node runner; loading and checking them is this half"
)]
pub struct ArtifactIdentity {
    /// Where the artifact is.
    pub path: PathBuf,
    /// The canonical digest it must have.
    pub digest: Digest,
}

/// Loads and checks one paid-work configuration file.
///
/// Every failure is a startup failure naming the field that failed, for
/// the reason §4 gives: a node that started with an unreadable
/// configuration would be one whose first symptom is an unsettleable
/// channel.
///
/// # Errors
///
/// The read and the parse, and then: a network id that is not one, a
/// digest that is not thirty-two bytes, a threshold identity consensus
/// cannot decode, a validator list that is not exactly
/// [`VALIDATOR_COUNT`] URLs with distinct normalised forms, an execution
/// policy the protocol's own [`check_execution_policy`] rejects, a
/// journal cap of zero or one larger than the journal's own record
/// ceiling, a zero poll cadence, and a zero response-alarm margin.
pub fn load_work_config(path: &Path) -> CliResult<WorkConfig> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: WorkConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    file.into_config()
        .with_context(|| format!("invalid work config {}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkConfigFile {
    chain: ChainFile,
    validators: Vec<String>,
    journal: JournalFile,
    policies: PoliciesFile,
    /// How often the watcher asks the chain for the next block.
    poll_ms: u64,
    response_alarm_margin_blocks: u64,
    #[serde(default)]
    artifact: Option<ArtifactFile>,
}

impl WorkConfigFile {
    fn into_config(self) -> CliResult<WorkConfig> {
        let Some(network) = NetworkId::new(self.chain.network_id.trim()) else {
            bail!(
                "chain.network_id {:?} is not a network id",
                self.chain.network_id
            );
        };
        let threshold_identity =
            parse_hex("chain.threshold_identity", &self.chain.threshold_identity)?;
        // Parsed before the verifier is built, so the list consensus is
        // handed is the normalised one this node will actually dial.
        let validators = parse_validators(self.validators)?;
        // The same constructor consensus verification uses. A threshold
        // identity that cannot be decoded here is one no finalized block
        // would ever verify under, and the node says so before it serves.
        hellas_chain::ConsensusVerifier::new(&hellas_chain::light_client::ConsensusInfo {
            validators: validators.clone(),
            threshold_identity: threshold_identity.clone(),
            network_id: self.chain.network_id.clone(),
        })
        .map_err(|error| anyhow::anyhow!("chain.threshold_identity is not usable: {error}"))?;

        let journal = self.journal.into_limits()?;
        let policies = self.policies.into_policies()?;
        if self.poll_ms == 0 {
            bail!("poll_ms must be greater than zero");
        }
        if self.response_alarm_margin_blocks == 0 {
            bail!("response_alarm_margin_blocks must be greater than zero");
        }

        Ok(WorkConfig {
            chain: ChainCrossCheck {
                network,
                genesis_payload_digest: parse_digest(
                    "chain.genesis_payload_digest",
                    &self.chain.genesis_payload_digest,
                )?,
                threshold_identity,
            },
            validators,
            journal,
            policy_salt: policies.0,
            channel_policy: policies.1,
            execution_policy: policies.2,
            poll: Duration::from_millis(self.poll_ms),
            response_alarm_margin_blocks: self.response_alarm_margin_blocks,
            artifact: self.artifact.map(ArtifactFile::into_identity).transpose()?,
        })
    }
}

/// Parses the six validator RPC URLs, and refuses anything that is not
/// one.
///
/// Both halves matter. A string that is not a URL is not an address this
/// node can ever fan a write to, and "trimmed and non-empty" admits `not
/// a URL` verbatim — a configuration whose first symptom would be five
/// validators answering and one that never does. And uniqueness is a
/// question about *addresses*, not about spellings: `HTTP://Host:443/`
/// and `http://host:443/` are one validator written twice, and a fan-out
/// to five validators is not six however it is spelled. So the
/// comparison is between parsed, normalised URLs, and the normalised
/// forms are what is kept.
///
/// A host is required, because these are dialled: a `mailto:` or a
/// `data:` parses perfectly well and is not a validator.
fn parse_validators(entries: Vec<String>) -> CliResult<Vec<String>> {
    let mut validators: Vec<String> = Vec::with_capacity(VALIDATOR_COUNT);
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            bail!("validators entries must be non-empty");
        }
        let url = reqwest::Url::parse(entry)
            .with_context(|| format!("validators entry {entry:?} is not a URL"))?;
        if url.host_str().is_none() {
            bail!("validators entry {entry:?} names no host to dial");
        }
        let normalised = url.as_str().to_string();
        if validators.contains(&normalised) {
            bail!("validators names {normalised} twice; a fan-out to five validators is not six");
        }
        validators.push(normalised);
    }
    if validators.len() != VALIDATOR_COUNT {
        bail!(
            "validators must name exactly {VALIDATOR_COUNT} validator URLs, found {}",
            validators.len(),
        );
    }
    Ok(validators)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainFile {
    network_id: String,
    genesis_payload_digest: String,
    threshold_identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    root: PathBuf,
    max_active_bytes: u64,
    max_active_frames: u64,
    max_checkpoint_bytes: u64,
}

impl JournalFile {
    fn into_limits(self) -> CliResult<JournalLimits> {
        if self.root.as_os_str().is_empty() {
            bail!("journal.root must be a path");
        }
        for (name, value) in [
            ("journal.max_active_bytes", self.max_active_bytes),
            ("journal.max_active_frames", self.max_active_frames),
            ("journal.max_checkpoint_bytes", self.max_checkpoint_bytes),
        ] {
            if value == 0 {
                bail!("{name} must be greater than zero");
            }
        }
        // A checkpoint is one journal record, so a configured ceiling
        // above the journal's own is a ceiling the journal will refuse
        // to write at. That refusal would arrive at a rotation, which is
        // the one moment a duty cannot absorb it.
        let record_ceiling = MAX_RECORD_BYTES as u64;
        if self.max_checkpoint_bytes > record_ceiling {
            bail!(
                "journal.max_checkpoint_bytes {} exceeds the {record_ceiling}-byte journal record ceiling",
                self.max_checkpoint_bytes,
            );
        }
        if self.max_checkpoint_bytes > self.max_active_bytes {
            bail!(
                "journal.max_checkpoint_bytes {} does not fit journal.max_active_bytes {}",
                self.max_checkpoint_bytes,
                self.max_active_bytes,
            );
        }
        Ok(JournalLimits {
            root: self.root,
            max_active_bytes: self.max_active_bytes,
            max_active_frames: self.max_active_frames,
            max_checkpoint_bytes: self.max_checkpoint_bytes,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoliciesFile {
    policy_salt: String,
    channel: ChannelPolicyFile,
    execution: ExecutionPolicyFile,
}

impl PoliciesFile {
    fn into_policies(self) -> CliResult<([u8; 32], PaidChannelPolicyV1, PaidExecutionPolicyV1)> {
        let salt = parse_bytes32("policies.policy_salt", &self.policy_salt)?;
        Ok((
            salt,
            PaidChannelPolicyV1 {
                compute_credit_limit: self.channel.compute_credit_limit,
                delivery_credit_limit: self.channel.delivery_credit_limit,
            },
            self.execution.into_policy()?,
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelPolicyFile {
    compute_credit_limit: u64,
    delivery_credit_limit: u64,
}

/// The execution policy, field for field.
///
/// Spelled out rather than flattened from some smaller shape because
/// every one of these is a value both parties sign: a default here would
/// be this node quietly proposing a policy its operator never wrote.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionPolicyFile {
    allowed_environment: String,
    generation_policy_digest: String,
    identity_source_digest: String,
    max_prompt_tokens: u32,
    max_new_tokens: u32,
    max_stop_token_ids: u16,
    max_spool_bytes: u64,
    max_encoded_result_frame: u32,
    max_encoded_quote_response: u32,
    dispatch_margin_blocks: u64,
    delivery_margin_blocks: u64,
    oracle_grace_blocks: u64,
    fixed_price: u64,
}

impl ExecutionPolicyFile {
    fn into_policy(self) -> CliResult<PaidExecutionPolicyV1> {
        let allowed_environment: ContentId =
            self.allowed_environment.parse().with_context(|| {
                format!(
                    "policies.execution.allowed_environment {:?} is not a ContentId",
                    self.allowed_environment
                )
            })?;
        let policy = PaidExecutionPolicyV1 {
            allowed_environment,
            generation_policy_digest: parse_digest(
                "policies.execution.generation_policy_digest",
                &self.generation_policy_digest,
            )?,
            identity_source_digest: parse_digest(
                "policies.execution.identity_source_digest",
                &self.identity_source_digest,
            )?,
            max_prompt_tokens: self.max_prompt_tokens,
            max_new_tokens: self.max_new_tokens,
            max_stop_token_ids: self.max_stop_token_ids,
            max_spool_bytes: self.max_spool_bytes,
            max_encoded_result_frame: self.max_encoded_result_frame,
            max_encoded_quote_response: self.max_encoded_quote_response,
            dispatch_margin_blocks: self.dispatch_margin_blocks,
            delivery_margin_blocks: self.delivery_margin_blocks,
            oracle_grace_blocks: self.oracle_grace_blocks,
            fixed_price: self.fixed_price,
        };
        // The protocol's own gate, run here rather than at the first
        // admission. A zero here is not a small bound, it is an absent
        // one — a zero margin gives a deadline no time to be met in, and
        // a zero price is a job nobody is paid for. Copying the fields
        // through unchecked moves that discovery to the moment a
        // counterparty is already waiting on a proposal.
        check_execution_policy(&policy)
            .map_err(|error| anyhow::anyhow!("policies.execution is not usable: {error}"))?;
        Ok(policy)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFile {
    path: PathBuf,
    digest: String,
}

impl ArtifactFile {
    fn into_identity(self) -> CliResult<ArtifactIdentity> {
        if self.path.as_os_str().is_empty() {
            bail!("artifact.path must be a path");
        }
        Ok(ArtifactIdentity {
            digest: parse_digest("artifact.digest", &self.digest)?,
            path: self.path,
        })
    }
}

fn parse_hex(field: &str, raw: &str) -> CliResult<Vec<u8>> {
    let bytes = hex::decode(raw.trim()).with_context(|| format!("{field} is not hexadecimal"))?;
    if bytes.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(bytes)
}

fn parse_bytes32(field: &str, raw: &str) -> CliResult<[u8; 32]> {
    let bytes = parse_hex(field, raw)?;
    let Ok(bytes) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        bail!("{field} must be 32 bytes, found {}", bytes.len());
    };
    Ok(bytes)
}

fn parse_digest(field: &str, raw: &str) -> CliResult<Digest> {
    Ok(Digest::from_bytes(parse_bytes32(field, raw)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn validators() -> Vec<serde_json::Value> {
        (1..=VALIDATOR_COUNT)
            .map(|index| serde_json::Value::String(format!("http://127.0.0.1:900{index}")))
            .collect()
    }

    /// A threshold identity the consensus verifier accepts.
    ///
    /// The BLS12-381 G1 generator, compressed: a real point in the real
    /// subgroup, so what this fixture proves is that the loader runs
    /// consensus's own decoder rather than a length check wearing its
    /// name.
    fn threshold_identity() -> String {
        hex::encode(THRESHOLD_IDENTITY)
    }

    const THRESHOLD_IDENTITY: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ];

    fn config() -> serde_json::Value {
        serde_json::json!({
            "chain": {
                "network_id": "hellas-devnet",
                "genesis_payload_digest": hex32(0x01),
                "threshold_identity": threshold_identity(),
            },
            "validators": validators(),
            "journal": {
                "root": "/var/lib/hellas/work",
                "max_active_bytes": 67_108_864_u64,
                "max_active_frames": 4_096_u64,
                "max_checkpoint_bytes": 4_194_304_u64,
            },
            "policies": {
                "policy_salt": hex32(0x5a),
                "channel": {
                    "compute_credit_limit": 40,
                    "delivery_credit_limit": 40,
                },
                "execution": {
                    "allowed_environment": hex32(0x11),
                    "generation_policy_digest": hex32(0x12),
                    "identity_source_digest": hex32(0x13),
                    "max_prompt_tokens": 512,
                    "max_new_tokens": 128,
                    "max_stop_token_ids": 4,
                    "max_spool_bytes": 1_048_576_u64,
                    "max_encoded_result_frame": 262_144,
                    "max_encoded_quote_response": 1_048_576_u64,
                    "dispatch_margin_blocks": 4,
                    "delivery_margin_blocks": 2,
                    "oracle_grace_blocks": 6,
                    "fixed_price": 10,
                },
            },
            "poll_ms": 250,
            "response_alarm_margin_blocks": 12,
            "artifact": {
                "path": "/var/lib/hellas/work/artifact.json",
                "digest": hex32(0x77),
            },
        })
    }

    fn write(dir: &tempfile::TempDir, value: &serde_json::Value) -> PathBuf {
        let path = dir.path().join("work-config.json");
        fs::write(&path, value.to_string()).unwrap();
        path
    }

    fn load(value: serde_json::Value) -> CliResult<WorkConfig> {
        let dir = tempfile::tempdir().unwrap();
        load_work_config(&write(&dir, &value))
    }

    /// Delete `field` from the object at `path`.
    fn without(mut value: serde_json::Value, path: &[&str], field: &str) -> serde_json::Value {
        let mut cursor = &mut value;
        for step in path {
            cursor = cursor.get_mut(step).unwrap();
        }
        cursor.as_object_mut().unwrap().remove(field).unwrap();
        value
    }

    fn with(
        mut value: serde_json::Value,
        field: &str,
        entry: serde_json::Value,
    ) -> serde_json::Value {
        value
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), entry);
        value
    }

    #[test]
    fn a_work_config_round_trips_from_a_file() {
        let loaded = load(config()).expect("the fixture config loads");

        assert_eq!(loaded.chain.network.as_str(), "hellas-devnet");
        assert_eq!(
            loaded.chain.genesis_payload_digest,
            Digest::from_bytes([0x01; 32]),
        );
        assert_eq!(loaded.chain.threshold_identity, THRESHOLD_IDENTITY.to_vec());
        assert_eq!(loaded.validators.len(), VALIDATOR_COUNT);
        assert_eq!(loaded.journal.root, PathBuf::from("/var/lib/hellas/work"));
        assert_eq!(loaded.journal.max_active_frames, 4_096);
        assert_eq!(loaded.policy_salt, [0x5a; 32]);
        assert_eq!(loaded.channel_policy.compute_credit_limit, 40);
        assert_eq!(loaded.execution_policy.fixed_price, 10);
        assert_eq!(loaded.execution_policy.max_stop_token_ids, 4);
        assert_eq!(loaded.poll, Duration::from_millis(250));
        assert_eq!(loaded.response_alarm_margin_blocks, 12);
        assert_eq!(
            loaded.measured_artifact().map(|artifact| artifact.digest),
            Some(Digest::from_bytes([0x77; 32])),
        );
        assert_eq!(
            loaded.admission_summary(),
            "paid admission rests on the configured measured artifact",
        );
    }

    /// No artifact is no paid admission, and it is not an error: §4
    /// disables setup and new work on missing evidence, never recovery.
    #[test]
    fn a_config_without_an_artifact_admits_no_paid_work() {
        let loaded = load(without(config(), &[], "artifact")).expect("the config still loads");
        assert!(loaded.measured_artifact().is_none());
        assert_eq!(
            loaded.admission_summary(),
            "no paid admission: no measured artifact is configured",
        );
    }

    /// Every required field is required, and the refusal names it.
    #[test]
    fn a_missing_field_is_refused_by_name() {
        for (path, field) in [
            (&[][..], "poll_ms"),
            (&[][..], "response_alarm_margin_blocks"),
            (&[][..], "validators"),
            (&["chain"][..], "threshold_identity"),
            (&["chain"][..], "genesis_payload_digest"),
            (&["journal"][..], "max_checkpoint_bytes"),
            (&["policies"][..], "policy_salt"),
            (&["policies", "execution"][..], "fixed_price"),
        ] {
            let error = format!(
                "{:?}",
                load(without(config(), path, field))
                    .expect_err("a config missing a required field is refused"),
            );
            assert!(
                error.contains(field),
                "the refusal for a missing {field} does not name it: {error}",
            );
        }
    }

    /// The two fields that were deleted from the design cannot be
    /// configured back into existence.
    #[test]
    fn a_deleted_field_is_refused_by_name() {
        for field in ["start_validity_blocks", "mutual_margin_blocks"] {
            let error = format!(
                "{:?}",
                load(with(config(), field, serde_json::json!(64))).unwrap_err(),
            );
            assert!(
                error.contains(field),
                "the refusal for {field} does not name it: {error}",
            );
        }
    }

    #[test]
    fn a_fan_out_is_exactly_six_distinct_validators() {
        let five = validators()[..5].to_vec();
        let error = format!(
            "{:?}",
            load(with(config(), "validators", serde_json::json!(five))).unwrap_err(),
        );
        assert!(error.contains("exactly 6"), "unexpected error: {error}");

        let mut duplicated = validators();
        duplicated[5] = duplicated[0].clone();
        let error = format!(
            "{:?}",
            load(with(config(), "validators", serde_json::json!(duplicated))).unwrap_err(),
        );
        assert!(error.contains("twice"), "unexpected error: {error}");
    }

    /// A validator entry has to be an address, not merely a string.
    ///
    /// `"not a URL"` is trimmed, non-empty, and distinct from the other
    /// five, which is all the loader used to ask. It is also nothing this
    /// node can ever fan a write to, and the first symptom of that would
    /// be one validator out of six that never answers.
    #[test]
    fn a_validator_that_is_not_a_url_is_refused() {
        let mut malformed = validators();
        malformed[3] = serde_json::Value::String("not a URL".to_string());
        let error = format!(
            "{:?}",
            load(with(config(), "validators", serde_json::json!(malformed))).unwrap_err(),
        );
        assert!(error.contains("not a URL"), "unexpected error: {error}");

        // A URL with no host parses and is still not a validator.
        let mut hostless = validators();
        hostless[0] = serde_json::Value::String("mailto:ops@example.com".to_string());
        let error = format!(
            "{:?}",
            load(with(config(), "validators", serde_json::json!(hostless))).unwrap_err(),
        );
        assert!(error.contains("no host"), "unexpected error: {error}");
    }

    /// Two spellings of one address are one validator, not two.
    ///
    /// Distinctness is a question about addresses. `HTTP://127.0.0.1:9001`
    /// and `http://127.0.0.1:9001/` differ as strings and name the same
    /// node, so a string comparison would accept a fan-out to five.
    #[test]
    fn a_validator_named_twice_in_two_spellings_is_refused() {
        let mut spelled = validators();
        spelled[5] = serde_json::Value::String("HTTP://127.0.0.1:9001".to_string());
        let error = format!(
            "{:?}",
            load(with(config(), "validators", serde_json::json!(spelled))).unwrap_err(),
        );
        assert!(error.contains("twice"), "unexpected error: {error}");
    }

    /// The loaded list is the normalised one, because that is what gets
    /// dialled and what was compared.
    #[test]
    fn validators_are_loaded_normalised() {
        let loaded = load(config()).expect("the fixture config loads");
        assert_eq!(
            loaded.validators[0], "http://127.0.0.1:9001/",
            "the parsed URL, not the string the operator typed",
        );
    }

    /// A zero execution-policy field is refused at load, by the
    /// protocol's own check.
    ///
    /// Every one of these is a value both parties sign, and each zero is
    /// an absent bound rather than a small one. Copying them through
    /// unchecked moves the refusal to the first admission, with a
    /// counterparty already waiting.
    #[test]
    fn a_zero_execution_policy_field_is_refused() {
        for field in [
            "fixed_price",
            "max_prompt_tokens",
            "max_new_tokens",
            "max_spool_bytes",
            "max_encoded_result_frame",
            "max_encoded_quote_response",
            "dispatch_margin_blocks",
            "delivery_margin_blocks",
            "oracle_grace_blocks",
        ] {
            let mut value = config();
            value["policies"]["execution"][field] = serde_json::json!(0);
            let Err(refusal) = load(value) else {
                panic!("a zero {field} loaded");
            };
            let error = format!("{refusal:?}");
            assert!(
                error.contains(field),
                "the refusal for a zero {field} does not name it: {error}",
            );
        }

        // The one bound that may be zero: a channel admitting no stop
        // tokens is a channel whose jobs run to `max_new_tokens`.
        let mut value = config();
        value["policies"]["execution"]["max_stop_token_ids"] = serde_json::json!(0);
        let loaded = load(value).expect("no stop tokens is a usable channel");
        assert_eq!(loaded.execution_policy.max_stop_token_ids, 0);
    }

    #[test]
    fn a_threshold_identity_consensus_cannot_decode_is_refused() {
        // A prefix of a real identity: hexadecimal, non-empty, and not a
        // point. A length check wearing consensus's name would take it.
        let mut broken = THRESHOLD_IDENTITY.to_vec();
        broken.truncate(32);
        let chain = serde_json::json!({
            "network_id": "hellas-devnet",
            "genesis_payload_digest": hex32(0x01),
            "threshold_identity": hex::encode(&broken),
        });
        let error = format!("{:?}", load(with(config(), "chain", chain)).unwrap_err());
        assert!(
            error.contains("threshold_identity"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn a_checkpoint_larger_than_a_journal_record_is_refused() {
        let journal = serde_json::json!({
            "root": "/var/lib/hellas/work",
            "max_active_bytes": 67_108_864_u64,
            "max_active_frames": 4_096_u64,
            "max_checkpoint_bytes": (MAX_RECORD_BYTES as u64) + 1,
        });
        let error = format!(
            "{:?}",
            load(with(config(), "journal", journal)).unwrap_err()
        );
        assert!(
            error.contains("max_checkpoint_bytes"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn a_watcher_that_never_polls_is_refused() {
        let error = format!(
            "{:?}",
            load(with(config(), "poll_ms", serde_json::json!(0))).unwrap_err(),
        );
        assert!(error.contains("poll_ms"), "unexpected error: {error}");
    }
}
