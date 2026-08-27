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
//! The **floor arithmetic** is not here either: the `64 >= T`
//! inequality and the Clopper–Pearson confidence test consume timings no
//! producer in this tree yet emits. What is here is the artifact those
//! timings will be written into, and the labelling that lets a node with
//! none of them say so out loud. Every number in the artifact carries
//! `measured` or `assumed`; one `assumed` field is a node that
//! countersigns no new channel; and no number is invented to fill a gap.
//! [`load_paid_work_duties`] is how the serve path asks which of §4's
//! four evidence cases it started in, and every one of them still
//! answers a contest.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use hellas_kernel::{EdgeValues, Fees, NetworkId};
use hellas_rpc::ContentId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, check_execution_policy,
};
use hellas_rpc::protocol::work_setup::{OmissionMeasurements, ProviderChannelPolicy};
use hellas_rpc::work_handshake::PaymentAdmission;
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

    /// The provider policy this configuration and one read artifact
    /// make together.
    ///
    /// The four fields a provider fixes for itself come from the
    /// configuration; the two it can only have measured come from the
    /// artifact. Which variant it lands in is the artifact's weakest
    /// label and nothing else — the numbers are identical either way,
    /// which is the point: what turns admission off is the absence of
    /// evidence, not a value that failed a test.
    fn duties(&self, artifact: MeasuredArtifact) -> PaidWorkDuties {
        let evidence = Box::new(MeasuredEvidence {
            provenance: artifact.provenance,
            samples: artifact.samples,
            policy: ProviderChannelPolicy {
                network: self.chain.network,
                policy_salt: self.policy_salt,
                channel_policy: self.channel_policy,
                execution_policy: self.execution_policy,
                expected_payment_values: artifact.expected_payment_values,
                omission: artifact.omission,
            },
        });
        match artifact.evidence {
            Evidence::Measured => PaidWorkDuties::Admits(evidence),
            Evidence::Assumed => PaidWorkDuties::Assumed(evidence),
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

/// What one node's evidence lets it do with paid work, decided once at
/// startup.
///
/// These are §4's four cases, and its rule is what separates them:
/// missing, changed or `assumed` evidence disables setup and new work,
/// and never disables recovery or the close duty. So *every* variant
/// below is a node that still answers a contest — the close half is
/// built from a journal and a key and asks for no policy at all
/// ([`CloseEndpoint`]) — and only [`Self::Admits`] countersigns a new
/// channel.
///
/// [`CloseEndpoint`]: hellas_rpc::work::CloseEndpoint
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the endpoint these duties are handed to is the node runner's half; deciding them is this one"
)]
pub enum PaidWorkDuties {
    /// The pinned artifact was read and every field in it is measured.
    /// This node countersigns new paid channels over the policy it
    /// makes.
    Admits(Box<MeasuredEvidence>),
    /// The pinned artifact was read and at least one field in it is
    /// `assumed`. The policy is still made, because setup journals and
    /// close descriptors are derived from it, and no payment is ever
    /// countersigned over it.
    Assumed(Box<MeasuredEvidence>),
    /// The configuration names no artifact.
    NotConfigured,
    /// The configuration names an artifact and there is no file there.
    /// This is a node before its bootstrap run, not a broken one.
    NotFound,
    /// A well-formed artifact that is not the one `artifact.digest`
    /// pins: §4's *changed* evidence, from another binary, another
    /// configuration or another machine.
    Changed,
}

impl PaidWorkDuties {
    /// What a setup endpoint over this evidence will countersign, or
    /// `None` when there is no policy to build one from.
    ///
    /// [`PaymentAdmission::Admits`] only under a fully measured
    /// artifact. Under an assumed one the same policy is handed over as
    /// [`PaymentAdmission::Proposes`], which is the admission that holds
    /// a policy, derives close state from it through
    /// [`ProviderChannelPolicy::describe_close`], and countersigns
    /// nothing: an endpoint under it refuses every proposed payment as
    /// `Declined`. That is what turns an unmeasured number into a
    /// missing countersignature, without a second admission flag beside
    /// the one the handshake already reads.
    ///
    /// `None` is not a weaker admission, it is no setup endpoint at all.
    /// With no artifact there are no omission measurements and no
    /// expected funding, and a policy invented to fill that gap would be
    /// exactly the measurement this node does not have.
    #[must_use]
    #[allow(
        dead_code,
        reason = "the endpoint these duties are handed to is the node runner's half; deciding them is this one"
    )]
    pub fn payment_admission(&self) -> Option<PaymentAdmission> {
        match self {
            Self::Admits(evidence) => {
                Some(PaymentAdmission::Admits(Box::new(evidence.policy.clone())))
            }
            Self::Assumed(evidence) => Some(PaymentAdmission::Proposes(Box::new(
                evidence.policy.clone(),
            ))),
            Self::NotConfigured | Self::NotFound | Self::Changed => None,
        }
    }

    /// The artifact this node started under, when it read one.
    #[must_use]
    #[allow(
        dead_code,
        reason = "the endpoint these duties are handed to is the node runner's half; deciding them is this one"
    )]
    pub const fn evidence(&self) -> Option<&MeasuredEvidence> {
        match self {
            Self::Admits(evidence) | Self::Assumed(evidence) => Some(evidence),
            Self::NotConfigured | Self::NotFound | Self::Changed => None,
        }
    }

    /// Whether this node countersigns new paid channels.
    #[must_use]
    pub const fn admits_paid_work(&self) -> bool {
        matches!(self, Self::Admits(_))
    }

    /// The one line the operator gets at startup, naming the case.
    ///
    /// A method rather than a string built at the log site, so what the
    /// node says is the same thing a test can read back. Every line that
    /// is not the admitting one opens with the same four words, because
    /// that is the fact an operator is looking for, and then says which
    /// of the four cases produced it.
    #[must_use]
    pub const fn summary(&self) -> &'static str {
        match self {
            Self::Admits(_) => {
                "paid admission is on: every field of the pinned artifact is measured"
            }
            Self::Assumed(_) => {
                "no paid admission: the pinned artifact carries at least one assumed field; \
                 setup, recovery and the close duty still run"
            }
            Self::NotConfigured => {
                "no paid admission: no measured artifact is configured; \
                 recovery and the close duty still run"
            }
            Self::NotFound => {
                "no paid admission: no artifact was found at the configured path; \
                 recovery and the close duty still run"
            }
            Self::Changed => {
                "no paid admission: the artifact at the configured path is not the one \
                 artifact.digest pins; recovery and the close duty still run"
            }
        }
    }
}

/// One artifact a node started under, and the policy it makes.
///
/// The two numbers the artifact contributes are inside the policy, which
/// is where every consumer wants them. What stays outside is what the
/// policy has no field for and an operator still has to be able to read
/// back: who produced this evidence, and how much of it there is.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the endpoint these duties are handed to is the node runner's half; deciding them is this one"
)]
pub struct MeasuredEvidence {
    /// Which binary, configuration and machine produced the artifact,
    /// and when.
    pub provenance: ArtifactProvenance,
    /// The fewest samples any one field of the artifact rests on. Zero
    /// whenever any field is `assumed`, because an assumed field rests
    /// on none — so this is the weakest link and not an average.
    pub samples: u64,
    /// The policy a setup endpoint is built over.
    pub policy: ProviderChannelPolicy,
}

/// Which run produced one artifact.
///
/// A measurement is a statement about a binary on a machine under a
/// configuration, and an artifact that does not say which is a number
/// with no subject. None of this is compared to anything here: this node
/// has no clock in this path and builds none, so the timestamp is read
/// and carried and never checked against a now.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the endpoint these duties are handed to is the node runner's half; deciding them is this one"
)]
pub struct ArtifactProvenance {
    /// Digest of the binary that measured.
    pub binary: Digest,
    /// Digest of the work configuration it measured under.
    pub config: Digest,
    /// The machine it measured on, as the operator names it.
    pub machine: String,
    /// When the run finished, in milliseconds since the Unix epoch, as
    /// the artifact records it.
    pub measured_at_unix_ms: u64,
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

/// Reads the artifact a configuration pins, and decides what this node's
/// evidence lets it do.
///
/// Three of the five answers are answers and not errors, which is §4's
/// rule rather than a leniency: a node whose artifact is absent, or is
/// not the pinned one, still owes every open contest a response, and
/// refusing to start is the one thing that guarantees the response is
/// never made. So missing and changed evidence turn admission off and
/// leave the node running.
///
/// What *is* an error is a file that is present and is not an artifact.
/// An operator writes this by hand until the bootstrap run writes it, so
/// the field that is wrong is named, at startup, exactly as
/// [`load_work_config`] names a configuration field.
///
/// The pin is compared after the parse and not before, for that reason:
/// a typo in a file whose digest also differs would otherwise be
/// reported as somebody else's artifact, and the operator would never
/// learn which field they got wrong.
///
/// # Errors
///
/// A file that does not parse, an unknown or missing field, a digest or
/// machine name that is not one, and a label its sample count
/// contradicts.
pub fn load_paid_work_duties(config: &WorkConfig) -> CliResult<PaidWorkDuties> {
    let Some(identity) = config.measured_artifact() else {
        return Ok(PaidWorkDuties::NotConfigured);
    };
    let bytes = match fs::read(&identity.path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PaidWorkDuties::NotFound);
        }
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "failed to read artifact {}",
                identity.path.display()
            )));
        }
    };
    let file: ArtifactBodyFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse artifact {}", identity.path.display()))?;
    let artifact = file
        .into_artifact()
        .with_context(|| format!("invalid artifact {}", identity.path.display()))?;
    if Digest::hash(&bytes) != identity.digest {
        return Ok(PaidWorkDuties::Changed);
    }
    Ok(config.duties(artifact))
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

// ── The measured artifact ─────────────────────────────────────────────

/// Whether one number was measured or written down.
///
/// Two answers and no third. `assumed` is a legal value and not a parse
/// error, because it is how a node that has never run a bootstrap says
/// what it *would* use without claiming to have seen it; §4 makes that
/// node one that admits no paid work and still runs recovery, which is a
/// startup case rather than a refusal.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Evidence {
    /// Observed, over the samples reported beside it.
    Measured,
    /// Written down. No sample supports it.
    Assumed,
}

impl Evidence {
    /// The weaker of two labels: one assumed field makes a whole
    /// artifact assumed.
    const fn weakest(self, other: Self) -> Self {
        match (self, other) {
            (Self::Measured, Self::Measured) => Self::Measured,
            _ => Self::Assumed,
        }
    }
}

/// One number in the artifact, and what it rests on.
///
/// The label travels with the number rather than with the file, because
/// a run that measured five of six quantities has an artifact that can
/// say which one it did not. `samples` is what the label is answerable
/// to: a `measured` number with no sample behind it is not a
/// measurement, and an `assumed` number reporting samples is a
/// measurement wearing the wrong label. Both are refused, by name.
///
/// Nothing here grades the number. The `64 >= T` floor and the
/// confidence bound are §4-B's and consume timings this tree does not
/// yet emit; this is the honest label they will one day be computed
/// from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasuredU64 {
    value: u64,
    evidence: Evidence,
    samples: u64,
}

impl MeasuredU64 {
    fn check(&self, field: &str) -> CliResult<()> {
        match (self.evidence, self.samples) {
            (Evidence::Measured, 0) => {
                bail!("{field} is labelled measured and rests on no samples")
            }
            (Evidence::Assumed, samples) if samples != 0 => {
                bail!("{field} is labelled assumed and reports {samples} samples")
            }
            _ => Ok(()),
        }
    }
}

/// One artifact, read and folded into the two values a policy needs.
struct MeasuredArtifact {
    provenance: ArtifactProvenance,
    omission: OmissionMeasurements,
    expected_payment_values: EdgeValues,
    evidence: Evidence,
    samples: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBodyFile {
    provenance: ProvenanceFile,
    omission: OmissionFile,
    expected_payment_values: PaymentValuesFile,
}

impl ArtifactBodyFile {
    fn into_artifact(self) -> CliResult<MeasuredArtifact> {
        // Every labelled number in the file, checked against its own
        // sample count and then folded to the two summaries a node acts
        // on: the weakest label any field carries, and the fewest
        // samples any field rests on. Listed rather than derived so a
        // field added to the schema and left out of this list is a
        // compile-time hole an author sees, not a field whose label is
        // silently never read.
        let fields = [
            (
                "omission.response_probability",
                &self.omission.response_probability,
            ),
            ("omission.response_blocks", &self.omission.response_blocks),
            (
                "omission.response_cost_cap",
                &self.omission.response_cost_cap,
            ),
            (
                "expected_payment_values.value",
                &self.expected_payment_values.value,
            ),
            (
                "expected_payment_values.reserve",
                &self.expected_payment_values.reserve,
            ),
            (
                "expected_payment_values.close_fees.base",
                &self.expected_payment_values.close_fees.base,
            ),
            (
                "expected_payment_values.close_fees.slot",
                &self.expected_payment_values.close_fees.slot,
            ),
            (
                "expected_payment_values.close_fees.proof",
                &self.expected_payment_values.close_fees.proof,
            ),
            (
                "expected_payment_values.close_fees.lifetime",
                &self.expected_payment_values.close_fees.lifetime,
            ),
        ];
        let mut evidence = Evidence::Measured;
        let mut samples = u64::MAX;
        for (name, field) in fields {
            field.check(name)?;
            evidence = evidence.weakest(field.evidence);
            samples = samples.min(field.samples);
        }

        Ok(MeasuredArtifact {
            provenance: self.provenance.into_provenance()?,
            omission: OmissionMeasurements {
                response_probability: self.omission.response_probability.value,
                response_blocks: self.omission.response_blocks.value,
                response_cost_cap: self.omission.response_cost_cap.value,
            },
            expected_payment_values: EdgeValues::new(
                self.expected_payment_values.value.value,
                self.expected_payment_values.reserve.value,
                Fees::new(
                    self.expected_payment_values.close_fees.base.value,
                    self.expected_payment_values.close_fees.slot.value,
                    self.expected_payment_values.close_fees.proof.value,
                    self.expected_payment_values.close_fees.lifetime.value,
                ),
            ),
            evidence,
            samples,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceFile {
    binary: String,
    config: String,
    machine: String,
    measured_at_unix_ms: u64,
}

impl ProvenanceFile {
    fn into_provenance(self) -> CliResult<ArtifactProvenance> {
        if self.machine.trim().is_empty() {
            bail!("provenance.machine must name a machine");
        }
        Ok(ArtifactProvenance {
            binary: parse_digest("provenance.binary", &self.binary)?,
            config: parse_digest("provenance.config", &self.config)?,
            machine: self.machine,
            measured_at_unix_ms: self.measured_at_unix_ms,
        })
    }
}

/// The three numbers [`OmissionMeasurements`] is, field for field.
///
/// Spelled out rather than flattened for [`ExecutionPolicyFile`]'s
/// reason: these are the numbers a provider's whole new-work admission
/// rests on, and a default here would be this node claiming a
/// measurement its operator never made.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OmissionFile {
    response_probability: MeasuredU64,
    response_blocks: MeasuredU64,
    response_cost_cap: MeasuredU64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentValuesFile {
    value: MeasuredU64,
    reserve: MeasuredU64,
    close_fees: CloseFeesFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseFeesFile {
    base: MeasuredU64,
    slot: MeasuredU64,
    proof: MeasuredU64,
    lifetime: MeasuredU64,
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

    // ── The measured artifact ─────────────────────────────────────────

    use hellas_kernel::{
        BlockHeight, CoinId, EdgeId, Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
        Payout, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkPaymentTerms,
        WorkStakeBondTerms,
    };
    use hellas_rpc::protocol::work::private_policy_commitment;
    use hellas_rpc::work_handshake::SetupEndpoint;
    use hellas_rpc::work_store::{Role, SetupScan, SetupStore};

    /// The window the fixture artifact measured its response
    /// probability over, and the one the fixture's terms admit.
    const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS + 4;
    const OMISSION_BOND: u64 = 4;
    const PAYMENT_VALUE: u64 = 1_000;
    const PAYMENT_RESERVE: u64 = 200;

    fn network() -> NetworkId {
        let Some(network) = NetworkId::new("hellas-devnet") else {
            panic!("the fixture configuration's network id is one");
        };
        network
    }

    fn measured(value: u64) -> serde_json::Value {
        serde_json::json!({ "value": value, "evidence": "measured", "samples": 3_000 })
    }

    fn assumed(value: u64) -> serde_json::Value {
        serde_json::json!({ "value": value, "evidence": "assumed", "samples": 0 })
    }

    /// The artifact a completed bootstrap run leaves behind: every
    /// number measured, and every number one this fixture's terms are
    /// priced by.
    fn artifact() -> serde_json::Value {
        serde_json::json!({
            "provenance": {
                "binary": hex32(0x21),
                "config": hex32(0x22),
                "machine": "bootstrap-1",
                "measured_at_unix_ms": 1_756_339_200_000_u64,
            },
            "omission": {
                "response_probability": measured(999_000),
                "response_blocks": measured(WINDOW),
                "response_cost_cap": measured(1),
            },
            "expected_payment_values": {
                "value": measured(PAYMENT_VALUE),
                "reserve": measured(PAYMENT_RESERVE),
                "close_fees": {
                    "base": measured(0),
                    "slot": measured(0),
                    "proof": measured(0),
                    "lifetime": measured(0),
                },
            },
        })
    }

    /// Writes one artifact beside a configuration that pins it, and
    /// answers what that node's evidence lets it do.
    ///
    /// The pin is the digest of the bytes actually written, unless
    /// `pin` overrides it: the changed-evidence case then differs from
    /// the matching one in exactly the field under test and in nothing
    /// else.
    fn duties_for(artifact: &serde_json::Value, pin: Option<String>) -> CliResult<PaidWorkDuties> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.json");
        let bytes = artifact.to_string();
        fs::write(&path, &bytes).unwrap();
        let digest = pin.unwrap_or_else(|| hex::encode(Digest::hash(bytes.as_bytes()).as_bytes()));
        let loaded = load(with(
            config(),
            "artifact",
            serde_json::json!({ "path": path.display().to_string(), "digest": digest }),
        ))?;
        load_paid_work_duties(&loaded)
    }

    /// Inserts `field` into the object at `path`, which the schema does
    /// not define.
    fn with_unknown(mut value: serde_json::Value, path: &[&str], field: &str) -> serde_json::Value {
        let mut cursor = &mut value;
        for step in path {
            cursor = cursor.get_mut(step).unwrap();
        }
        cursor
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), serde_json::json!(1));
        value
    }

    fn signer(byte: u8) -> Secp256k1Signer {
        let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
            panic!("a fixed scalar is a key");
        };
        signer
    }

    fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
        let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
        for (slot, id) in slots.iter_mut().zip(ids) {
            *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
        }
        List::take(slots, ids.len())
    }

    fn bond_terms() -> WorkStakeBondTerms {
        WorkStakeBondTerms {
            parties: Parties::new(signer(0x22).party_key(), signer(0x21).party_key()),
            timeout: BlockHeight::new(500),
            timeout_outputs: List::take(
                [Payout::new(signer(0x22).party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: 40,
        }
    }

    /// The provider's stake funding: its own coins, none of the
    /// client's.
    fn bond_funding() -> Funding {
        Funding::new(coins(&[0xa1]), coins(&[]))
    }

    /// The edge the bond opens at, which is also the key the setup
    /// journal is opened under.
    fn bond_edge() -> EdgeId {
        Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms()))
    }

    /// The terms a client proposes over that bond.
    ///
    /// The commitment is opened against the *configuration's* own salt
    /// and credit policy, because that is what a provider's admission
    /// re-derives: terms committing to any other policy are refused
    /// rather than countersigned.
    fn payment_terms() -> WorkPaymentTerms {
        WorkPaymentTerms {
            bond_edge: bond_edge(),
            bond_terms: bond_terms(),
            private_policy_commitment: private_policy_commitment(
                network(),
                &[0x5a; 32],
                &PaidChannelPolicyV1 {
                    compute_credit_limit: 40,
                    delivery_credit_limit: 40,
                },
            ),
            omit_response_blocks: WINDOW,
            start_validity_blocks: 8,
            omission_bond: OMISSION_BOND,
        }
    }

    fn payment_edge() -> EdgeId {
        EdgeId::from_bytes([0xc0; EdgeId::LENGTH])
    }

    /// Opens a provider's setup journal under its own directory, with
    /// its immutable history floor armed.
    ///
    /// The floor is armed here because a provider's own first revision
    /// is refused without one: recovery arming is not a step evidence
    /// gates, it is the step every later one is refused before.
    fn setup_endpoint(dir: &tempfile::TempDir, admission: PaymentAdmission) -> SetupEndpoint {
        let store = match SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &Secp256k1Verifier::new(),
        ) {
            Ok(store) => store,
            Err(error) => panic!("the fixture journal opens: {error}"),
        };
        let mut endpoint = SetupEndpoint::new(store, signer(0x22), admission);
        if let Err(error) = endpoint.arm_scan(SetupScan {
            height: 7,
            payload: [0x47; 32],
        }) {
            panic!("the fixture arms its immutable history floor: {error}");
        }
        endpoint
    }

    /// The artifact round-trips: every labelled number arrives in the
    /// policy, and what the policy has no field for arrives beside it.
    #[test]
    fn a_measured_artifact_round_trips_into_a_policy() {
        let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");

        assert!(duties.admits_paid_work());
        let evidence = duties.evidence().expect("a read artifact is evidence");
        assert_eq!(
            evidence.provenance,
            ArtifactProvenance {
                binary: Digest::from_bytes([0x21; 32]),
                config: Digest::from_bytes([0x22; 32]),
                machine: "bootstrap-1".to_string(),
                measured_at_unix_ms: 1_756_339_200_000,
            },
        );
        assert_eq!(evidence.samples, 3_000);
        assert_eq!(
            evidence.policy.omission,
            OmissionMeasurements {
                response_probability: 999_000,
                response_blocks: WINDOW,
                response_cost_cap: 1,
            },
        );
        assert_eq!(
            evidence.policy.expected_payment_values,
            EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
        );
        // The four fields a provider fixes for itself come from the
        // configuration and never from the artifact.
        assert_eq!(evidence.policy.network.as_str(), "hellas-devnet");
        assert_eq!(evidence.policy.policy_salt, [0x5a; 32]);
        assert_eq!(evidence.policy.channel_policy.compute_credit_limit, 40);
        assert_eq!(evidence.policy.execution_policy.fixed_price, 10);
        assert_eq!(
            duties.summary(),
            "paid admission is on: every field of the pinned artifact is measured",
        );
    }

    /// An unknown artifact field is refused by name, wherever it sits.
    ///
    /// The names are §4-B's on purpose: the confidence bound, the
    /// lower-tail block time and the restart downtime are what a later
    /// measured gate consumes, and a file carrying one today is an
    /// operator configuring something this node does not implement.
    #[test]
    fn an_unknown_artifact_field_is_refused_by_name() {
        for (path, field) in [
            (&[][..], "lower_tail_block_ms"),
            (&["provenance"][..], "restart_downtime_ms"),
            (&["omission"][..], "general_inclusion_blocks"),
            (
                &["omission", "response_probability"][..],
                "confidence_upper",
            ),
            (&["expected_payment_values", "close_fees"][..], "settlement"),
        ] {
            let error = format!(
                "{:?}",
                duties_for(&with_unknown(artifact(), path, field), None)
                    .expect_err("an unknown artifact field is refused"),
            );
            assert!(
                error.contains(field),
                "the refusal for {field} does not name it: {error}",
            );
        }
    }

    /// Every artifact field is required, and the label most of all: a
    /// number with no `evidence` beside it would be a measurement
    /// nobody claimed.
    #[test]
    fn a_missing_artifact_field_is_refused_by_name() {
        for (path, field) in [
            (&["provenance"][..], "machine"),
            (&["provenance"][..], "measured_at_unix_ms"),
            (&["omission"][..], "response_blocks"),
            (&["omission", "response_cost_cap"][..], "evidence"),
            (&["omission", "response_cost_cap"][..], "samples"),
            (&["expected_payment_values"][..], "close_fees"),
            (&["expected_payment_values", "close_fees"][..], "lifetime"),
        ] {
            let error = format!(
                "{:?}",
                duties_for(&without(artifact(), path, field), None)
                    .expect_err("an artifact missing a required field is refused"),
            );
            assert!(
                error.contains(field),
                "the refusal for a missing {field} does not name it: {error}",
            );
        }
    }

    /// A label its own sample count contradicts is refused by name.
    ///
    /// Both directions, because both are dishonest: a `measured` number
    /// resting on nothing is not a measurement, and an `assumed` number
    /// reporting samples is a measurement wearing the wrong label — and
    /// the second one would turn paid admission *off* for a node that
    /// had actually earned it.
    #[test]
    fn a_label_its_samples_contradict_is_refused_by_name() {
        let mut unsampled = artifact();
        unsampled["omission"]["response_blocks"] =
            serde_json::json!({ "value": WINDOW, "evidence": "measured", "samples": 0 });
        let error = format!("{:?}", duties_for(&unsampled, None).unwrap_err());
        assert!(
            error.contains("omission.response_blocks") && error.contains("no samples"),
            "unexpected error: {error}",
        );

        let mut oversampled = artifact();
        oversampled["expected_payment_values"]["reserve"] = serde_json::json!({
            "value": PAYMENT_RESERVE,
            "evidence": "assumed",
            "samples": 12,
        });
        let error = format!("{:?}", duties_for(&oversampled, None).unwrap_err());
        assert!(
            error.contains("expected_payment_values.reserve"),
            "unexpected error: {error}",
        );
    }

    /// A fully measured artifact yields a policy that admits, and an
    /// admission that countersigns.
    #[test]
    fn a_measured_artifact_yields_a_policy_that_admits() {
        let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");
        let policy = &duties
            .evidence()
            .expect("a read artifact is evidence")
            .policy;

        let descriptor = policy
            .admit(payment_edge(), payment_terms())
            .expect("a measured policy admits the terms it was measured for");

        assert_eq!(descriptor.bond_edge(), bond_edge());
        assert!(matches!(
            duties.payment_admission(),
            Some(PaymentAdmission::Admits(_)),
        ));
    }

    /// One `assumed` field is a node that countersigns nothing and
    /// still runs setup and the close duty.
    ///
    /// The numbers are the measured fixture's, to the byte: only the
    /// label moves. So what refuses admission is the absence of
    /// evidence and not a value that failed a check — `admit` on this
    /// very policy still succeeds, and the endpoint built over it never
    /// gets to ask, because `Proposes` declines every proposed payment.
    #[test]
    fn an_assumed_field_refuses_admission_and_keeps_setup_and_close() {
        let mut value = artifact();
        value["omission"]["response_cost_cap"] = assumed(1);
        let duties = duties_for(&value, None).expect("an assumed artifact still loads");
        let measured = duties_for(&artifact(), None).expect("the fixture artifact loads");

        assert!(!duties.admits_paid_work());
        let evidence = duties.evidence().expect("a read artifact is evidence");
        assert_eq!(evidence.samples, 0, "an assumed field rests on no samples");
        assert_eq!(
            evidence.policy,
            measured
                .evidence()
                .expect("a read artifact is evidence")
                .policy,
            "only the label moved",
        );
        evidence
            .policy
            .admit(payment_edge(), payment_terms())
            .expect("the numbers themselves still price these terms");

        // Setup and the close duty still run: close state is derivable
        // from this policy, and an endpoint is built over an admission
        // that countersigns nothing.
        evidence
            .policy
            .describe_close(payment_edge(), payment_terms())
            .expect("close state is derivable from an assumed policy");
        let admission = duties.payment_admission().expect("an artifact was read");
        assert!(matches!(admission, PaymentAdmission::Proposes(_)));
        let dir = tempfile::tempdir().unwrap();
        let mut endpoint = setup_endpoint(&dir, admission);
        endpoint
            .propose_bond(network(), bond_funding(), bond_terms())
            .expect("an unmeasured provider still journals its half of a setup");

        assert!(
            duties.summary().contains("no paid admission"),
            "unexpected summary: {}",
            duties.summary(),
        );
    }

    /// No file at the configured path is a node before its bootstrap
    /// run, not a broken one: §4 disables new work on missing evidence
    /// and never disables recovery or the close duty.
    #[test]
    fn a_missing_artifact_admits_no_paid_work() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load(with(
            config(),
            "artifact",
            serde_json::json!({
                "path": dir.path().join("artifact.json").display().to_string(),
                "digest": hex32(0x77),
            }),
        ))
        .expect("a configuration pinning an artifact that is not there still loads");

        let duties =
            load_paid_work_duties(&loaded).expect("a missing artifact is an answer, not an error");

        assert_eq!(duties, PaidWorkDuties::NotFound);
        assert!(!duties.admits_paid_work());
        assert!(duties.payment_admission().is_none());
        assert!(
            duties.summary().contains("no paid admission"),
            "unexpected summary: {}",
            duties.summary(),
        );
    }

    /// A configuration naming no artifact at all is the same answer in
    /// different words.
    #[test]
    fn a_config_without_an_artifact_admits_no_paid_work() {
        let loaded = load(without(config(), &[], "artifact")).expect("the config still loads");
        assert!(loaded.measured_artifact().is_none());

        let duties = load_paid_work_duties(&loaded).expect("no artifact is not an error");

        assert_eq!(duties, PaidWorkDuties::NotConfigured);
        assert!(duties.payment_admission().is_none());
        assert!(
            duties.summary().contains("no paid admission"),
            "unexpected summary: {}",
            duties.summary(),
        );
    }

    /// An artifact that is not the one the configuration pins is
    /// refused as evidence, and the node still starts.
    ///
    /// §4 groups changed evidence with missing evidence: both disable
    /// setup and new work, and neither disables recovery or the close
    /// duty. Refusing to start would be the one way to guarantee an
    /// open contest is never answered.
    #[test]
    fn an_artifact_that_is_not_the_pinned_one_is_refused() {
        let duties = duties_for(&artifact(), Some(hex32(0x77)))
            .expect("changed evidence is an answer, not a startup failure");

        assert_eq!(duties, PaidWorkDuties::Changed);
        assert!(duties.payment_admission().is_none());
        assert!(
            duties.summary().contains("no paid admission"),
            "unexpected summary: {}",
            duties.summary(),
        );
    }

    /// A `ProviderChannelPolicy` is built from a configuration and its
    /// artifact, and a `SetupEndpoint` over that — which is the pair
    /// nothing in this crate could construct at all.
    #[test]
    fn a_setup_endpoint_is_built_from_the_loaded_policy() {
        let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");
        let admission = duties
            .payment_admission()
            .expect("a measured artifact carries an admission");
        let dir = tempfile::tempdir().unwrap();
        let mut endpoint = setup_endpoint(&dir, admission);

        assert!(endpoint.state().revision().is_none());
        let state = endpoint
            .propose_bond(network(), bond_funding(), bond_terms())
            .expect("the endpoint signs and journals its bond proposal");

        assert_eq!(state.revision(), Some(1));
    }
}
