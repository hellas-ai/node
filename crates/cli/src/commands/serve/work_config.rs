//! The paid-work configuration file: what an operator writes down, and
//! what a node refuses to start without.
//!
//! `--work-config` was a path whose *presence* advertised two ALPNs and
//! whose contents were never opened. A node cannot mount a channel from
//! a path, so this is the schema and the loader for what is in it: the
//! three-part chain cross-check, the six validator URLs a write is
//! fanned to, the journal root, the bilateral route table, the two
//! policies this provider works under, the watcher's poll cadence, the
//! response alarm's margin, and the identity of the measured artifact.
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
//! There is no Start-span field, no mutual-margin field, and no journal
//! cap. All were deleted: the Start span is fixed at 64, a work-payment
//! edge has no Mutual route, and the journal's active and checkpoint
//! ceilings are constants it enforces on itself
//! ([`MAX_ACTIVE_JOURNAL_BYTES`]), so any of them appearing in a file is
//! an operator configuring something that does not exist. Every struct
//! below denies unknown fields, which is what turns that into an error
//! naming the field.
//!
//! [`MAX_ACTIVE_JOURNAL_BYTES`]: hellas_rpc::work_store::journal::MAX_ACTIVE_JOURNAL_BYTES
//!
//! # The floor, and where it is decided
//!
//! §4-B's arithmetic is not spelled here either — it is
//! [`hellas_rpc::protocol::mount`], so that the startup check below and
//! [`ProviderChannelPolicy::admit`] run the same formulas over the same
//! samples. What is here is the artifact those samples are written into,
//! the labelling that lets a node with none of them say so out loud, and
//! the one judgement a reader makes rather than trusts: the raw
//! observations are reduced to §4's terms *here*, by this node. An
//! artifact cannot talk its way into admission by writing a flattering
//! summary; it can only report what it saw.
//!
//! Every number in the artifact carries `measured` or `assumed`; one
//! `assumed` field is a node that countersigns no new channel by default;
//! and no number is invented to fill a gap. The sole exception is the
//! explicitly unsafe, exact-network devnet escape hatch used to bootstrap an
//! isolated demo. It remains a distinct duty variant and an alarming startup
//! warning, so it cannot be reported as measured evidence.
//! [`load_paid_work_duties`] is how
//! the serve path asks which of §4's evidence cases it started in, and
//! every one of them still answers a contest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context as _, bail};
use hellas_kernel::{
    EdgeId, EdgeValues, Fees, Key, NetworkId, RESPONSE_POLL_BLOCKS, Secp256k1Verifier,
};
use hellas_rpc::ContentId;
use hellas_rpc::peers::PeerId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::mount::{FloorError, MountBudget, MountFloor};
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, check_execution_policy,
};
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_rpc::work_handshake::PaymentAdmission;
use hellas_rpc::work_store::{Role, SetupStore, discover_setups};
use serde::Deserialize;

use crate::commands::CliResult;

/// How many validator RPCs a write names.
///
/// Reads come from a follower and writes are fanned to all six; a
/// configuration naming five has one validator whose acceptance this
/// node can never win, and one naming seven names something this
/// deployment does not have.
pub const VALIDATOR_COUNT: usize = 6;

/// The only network on which assumed measurements may be admitted.
///
/// This is deliberately the full, shipped network id rather than a suffix or
/// substring check. A production network whose operator happened to put
/// "devnet" in its name must not acquire this escape hatch.
const UNSAFE_ASSUMED_ADMISSION_NETWORK: &str = "hellas-devnet-1";

/// One operator's complete paid-work configuration, loaded and structurally
/// checked.
///
/// A plain record with public fields, for [`WorkChannelConfig`]'s
/// reason: this is the shape a file fills in. Every file-local gate has
/// already run in [`load_work_config`]; the serve path then runs
/// [`validate_work_routes`] against the journals that must exist when it
/// starts. Provisioning shares the file loader before it creates one, which is
/// why disk agreement is not pretended to be a parse-time fact.
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
    /// Directory holding the setup and channel journals.
    pub journal_root: PathBuf,
    /// Bilateral setup routes, keyed by the authenticated transport peer.
    pub routes: WorkRoutes,
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
    /// Explicit, devnet-only escape hatch for admitting an artifact with
    /// `assumed` fields.
    ///
    /// The loader refuses this setting on every network except the shipped
    /// devnet. Missing, changed, malformed, or arithmetically refused
    /// artifacts remain fail-closed even there.
    pub unsafe_devnet_admit_assumed_measurements: bool,
}

/// One bilateral setup route written in the paid-work configuration.
///
/// The bond names the provider setup journal under [`WorkConfig::journal_root`].
/// The client key is repeated here deliberately: startup compares it with the
/// taker committed inside that journal, turning a stale or mistyped route into
/// a refusal before the node binds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRoute {
    /// The transport-authenticated peer allowed to reach this bond.
    pub peer: PeerId,
    /// The bond whose provider setup journal this route names.
    pub bond: EdgeId,
    /// The settlement key the bond terms must name as taker.
    pub client: Key,
}

/// Paid-work routes keyed by their authenticated peer.
///
/// Construction is private to the checked file loader. In particular, there
/// is no insertion API through which a caller could recreate last-one-wins
/// handling after duplicate peers and bonds have been refused.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkRoutes {
    by_peer: BTreeMap<PeerId, WorkRoute>,
}

impl WorkRoutes {
    /// Returns every configured route in peer order.
    pub fn iter(&self) -> impl Iterator<Item = &WorkRoute> {
        self.by_peer.values()
    }

    /// Returns how many bilateral routes were configured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_peer.len()
    }

    /// Returns whether no bilateral route was configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_peer.is_empty()
    }

    fn from_files(files: Vec<WorkRouteFile>) -> CliResult<Self> {
        let mut by_peer = BTreeMap::new();
        let mut bonds = BTreeSet::new();
        for file in files {
            let peer = PeerId::from_bytes(parse_fixed_hex("routes[].peer", &file.peer)?);
            let bond = EdgeId::from_bytes(parse_fixed_hex("routes[].bond", &file.bond)?);
            let client = Key::from_bytes(parse_fixed_hex("routes[].client", &file.client)?);
            let route = WorkRoute { peer, bond, client };
            if by_peer.insert(peer, route).is_some() {
                bail!("routes names peer {peer:#} twice; one authenticated peer has one route");
            }
            if !bonds.insert(bond) {
                bail!(
                    "routes names bond {} twice; one provider journal has one route",
                    hex::encode(bond.to_bytes()),
                );
            }
        }
        Ok(Self { by_peer })
    }
}

impl WorkConfig {
    /// Returns the measured artifact, or `None` when this node admits no
    /// paid work.
    ///
    /// It answers which of the two configurations this is, and a `None`
    /// is the fail-closed one. Recovery is unaffected either way — §4
    /// disables setup and new work on missing evidence, never recovery.
    #[must_use]
    pub const fn measured_artifact(&self) -> Option<&ArtifactIdentity> {
        self.artifact.as_ref()
    }

    /// Whether the explicit devnet-only assumed-measurement bypass is armed.
    #[must_use]
    pub const fn unsafe_devnet_admits_assumed_measurements(&self) -> bool {
        self.unsafe_devnet_admit_assumed_measurements
    }

    /// The provider policy this configuration and one read artifact
    /// make together, or the floor's refusal.
    ///
    /// The four fields a provider fixes for itself come from the
    /// configuration; the two it can only have measured come from the
    /// artifact; and the floor is computed here, by this node, over the
    /// artifact's raw samples.
    ///
    /// The floor is asked first and it is a refusal rather than a label.
    /// A missing or `assumed` number is a node that has not measured
    /// something yet — §4 leaves it setup and its close duty and takes
    /// away only its countersignature. A budget that does not clear
    /// `64 ≥ T`, or whose blocks take no time, or whose configured alarm
    /// fires later than the budget needs, is not weak evidence: it is a
    /// measurement of a deployment in which a start authorization
    /// expires before the channel it authorises can be reached. Such a
    /// node holds no policy at all, which is the same answer as naming
    /// no artifact, and its recovery and close duty are untouched
    /// because those are built from a journal and a key.
    ///
    /// A configured poll cadence is different: it controls the watcher
    /// that performs the close duty, and a cadence outside the four
    /// blocks the response window prices is an unusable configuration,
    /// not evidence that merely disables new admission.
    ///
    /// Past those gates, which variant it lands in is the artifact's
    /// weakest label and nothing else — the numbers are identical either
    /// way, which is the point: what turns admission off there is the
    /// absence of evidence, not a value that failed a test.
    ///
    /// # Errors
    ///
    /// `poll_ms` exceeds [`RESPONSE_POLL_BLOCKS`] at the artifact's own
    /// `lower_tail_block_ms`.
    fn duties(&self, artifact: MeasuredArtifact) -> CliResult<PaidWorkDuties> {
        let floor = match artifact.budget.floor() {
            Ok(floor) => floor,
            Err(refusal) => return Ok(PaidWorkDuties::Refused(refusal)),
        };
        let priced_poll_ms =
            u128::from(RESPONSE_POLL_BLOCKS) * u128::from(artifact.budget.lower_tail_block_ms);
        if self.poll.as_millis() > priced_poll_ms {
            bail!(
                "poll_ms {} exceeds the {priced_poll_ms} ms priced by \
                 RESPONSE_POLL_BLOCKS={RESPONSE_POLL_BLOCKS} at the artifact's \
                 lower_tail_block_ms={}",
                self.poll.as_millis(),
                artifact.budget.lower_tail_block_ms,
            );
        }
        if let Err(refusal) = floor
            .check_start_span()
            .and_then(|()| floor.check_alarm_margin(self.response_alarm_margin_blocks))
        {
            return Ok(PaidWorkDuties::Refused(refusal));
        }
        let evidence = Box::new(MeasuredEvidence {
            provenance: artifact.provenance,
            samples: artifact.samples,
            floor,
            policy: ProviderChannelPolicy {
                network: self.chain.network,
                policy_salt: self.policy_salt,
                channel_policy: self.channel_policy,
                execution_policy: self.execution_policy,
                expected_payment_values: artifact.expected_payment_values,
                floor,
            },
        });
        Ok(match artifact.evidence {
            Evidence::Measured => PaidWorkDuties::Admits(evidence),
            Evidence::Assumed if self.unsafe_devnet_admit_assumed_measurements => {
                PaidWorkDuties::UnsafeDevnetAdmitsAssumed(evidence)
            }
            Evidence::Assumed => PaidWorkDuties::Assumed(evidence),
        })
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
/// These are §4's evidence cases plus one conspicuous demo-only exception,
/// and its rule is what separates them:
/// missing, changed or `assumed` evidence disables setup and new work,
/// and never disables recovery or the close duty. So *every* variant
/// below is a node that still answers a contest — the close half is
/// built from a journal and a key and asks for no policy at all
/// ([`CloseEndpoint`]). Only [`Self::Admits`] and the explicit
/// [`Self::UnsafeDevnetAdmitsAssumed`] exception countersign a new channel.
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
    /// An explicitly unsafe node on the shipped devnet countersigns using an
    /// artifact that still contains `assumed` fields.
    ///
    /// This variant is kept distinct from [`Self::Admits`] so no status or
    /// operator output can mistake the demo bypass for measured evidence.
    UnsafeDevnetAdmitsAssumed(Box<MeasuredEvidence>),
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
    /// The file at the configured path is not the one
    /// `artifact.digest` pins, or the pinned artifact records another
    /// measuring binary: §4's *changed* evidence.
    Changed,
    /// The pinned artifact was read and §4's measured floor does not
    /// hold over it. This node countersigns nothing and holds no policy
    /// to countersign with; its recovery and close duty are built from a
    /// journal and a key and still run.
    Refused(FloorError),
}

impl PaidWorkDuties {
    /// What a setup endpoint over this evidence will countersign, or
    /// `None` when there is no policy to build one from.
    ///
    /// [`PaymentAdmission::Admits`] under a fully measured artifact, or
    /// under the separately named unsafe devnet bypass. Under an assumed
    /// artifact in the normal fail-closed mode the same policy is handed over as
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
            Self::Admits(evidence) | Self::UnsafeDevnetAdmitsAssumed(evidence) => {
                Some(PaymentAdmission::Admits(Box::new(evidence.policy.clone())))
            }
            Self::Assumed(evidence) => Some(PaymentAdmission::Proposes(Box::new(
                evidence.policy.clone(),
            ))),
            Self::NotConfigured | Self::NotFound | Self::Changed | Self::Refused(_) => None,
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
            Self::Admits(evidence)
            | Self::UnsafeDevnetAdmitsAssumed(evidence)
            | Self::Assumed(evidence) => Some(evidence),
            Self::NotConfigured | Self::NotFound | Self::Changed | Self::Refused(_) => None,
        }
    }

    /// Whether this node countersigns new paid channels.
    #[must_use]
    pub const fn admits_paid_work(&self) -> bool {
        matches!(self, Self::Admits(_) | Self::UnsafeDevnetAdmitsAssumed(_))
    }

    /// The one line the operator gets at startup, naming the case.
    ///
    /// A method rather than a string built at the log site, so what the
    /// node says is the same thing a test can read back. Every line that
    /// is not the admitting one opens with the same four words, because
    /// that is the fact an operator is looking for, and then says which
    /// evidence case produced it.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Admits(evidence) => format!(
                "paid admission is on: every field of the pinned artifact is measured, \
                 and its floor needs T={} of the 64-block start span",
                evidence.floor.t(),
            ),
            Self::UnsafeDevnetAdmitsAssumed(evidence) => format!(
                "UNSAFE DEVNET paid admission is on: the pinned artifact contains assumed \
                 measurements; its floor needs T={} of the 64-block start span",
                evidence.floor.t(),
            ),
            Self::Assumed(_) => {
                "no paid admission: the pinned artifact carries at least one assumed field; \
                 setup, recovery and the close duty still run"
                    .to_string()
            }
            Self::NotConfigured => "no paid admission: no measured artifact is configured; \
                 recovery and the close duty still run"
                .to_string(),
            Self::NotFound => "no paid admission: no artifact was found at the configured path; \
                 recovery and the close duty still run"
                .to_string(),
            Self::Changed => {
                "no paid admission: the artifact misses its configured digest or records \
                 another measuring binary; recovery and the close duty still run"
                    .to_string()
            }
            Self::Refused(refusal) => format!(
                "no paid admission: the measured floor refuses this deployment: {refusal}; \
                 recovery and the close duty still run"
            ),
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
    /// §4's floor over this artifact's raw samples, as this node
    /// computed it. The same value the policy carries, kept here too so
    /// an operator can read `T` back without opening a policy.
    pub floor: MountFloor,
    /// The policy a setup endpoint is built over.
    pub policy: ProviderChannelPolicy,
}

/// Which run produced one artifact.
///
/// A measurement is a statement about a binary on a machine under a
/// configuration, and an artifact that does not say which is a number
/// with no subject. The binary is compared with the executable loading
/// the artifact. The configuration digest cannot honestly be compared:
/// the probe hashes the configuration before its output digest is put
/// into that same file, so installing `artifact.digest` necessarily
/// changes the recorded bytes. Nor can the operator's `--machine` label
/// be reconstructed, because serve is given no corresponding label.
/// Those two identities are therefore read and carried, not claimed as
/// deployment checks. This node also has no clock in this path and
/// builds none, so the timestamps are checked against one another and
/// against the samples, but never against a now.
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
    /// When the run began, in milliseconds since the Unix epoch, as the
    /// artifact records it. The pair with
    /// [`Self::measured_at_unix_ms`] bounds every raw sample in the
    /// file, which is what makes a sample's own timestamp checkable
    /// against something.
    pub started_at_unix_ms: u64,
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
/// policy the protocol's own [`check_execution_policy`] rejects, an
/// empty journal root, a route field of the wrong width, duplicate peers or
/// bonds in the route table, a zero poll cadence, and a zero response-alarm
/// margin.
pub fn load_work_config(path: &Path) -> CliResult<WorkConfig> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: WorkConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    file.into_config()
        .with_context(|| format!("invalid work config {}", path.display()))
}

/// Verifies that every configured route names this root's provider journal
/// and the client settlement key committed by its bond terms.
///
/// This is a serve-startup check rather than part of [`load_work_config`]:
/// provisioning uses the same configuration loader before it creates a
/// journal, while a serving node must already have every journal it promises.
/// Discovery comes first so [`SetupStore::open`] is never allowed to create a
/// missing journal merely because a route named its bond.
///
/// # Errors
///
/// The root cannot be enumerated, a route's provider journal is absent from
/// that root or cannot be opened, the journal holds no bond proposal, or its
/// bond names a taker other than the route's configured client.
pub(super) fn validate_work_routes(config: &WorkConfig) -> CliResult<()> {
    if config.routes.is_empty() {
        return Ok(());
    }
    let found = discover_setups(&config.journal_root, config.chain.network).with_context(|| {
        format!(
            "failed to enumerate configured work routes under journal.root {}",
            config.journal_root.display(),
        )
    })?;
    for route in config.routes.iter() {
        if !found
            .setups
            .iter()
            .any(|setup| setup.role == Role::Provider && setup.bond_edge == route.bond)
        {
            bail!(
                "route for peer {:#} names bond {}, but its provider setup journal is not under \
                 journal.root {}",
                route.peer,
                hex::encode(route.bond.to_bytes()),
                config.journal_root.display(),
            );
        }
        let store = SetupStore::open(
            &config.journal_root,
            config.chain.network,
            route.bond,
            Role::Provider,
            &Secp256k1Verifier::new(),
        )
        .with_context(|| {
            format!(
                "route for peer {:#} could not open provider setup journal for bond {} under {}",
                route.peer,
                hex::encode(route.bond.to_bytes()),
                config.journal_root.display(),
            )
        })?;
        let Some(bundle) = store.state().bundle() else {
            bail!(
                "route for peer {:#} names provider setup journal for bond {}, but it holds no \
                 bond proposal",
                route.peer,
                hex::encode(route.bond.to_bytes()),
            );
        };
        let journal_client = bundle.bond_terms().parties.taker();
        if journal_client != route.client {
            bail!(
                "route for peer {:#} expects client settlement key {}, but provider setup journal \
                 for bond {} names {} as its taker",
                route.peer,
                hex::encode(route.client.to_bytes()),
                hex::encode(route.bond.to_bytes()),
                hex::encode(journal_client.to_bytes()),
            );
        }
    }
    Ok(())
}

/// Reads the artifact a configuration pins, and decides what this node's
/// evidence lets it do.
///
/// The non-admitting evidence states are answers and not errors, which is
/// §4's rule rather than a leniency: a node whose artifact is absent, or is
/// not the pinned one, still owes every open contest a response, and
/// refusing to start is the one thing that guarantees the response is
/// never made. So missing and changed evidence turn admission off and
/// leave the node running. A pinned artifact produced by a different
/// executable is changed evidence too: measurements made by that binary
/// are not measurements of this one.
///
/// What *is* an error is the pinned file being unreadable as an artifact.
/// Its digest is compared before its contents are interpreted: bytes
/// that do not match the pin were never this node's evidence to grade,
/// however malformed they are. Once the bytes match, a malformed field
/// is a corruption of the exact artifact the operator pinned and is
/// named at startup, exactly as [`load_work_config`] names a
/// configuration field.
///
/// # Errors
///
/// A pinned file that does not parse, an unknown or missing field, a
/// digest or machine name that is not one, a label its sample count
/// contradicts, a running executable whose bytes cannot be read, and a
/// `poll_ms` slower than the artifact's four priced blocks.
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
    if Digest::hash(&bytes) != identity.digest {
        return Ok(PaidWorkDuties::Changed);
    }
    let file: ArtifactBodyFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse artifact {}", identity.path.display()))?;
    let artifact = file
        .into_artifact()
        .with_context(|| format!("invalid artifact {}", identity.path.display()))?;
    if artifact.provenance.binary != running_binary_digest()? {
        return Ok(PaidWorkDuties::Changed);
    }
    config.duties(artifact)
}

/// Identifies the executable whose paid-work duties are being loaded,
/// by the same bytes and hash the bootstrap probe records.
fn running_binary_digest() -> CliResult<Digest> {
    static DIGEST: OnceLock<Result<Digest, String>> = OnceLock::new();
    match DIGEST.get_or_init(|| {
        let result = || -> CliResult<Digest> {
            let path =
                std::env::current_exe().context("failed to locate the running executable")?;
            let bytes = fs::read(&path)
                .with_context(|| format!("failed to read running executable {}", path.display()))?;
            Ok(Digest::hash(&bytes))
        };
        result().map_err(|error| format!("{error:#}"))
    }) {
        Ok(digest) => Ok(*digest),
        Err(error) => Err(anyhow::anyhow!(error.clone())),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkConfigFile {
    chain: ChainFile,
    validators: Vec<String>,
    journal: JournalFile,
    routes: Vec<WorkRouteFile>,
    policies: PoliciesFile,
    /// How often the watcher asks the chain for the next block.
    poll_ms: u64,
    response_alarm_margin_blocks: u64,
    #[serde(default)]
    artifact: Option<ArtifactFile>,
    /// Demo-only escape hatch. It is intentionally long and alarming in the
    /// operator-owned file, and absent means false.
    #[serde(default)]
    unsafe_devnet_admit_assumed_measurements: bool,
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

        let journal_root = self.journal.into_root()?;
        let routes = WorkRoutes::from_files(self.routes)?;
        let policies = self.policies.into_policies()?;
        if self.poll_ms == 0 {
            bail!("poll_ms must be greater than zero");
        }
        if self.response_alarm_margin_blocks == 0 {
            bail!("response_alarm_margin_blocks must be greater than zero");
        }
        if self.unsafe_devnet_admit_assumed_measurements
            && network.as_str() != UNSAFE_ASSUMED_ADMISSION_NETWORK
        {
            bail!(
                "unsafe_devnet_admit_assumed_measurements may only be enabled for network_id \
                 {UNSAFE_ASSUMED_ADMISSION_NETWORK:?}; configured network is {:?}",
                network.as_str(),
            );
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
            journal_root,
            routes,
            policy_salt: policies.0,
            channel_policy: policies.1,
            execution_policy: policies.2,
            poll: Duration::from_millis(self.poll_ms),
            response_alarm_margin_blocks: self.response_alarm_margin_blocks,
            artifact: self.artifact.map(ArtifactFile::into_identity).transpose()?,
            unsafe_devnet_admit_assumed_measurements: self.unsafe_devnet_admit_assumed_measurements,
        })
    }
}

/// One bilateral route exactly as the operator writes it.
///
/// All three values are fixed-width lowercase-or-uppercase hexadecimal on
/// input and canonical byte values after loading. A peer or bond written in a
/// second spelling is therefore still the same key for duplicate detection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRouteFile {
    peer: String,
    bond: String,
    client: String,
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

/// Where the work journals live.
///
/// A root and nothing else. How large a journal may grow is not an
/// operator's to say: the active and checkpoint ceilings are constants
/// the journal enforces on itself, so a cap here would be a number
/// written down and ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    root: PathBuf,
}

impl JournalFile {
    fn into_root(self) -> CliResult<PathBuf> {
        if self.root.as_os_str().is_empty() {
            bail!("journal.root must be a path");
        }
        Ok(self.root)
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
        let salt = parse_fixed_hex("policies.policy_salt", &self.policy_salt)?;
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
/// Nothing here grades the number. The `64 >= T` floor is computed from
/// [`BudgetFile`]'s raw samples; this is the honest label it answers to.
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

/// One artifact, read and folded into the values a policy needs.
struct MeasuredArtifact {
    provenance: ArtifactProvenance,
    expected_payment_values: EdgeValues,
    /// §4's terms, reduced from the file's raw samples by this node.
    budget: MountBudget,
    evidence: Evidence,
    samples: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBodyFile {
    provenance: ProvenanceFile,
    expected_payment_values: PaymentValuesFile,
    budget: BudgetFile,
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

        // The run before its samples, because the run's window is what
        // every sample's own timestamp is checked against.
        let provenance = self.provenance.into_provenance()?;
        let (budget, budget_samples, budget_evidence) = self.budget.into_budget(&provenance)?;
        evidence = evidence.weakest(budget_evidence);
        samples = samples.min(budget_samples);
        if evidence == Evidence::Assumed {
            // §4's own accounting: an assumed field rests on no samples,
            // so an artifact carrying one reports none.
            samples = 0;
        }

        Ok(MeasuredArtifact {
            provenance,
            budget,
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
    started_at_unix_ms: u64,
    measured_at_unix_ms: u64,
}

impl ProvenanceFile {
    fn into_provenance(self) -> CliResult<ArtifactProvenance> {
        if self.machine.trim().is_empty() {
            bail!("provenance.machine must name a machine");
        }
        // The run's own window, checked for being one. A finish before
        // its start is a file assembled by hand or a clock that moved
        // under the run, and either way every timestamp inside it means
        // something other than what it says.
        if self.measured_at_unix_ms < self.started_at_unix_ms {
            bail!(
                "provenance.measured_at_unix_ms {} is before provenance.started_at_unix_ms {}",
                self.measured_at_unix_ms,
                self.started_at_unix_ms,
            );
        }
        Ok(ArtifactProvenance {
            binary: parse_digest("provenance.binary", &self.binary)?,
            config: parse_digest("provenance.config", &self.config)?,
            machine: self.machine,
            started_at_unix_ms: self.started_at_unix_ms,
            measured_at_unix_ms: self.measured_at_unix_ms,
        })
    }
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

/// Every §4 term the two waits are built from, as observations rather
/// than as answers.
///
/// One field per name in §4's two formulas, spelled exactly as §4 spells
/// it, plus the two the block counts divide and multiply by. Nothing is
/// optional and nothing defaults: a term left out of a bootstrap run is
/// a term the operator writes `assumed` and a node that admits no work,
/// which is a decision somebody made rather than a zero that quietly
/// made the floor smaller.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFile {
    fsync_tail_ms: BudgetTermFile,
    rotation_tail_ms: BudgetTermFile,
    response_build_ms: BudgetTermFile,
    one_block_fetch_ms: BudgetTermFile,
    fresh_tip_ms: BudgetTermFile,
    close_prepared_fsync_ms: BudgetTermFile,
    rpc_ms: BudgetTermFile,
    response_worker_ms: BudgetTermFile,
    general_worker_ms: BudgetTermFile,
    validation_ms: BudgetTermFile,
    restart_replay_ms_at_cap: BudgetTermFile,
    restart_downtime_ms: BudgetTermFile,
    lower_tail_block_ms: BudgetTermFile,
    general_inclusion_blocks: BudgetTermFile,
}

/// Which end of a term's observations is the conservative one.
///
/// Not a preference: every term of §4 enters the floor either as a
/// numerator, where longer is worse, or as the divisor
/// `lower_tail_block_ms`, where *shorter* is worse because a shorter
/// block buys less time per block. Naming the two ends here means the
/// reduction of each term is written down beside the term rather than
/// inferred from its units.
#[derive(Clone, Copy, Debug)]
enum Tail {
    /// The longest observation: every wait, and `Ig`.
    Longest,
    /// The shortest observation: `lower_tail_block_ms`, the one term a
    /// small value makes the floor larger.
    Shortest,
}

/// One §4 term: what the run saw, or what an operator wrote instead.
///
/// The same honesty rule [`MeasuredU64`] carries, in the shape a raw
/// sample set needs. `measured` means `samples` is non-empty and there
/// is no `value` to contradict them; `assumed` means a `value` and no
/// samples. There is no third shape, and in particular no way to write
/// down a number and a sample set that does not produce it: the reader
/// reduces the samples itself.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetTermFile {
    evidence: Evidence,
    #[serde(default)]
    value: Option<u64>,
    #[serde(default)]
    samples: Vec<RawSampleFile>,
}

/// One observation, as the seam emitted it and the collector timestamped
/// it.
///
/// Whole units, because §4's terms are whole milliseconds and blocks and
/// the probe rounds a duration up on the way in. The timestamp is what
/// makes this a sample of a run rather than a number in a list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSampleFile {
    at_unix_ms: u64,
    value: u64,
}

impl BudgetTermFile {
    /// The one number this term contributes, and how many observations
    /// it rests on.
    ///
    /// # Errors
    ///
    /// A label its samples contradict, in either direction, and an
    /// `assumed` term that names no value.
    fn reduce(&self, field: &str, tail: Tail, run: &ArtifactProvenance) -> CliResult<(u64, u64)> {
        for sample in &self.samples {
            // A sample stamped outside the run that claims it is not a
            // sample of that run. It is the previous artifact, or a
            // hand-edited file, or a clock that moved — and a floor
            // computed over one would be a floor for a machine nobody
            // named.
            if sample.at_unix_ms < run.started_at_unix_ms
                || sample.at_unix_ms > run.measured_at_unix_ms
            {
                bail!(
                    "budget.{field} carries a sample stamped {} outside the run's own \
                     {}..={} window",
                    sample.at_unix_ms,
                    run.started_at_unix_ms,
                    run.measured_at_unix_ms,
                );
            }
        }
        match (self.evidence, self.value, self.samples.len()) {
            (Evidence::Measured, _, 0) => {
                bail!("budget.{field} is labelled measured and rests on no samples")
            }
            (Evidence::Measured, Some(value), _) => bail!(
                "budget.{field} is labelled measured and writes {value} down beside its samples"
            ),
            (Evidence::Assumed, _, count) if count != 0 => {
                bail!("budget.{field} is labelled assumed and reports {count} samples")
            }
            (Evidence::Assumed, None, _) => {
                bail!("budget.{field} is labelled assumed and names no value")
            }
            (Evidence::Assumed, Some(value), _) => Ok((value, 0)),
            (Evidence::Measured, None, count) => {
                let values = self.samples.iter().map(|sample| sample.value);
                let reduced = match tail {
                    Tail::Longest => values.max(),
                    Tail::Shortest => values.min(),
                };
                let Some(reduced) = reduced else {
                    bail!("budget.{field} is labelled measured and rests on no samples")
                };
                Ok((reduced, count as u64))
            }
        }
    }
}

impl BudgetFile {
    /// Reduces every term to the number it contributes, and reports the
    /// weakest label and the fewest samples any of them rests on.
    ///
    /// The list is written out rather than derived for
    /// [`ArtifactBodyFile::into_artifact`]'s reason: a term added to
    /// [`MountBudget`] and left out here is a term that stops
    /// compiling, not a term whose samples are silently never read.
    ///
    /// # Errors
    ///
    /// Whatever [`BudgetTermFile::reduce`] raises, naming the term.
    fn into_budget(self, run: &ArtifactProvenance) -> CliResult<(MountBudget, u64, Evidence)> {
        let mut samples = u64::MAX;
        let mut evidence = Evidence::Measured;
        let mut term = |field: &str, entry: &BudgetTermFile, tail: Tail| -> CliResult<u64> {
            let (value, count) = entry.reduce(field, tail, run)?;
            samples = samples.min(count);
            evidence = evidence.weakest(entry.evidence);
            Ok(value)
        };
        let budget = MountBudget {
            fsync_tail_ms: term("fsync_tail_ms", &self.fsync_tail_ms, Tail::Longest)?,
            rotation_tail_ms: term("rotation_tail_ms", &self.rotation_tail_ms, Tail::Longest)?,
            response_build_ms: term("response_build_ms", &self.response_build_ms, Tail::Longest)?,
            one_block_fetch_ms: term(
                "one_block_fetch_ms",
                &self.one_block_fetch_ms,
                Tail::Longest,
            )?,
            fresh_tip_ms: term("fresh_tip_ms", &self.fresh_tip_ms, Tail::Longest)?,
            close_prepared_fsync_ms: term(
                "close_prepared_fsync_ms",
                &self.close_prepared_fsync_ms,
                Tail::Longest,
            )?,
            rpc_ms: term("rpc_ms", &self.rpc_ms, Tail::Longest)?,
            response_worker_ms: term(
                "response_worker_ms",
                &self.response_worker_ms,
                Tail::Longest,
            )?,
            general_worker_ms: term("general_worker_ms", &self.general_worker_ms, Tail::Longest)?,
            validation_ms: term("validation_ms", &self.validation_ms, Tail::Longest)?,
            restart_replay_ms_at_cap: term(
                "restart_replay_ms_at_cap",
                &self.restart_replay_ms_at_cap,
                Tail::Longest,
            )?,
            restart_downtime_ms: term(
                "restart_downtime_ms",
                &self.restart_downtime_ms,
                Tail::Longest,
            )?,
            // The one term whose conservative end is the small one.
            lower_tail_block_ms: term(
                "lower_tail_block_ms",
                &self.lower_tail_block_ms,
                Tail::Shortest,
            )?,
            general_inclusion_blocks: term(
                "general_inclusion_blocks",
                &self.general_inclusion_blocks,
                Tail::Longest,
            )?,
        };
        Ok((budget, samples, evidence))
    }
}

fn parse_hex(field: &str, raw: &str) -> CliResult<Vec<u8>> {
    let bytes = hex::decode(raw.trim()).with_context(|| format!("{field} is not hexadecimal"))?;
    if bytes.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(bytes)
}

fn parse_fixed_hex<const N: usize>(field: &str, raw: &str) -> CliResult<[u8; N]> {
    let bytes = parse_hex(field, raw)?;
    let Ok(bytes) = <[u8; N]>::try_from(bytes.as_slice()) else {
        bail!("{field} must be {N} bytes, found {}", bytes.len());
    };
    Ok(bytes)
}

fn parse_digest(field: &str, raw: &str) -> CliResult<Digest> {
    Ok(Digest::from_bytes(parse_fixed_hex(field, raw)?))
}

#[cfg(test)]
mod tests;
