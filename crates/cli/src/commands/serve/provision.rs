//! Making the one offer a fresh provider has nothing to serve without.
//!
//! `WorkRunner::discover` answers `WorkSetup` from the setup journals it
//! finds under the configured work root, and finding is the whole of what
//! it does. A correctly configured provider with no journal therefore
//! refuses every client that dials it, and the paid path is unreachable
//! from a clean install. This is the operator's step that writes one.
//!
//! # The order is the journal's, and none of its rules are here
//!
//! Three library calls. [`SetupStore`] is opened as the provider's half
//! of one bond, the immutable history floor is armed, and
//! [`SetupEndpoint::propose_bond`] signs the stake and journals it before
//! there is anything to export.
//!
//! Arming is first because it has to be: the setup state refuses
//! "recording revision 1 before arming its scan floor", so the floor is
//! not a preparation this command chose to do early but the step every
//! later one is refused before. The floor is a finalized height and the
//! payload digest at it, and the setup's own history must name that
//! digest as the parent of its first block. So it is read from a
//! validator rather than written down by an operator: a floor naming a
//! block this chain does not have is a setup whose history can never be
//! contiguous, and nothing later would say so out loud.
//!
//! # Exit means durable
//!
//! [`SetupStore::commit`] fsyncs a revision before it returns, and this
//! command still reopens the journal and replays it before printing
//! anything. That reopen is the one `WorkRunner::discover` will do, run
//! early: an operator told the offer exists has been told about the disk,
//! and about a file whose exclusive lock is already free for the runner
//! to take.
//!
//! # One root holds one offer
//!
//! `WorkSetup`'s first request carries no selector, so a node serves an
//! offer only when exactly one provider journal is discovered, and
//! deliberately serves none when there are several. Writing a second
//! offer under a root that already holds one would turn a node that
//! answers into a node that refuses. The refusal below is that same
//! count, taken from the same `discover_setups`, asked before the second
//! file exists rather than after.
//!
//! # Evidence gates the countersignature, not the journal
//!
//! §4's evidence rule is spelled once, in [`PaidWorkDuties`], and it is a
//! rule about a signature: an assumed artifact yields
//! [`PaymentAdmission::Proposes`], which declines every payment a client
//! proposes, and the identical policy under a measured artifact yields
//! `Admits`. This command does not ask that question a second time. It
//! refuses only where there is no policy at all — no artifact
//! configured, none found, one that is not the pinned one, or one the
//! measured floor refuses — because there is then no endpoint to build,
//! and [`super::work_config`] has already said that a policy invented to
//! fill that gap would be exactly the measurement this node does not
//! have.
//!
//! Provisioning under an assumed artifact is therefore allowed, and the
//! reason is that the journal outlives the artifact. Nothing in a setup
//! journal records which evidence case wrote it, so the same revision 1
//! is served — and admitted — by a restart under a measured one. A
//! provisioning-time evidence gate would be a permanent refusal decided
//! from a fact that changes at every startup, and it would deadlock the
//! deployment it was meant to protect: eleven of §4's fourteen terms need
//! a funded channel with an open contest on a live chain ([`super::probe`]),
//! and a funded channel needs an offer for a client to answer.
//!
//! # What the operator chooses, and what is built
//!
//! Every number in the bond is the operator's and this command invents
//! none of them. Two parts of the shape are not choices: a stake bond is
//! funded by its maker alone, so the taker's side of the funding is
//! empty, and its timeout pays the staking party and nobody else, so
//! there is one payout and it names the provider's own key. A second
//! payout to that same party would only raise the close cost the payout
//! has to clear. The kernel checks the rest when the Open reaches it —
//! that the payout total is the edge's close value, that the price cap
//! covers a job, that the timeout is ahead of the block including it —
//! and re-spelling any of that here would be a second answer to a
//! question consensus already answers.
//!
//! [`PaidWorkDuties`]: super::work_config::PaidWorkDuties

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::{ConsensusInfo, ConsensusVerifier, WorkBlocks};
use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, NetworkId,
    Parties, Payout, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkStakeBondTerms,
};
use hellas_rpc::work_close::FinalizedBlocks;
use hellas_rpc::work_handshake::{PaymentAdmission, SetupEndpoint};
use hellas_rpc::work_store::{Role, SetupScan, SetupStore, discover_setups};
use tracing::{info, warn};

use super::work_config::{PaidWorkDuties, WorkConfig, load_paid_work_duties};
use crate::commands::CliResult;

/// What an operator asks for when they make their one offer.
pub struct ProvisionOptions {
    /// The loaded paid-work configuration, not the path it came from. It
    /// carries the network the bond is bound to, the root the journal is
    /// written under, the validators the floor is read from, and the
    /// artifact the provider's policy rests on.
    pub work_config: WorkConfig,
    /// The key this provider stakes and signs the bond with, read from
    /// the identity the operator already has and never made here.
    pub settlement_key: Secp256k1Signer,
    /// The client this bond names as taker, hex-encoded.
    pub client: String,
    /// The coins this provider stakes, hex-encoded.
    pub stake_coins: Vec<String>,
    /// Height the bond expires at, which is also the admission horizon of
    /// the channel it insures.
    pub bond_timeout: u64,
    /// What the bond's timeout returns to the staking provider.
    pub timeout_payout: u64,
    /// The largest job price this bond covers.
    pub max_job_price: u64,
}

/// Makes one offer, and says where it is.
///
/// # Errors
///
/// A configuration that builds no provider policy, a root that already
/// holds a provider offer, a key or coin id that is not one, no
/// configured validator with a finalized block to read a floor from, and
/// whatever the setup journal says about the revision it refused or could
/// not make durable.
pub async fn run_provision(options: ProvisionOptions) -> CliResult<()> {
    let duties = load_paid_work_duties(&options.work_config)?;
    let offer = Offer::plan(&options, &duties)?;
    // Dialled after every refusal that can be made without a chain, and
    // before the journal exists: a floor is the first thing written into
    // it, so a run that cannot read one leaves no half-made offer behind.
    let made = offer.journal(finalized_floor(&options.work_config).await?)?;

    println!(
        "offer journaled: bond {} under {}",
        hex::encode(made.bond_edge.to_bytes()),
        options.work_config.journal_root.display(),
    );
    // The floor read back out of the journal rather than the one just
    // dialled, because those differ on a retry and the durable one is the
    // one this setup's history will be measured against.
    println!(
        "history floor: finalized height {} with payload {}",
        made.floor.height,
        hex::encode(made.floor.payload),
    );
    // Said back because it decides what a client that answers this offer
    // will be told: the same revision 1 is served either way, and only a
    // measured artifact countersigns the payment proposed over it.
    println!("{}", duties.summary());
    Ok(())
}

/// One offer as the disk holds it, read back after it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Provisioned {
    /// The bond this journal is keyed to, which is what discovery names
    /// it by.
    bond_edge: EdgeId,
    /// The floor its history starts above, as retained.
    floor: SetupScan,
}

/// One offer, decided before anything is dialled or written.
struct Offer {
    network: NetworkId,
    journal_root: PathBuf,
    bond_edge: EdgeId,
    bond_funding: Funding,
    bond_terms: WorkStakeBondTerms,
    admission: PaymentAdmission,
    settlement_key: Secp256k1Signer,
}

impl Offer {
    /// Reads the operator's answers, and refuses everything refusable
    /// without a chain.
    fn plan(options: &ProvisionOptions, duties: &PaidWorkDuties) -> CliResult<Self> {
        let Some(admission) = duties.payment_admission() else {
            bail!(
                "this configuration builds no provider policy, so it has no offer to make: {}",
                duties.summary(),
            );
        };
        let network = options.work_config.chain.network;
        let journal_root = options.work_config.journal_root.clone();
        refuse_a_second_offer(&journal_root, network)?;

        // Maker is the provider and taker is the client, which is what
        // makes this signature the maker's: `propose_bond` refuses a bond
        // whose staking party this key is not.
        let provider = options.settlement_key.party_key();
        let bond_terms = WorkStakeBondTerms {
            parties: Parties::new(
                provider,
                Key::from_bytes(fixed::<{ Key::LENGTH }>("--client", &options.client)?),
            ),
            timeout: BlockHeight::new(options.bond_timeout),
            timeout_outputs: List::take(
                [Payout::new(provider, options.timeout_payout); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: options.max_job_price,
        };
        let bond_funding = Funding::new(
            staked(&options.stake_coins)?,
            List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
        );
        let bond_edge = Tx::edge_id_of(&bond_funding, &Terms::work_stake_bond(bond_terms.clone()));
        Ok(Self {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            admission,
            settlement_key: options.settlement_key.clone(),
        })
    }

    /// Journals revision 1, and returns only once a fresh open of the
    /// journal replays it.
    fn journal(self, floor: SetupScan) -> CliResult<Provisioned> {
        let Self {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            admission,
            settlement_key,
        } = self;
        {
            let store = open_provider_journal(&journal_root, network, bond_edge)?;
            let mut endpoint = SetupEndpoint::new(store, settlement_key, admission);
            // The floor is immutable and the store writes exactly one arm
            // of it, so a run that arms and then fails keeps the height
            // its successor starts from rather than moving it.
            if let Some(held) = endpoint.state().scan_armed() {
                info!(
                    height = held.height,
                    "this journal already holds its history floor, and a floor does not move",
                );
            } else {
                endpoint
                    .arm_scan(floor)
                    .context("failed to make this setup's immutable history floor durable")?;
            }
            endpoint
                .propose_bond(network, bond_funding, bond_terms)
                .context("failed to sign and journal the bond proposal")?;
        }

        // The journal is closed above, so this is a second process's view
        // of it: the same replay and the same signature checks the runner
        // runs, before an operator is told there is anything to run them
        // on.
        let reopened = open_provider_journal(&journal_root, network, bond_edge)?;
        let state = reopened.state();
        let (Some(1), Some(floor)) = (state.revision(), state.scan_armed()) else {
            bail!(
                "the journal under {} replays as revision {:?} over floor {:?}, not the armed \
                 proposal that was just written",
                journal_root.display(),
                state.revision(),
                state.scan_armed().map(|scan| scan.height),
            );
        };
        Ok(Provisioned { bond_edge, floor })
    }
}

fn open_provider_journal(
    root: &Path,
    network: NetworkId,
    bond_edge: EdgeId,
) -> CliResult<SetupStore> {
    SetupStore::open(
        root,
        network,
        bond_edge,
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .with_context(|| {
        format!(
            "failed to open the provider setup journal for bond {} under {}",
            hex::encode(bond_edge.to_bytes()),
            root.display(),
        )
    })
}

/// Refuses to write a second offer under one root.
///
/// The count is the runner's own: it serves `WorkSetup` when exactly one
/// provider journal is discovered and serves none when there are
/// several, so a second offer here is a node that stops answering. A
/// journal that cannot be named is reported and not counted, exactly as
/// the runner reports it: it holds no revision, so there is no offer in
/// it.
fn refuse_a_second_offer(root: &Path, network: NetworkId) -> CliResult<()> {
    let found = discover_setups(root, network).with_context(|| {
        format!(
            "failed to enumerate the work journals under {}",
            root.display(),
        )
    })?;
    for unnamed in &found.unidentified {
        warn!(
            path = %unnamed.path.display(),
            reason = %unnamed.reason,
            "a setup journal under the work root could not be named",
        );
    }
    let Some(held) = found
        .setups
        .iter()
        .find(|setup| setup.role == Role::Provider)
    else {
        return Ok(());
    };
    bail!(
        "{} already holds a provider setup journal, over bond {}: a node serves WorkSetup only \
         from exactly one, so a second offer under this root would leave it serving none",
        root.display(),
        hex::encode(held.bond_edge.to_bytes()),
    );
}

/// Reads one finalized block from the first configured validator that
/// answers, as the floor this setup's history starts above.
async fn finalized_floor(config: &WorkConfig) -> CliResult<SetupScan> {
    let verifier = ConsensusVerifier::new(&ConsensusInfo {
        validators: config.validators.clone(),
        threshold_identity: config.chain.threshold_identity.clone(),
        network_id: config.chain.network.as_str().to_owned(),
    })
    .context("the configured threshold identity is not usable")?;
    for url in &config.validators {
        let client = match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => client,
            Err(error) => {
                warn!(validator = %url, %error, "a configured validator did not answer");
                continue;
            }
        };
        match floor_of(&WorkBlocks::new(client)).await {
            Ok(Some(floor)) => {
                info!(validator = %url, height = floor.height, "the history floor was read here");
                return Ok(floor);
            }
            Ok(None) => warn!(validator = %url, "a configured validator has finalized nothing"),
            Err(error) => warn!(validator = %url, %error, "a configured validator did not answer"),
        }
    }
    bail!("no configured validator answered with a finalized block to floor this offer at")
}

/// Returns the finalized tip as a scan floor, or `None` before anything
/// is finalized.
///
/// The height and the payload come from one block rather than from two
/// reads, because the setup's first history block must name that exact
/// payload as its parent.
async fn floor_of<B>(blocks: &B) -> CliResult<Option<SetupScan>>
where
    B: FinalizedBlocks + ?Sized,
{
    let Some(height) = blocks.latest_height().await? else {
        return Ok(None);
    };
    let Some(block) = blocks.block_at(height).await? else {
        return Ok(None);
    };
    Ok(Some(SetupScan {
        height: block.height,
        payload: block.payload,
    }))
}

/// Reads the coins one provider stakes.
fn staked(ids: &[String]) -> CliResult<List<CoinId, MAX_PARTY_INPUTS>> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes(fixed::<{ CoinId::LENGTH }>("--stake-coin", id)?);
    }
    // The zip above stops at the shorter side, so a list the array cannot
    // hold is refused here rather than silently staking the first four of
    // it.
    List::new(slots, ids.len()).with_context(|| {
        format!(
            "--stake-coin names {} coins, and one party funds an open with at most \
             {MAX_PARTY_INPUTS}",
            ids.len(),
        )
    })
}

/// Reads exactly `N` bytes of hex, or says which flag was not that.
fn fixed<const N: usize>(flag: &str, value: &str) -> CliResult<[u8; N]> {
    let bytes =
        hex::decode(value).with_context(|| format!("{flag} {value:?} is not hex-encoded bytes"))?;
    let Ok(fixed) = <[u8; N]>::try_from(bytes.as_slice()) else {
        bail!(
            "{flag} {value:?} is {} bytes, and {N} are wanted",
            bytes.len()
        );
    };
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hellas_kernel::{EdgeValues, Fees, MIN_OMIT_RESPONSE_BLOCKS};
    use hellas_rpc::protocol::Digest;
    use hellas_rpc::protocol::mount::{FloorError, MountBudget};
    use hellas_rpc::protocol::work::{PaidChannelPolicyV1, PaidExecutionPolicyV1};
    use hellas_rpc::protocol::work_setup::{OmissionMeasurements, ProviderChannelPolicy};
    use hellas_rpc::work_close::{BlockSourceError, FinalizedWork};

    use super::super::work_config::{ArtifactProvenance, ChainCrossCheck, MeasuredEvidence};
    use super::*;

    fn network() -> NetworkId {
        let Some(network) = NetworkId::new("hellas-devnet") else {
            panic!("the fixture network id is one");
        };
        network
    }

    fn signer(byte: u8) -> Secp256k1Signer {
        let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
            panic!("a fixed scalar is a key");
        };
        signer
    }

    /// The provider whose identity this offer is staked by.
    fn provider() -> Secp256k1Signer {
        signer(0x22)
    }

    /// The client the bond names as taker.
    fn client() -> Secp256k1Signer {
        signer(0x21)
    }

    /// The floor a validator answered with.
    fn floor() -> SetupScan {
        SetupScan {
            height: 7,
            payload: [0x47; 32],
        }
    }

    /// A budget whose §4 floor is computable, so a policy can be made
    /// over it. The numbers are the tails of the work-config fixture's
    /// own samples: a deployment with an SSD and a half-second block.
    fn budget() -> MountBudget {
        MountBudget {
            fsync_tail_ms: 5,
            rotation_tail_ms: 12,
            response_build_ms: 4,
            one_block_fetch_ms: 25,
            fresh_tip_ms: 14,
            close_prepared_fsync_ms: 6,
            rpc_ms: 44,
            response_worker_ms: 9,
            general_worker_ms: 8,
            validation_ms: 3,
            restart_replay_ms_at_cap: 520,
            restart_downtime_ms: 900,
            lower_tail_block_ms: 480,
            general_inclusion_blocks: 3,
        }
    }

    fn policy() -> ProviderChannelPolicy {
        let Ok(environment) = hex::encode([0x11; 32]).parse() else {
            panic!("the fixture environment id is one");
        };
        ProviderChannelPolicy {
            network: network(),
            policy_salt: [0x5a; 32],
            channel_policy: PaidChannelPolicyV1 {
                compute_credit_limit: 40,
                delivery_credit_limit: 40,
            },
            execution_policy: PaidExecutionPolicyV1 {
                allowed_environment: environment,
                generation_policy_digest: Digest::from_bytes([0x12; 32]),
                identity_source_digest: Digest::from_bytes([0x13; 32]),
                max_prompt_tokens: 512,
                max_new_tokens: 128,
                max_stop_token_ids: 4,
                max_spool_bytes: 1 << 20,
                max_encoded_result_frame: 262_144,
                max_encoded_quote_response: 1 << 20,
                dispatch_margin_blocks: 4,
                delivery_margin_blocks: 2,
                oracle_grace_blocks: 6,
                fixed_price: 10,
            },
            expected_payment_values: EdgeValues::new(1_000, 200, Fees::new(0, 0, 0, 0)),
            omission: OmissionMeasurements {
                response_probability: 999_000,
                response_blocks: MIN_OMIT_RESPONSE_BLOCKS + 4,
                response_cost_cap: 1,
            },
            floor: match budget().floor() {
                Ok(floor) => floor,
                Err(error) => panic!("the fixture budget has a floor: {error}"),
            },
        }
    }

    /// The evidence both labels carry. Identical either way, which is
    /// what the labels are about: only what may be countersigned moves.
    fn evidence() -> Box<MeasuredEvidence> {
        Box::new(MeasuredEvidence {
            provenance: ArtifactProvenance {
                binary: Digest::from_bytes([0x21; 32]),
                config: Digest::from_bytes([0x22; 32]),
                machine: "bootstrap-1".to_string(),
                started_at_unix_ms: 1_756_339_000_000,
                measured_at_unix_ms: 1_756_339_200_000,
            },
            samples: 2,
            floor: policy().floor,
            policy: policy(),
        })
    }

    fn admits() -> PaidWorkDuties {
        PaidWorkDuties::Admits(evidence())
    }

    fn assumed() -> PaidWorkDuties {
        PaidWorkDuties::Assumed(evidence())
    }

    /// A configuration whose journal root is `root` and which names no
    /// artifact, because the duties are handed in separately: this is
    /// what the offer is written under, not what it is graded by.
    fn work_config(root: &Path) -> WorkConfig {
        WorkConfig {
            chain: ChainCrossCheck {
                network: network(),
                genesis_payload_digest: Digest::from_bytes([0x01; 32]),
                threshold_identity: Vec::new(),
            },
            validators: Vec::new(),
            journal_root: root.to_path_buf(),
            policy_salt: [0x5a; 32],
            channel_policy: policy().channel_policy,
            execution_policy: policy().execution_policy,
            poll: Duration::from_millis(250),
            response_alarm_margin_blocks: 16,
            artifact: None,
        }
    }

    fn options(root: &Path, max_job_price: u64) -> ProvisionOptions {
        ProvisionOptions {
            work_config: work_config(root),
            settlement_key: provider(),
            client: hex::encode(client().party_key().to_bytes()),
            stake_coins: vec![hex::encode([0xa1; 32])],
            bond_timeout: 500,
            timeout_payout: 64,
            max_job_price,
        }
    }

    /// The whole command, minus the one step that needs a validator.
    fn provision(
        root: &Path,
        duties: &PaidWorkDuties,
        max_job_price: u64,
    ) -> CliResult<Provisioned> {
        Offer::plan(&options(root, max_job_price), duties)?.journal(floor())
    }

    /// The bond the fixture inputs name, spelled out here rather than
    /// taken from the command: the parties are positional, so a maker
    /// and taker the other way round is a different edge and this
    /// notices.
    fn expected_bond(max_job_price: u64) -> EdgeId {
        let funding = Funding::new(
            List::take([CoinId::from_bytes([0xa1; 32]); MAX_PARTY_INPUTS], 1),
            List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
        );
        let terms = WorkStakeBondTerms {
            parties: Parties::new(provider().party_key(), client().party_key()),
            timeout: BlockHeight::new(500),
            timeout_outputs: List::take(
                [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price,
        };
        Tx::edge_id_of(&funding, &Terms::work_stake_bond(terms))
    }

    fn provider_setups(root: &Path) -> usize {
        let Ok(found) = discover_setups(root, network()) else {
            panic!("the fixture root enumerates");
        };
        assert!(
            found.unidentified.is_empty(),
            "a journal under the root could not be named: {:?}",
            found.unidentified,
        );
        found
            .setups
            .iter()
            .filter(|setup| setup.role == Role::Provider)
            .count()
    }

    /// A provisioned root is an offer the runner finds: the journal names
    /// the bond and the role `WorkRunner::discover` looks for, and the
    /// revision under them is the proposal.
    #[test]
    fn a_provisioned_root_is_the_offer_a_runner_discovers() {
        let dir = tempfile::tempdir().unwrap();
        let Ok(made) = provision(dir.path(), &admits(), 40) else {
            panic!("a configured provider makes its offer");
        };
        assert_eq!(made.bond_edge, expected_bond(40));
        assert_eq!(made.floor, floor());

        let Ok(found) = discover_setups(dir.path(), network()) else {
            panic!("the provisioned root enumerates");
        };
        assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
        let [discovered] = found.setups.as_slice() else {
            panic!("one offer was made, one is found: {:?}", found.setups);
        };
        assert_eq!(discovered.bond_edge, made.bond_edge);
        assert_eq!(discovered.role, Role::Provider);

        // Reopened by bond and role alone, which is all the runner is
        // told. The open re-verifies every signature the revision
        // carries, so a proposal staked by some other party would not
        // survive this line.
        let Ok(store) = open_provider_journal(dir.path(), network(), discovered.bond_edge) else {
            panic!("the discovered journal reopens");
        };
        let Some(bundle) = store.state().bundle() else {
            panic!("a discovered offer holds the revision it was discovered by");
        };
        assert_eq!(bundle.revision(), 1);
        assert_eq!(bundle.network(), network());
        assert_eq!(bundle.bond_edge(), made.bond_edge);
        assert_eq!(store.state().scan_armed(), Some(floor()));
    }

    /// A root that already holds an offer takes no second one, and the
    /// refusal says what a second would cost.
    #[test]
    fn a_second_offer_under_one_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let Ok(first) = provision(dir.path(), &admits(), 40) else {
            panic!("the first offer is made");
        };

        // A different bond, so this is the root being full rather than
        // the journal recognising bytes it already holds.
        let Err(error) = provision(dir.path(), &admits(), 41) else {
            panic!("a root that holds an offer takes no second one");
        };

        let said = format!("{error:#}");
        assert!(
            said.contains(&hex::encode(first.bond_edge.to_bytes())),
            "the refusal does not name the offer already held: {said}",
        );
        assert!(
            said.contains("serving none"),
            "the refusal does not say what a second offer costs: {said}",
        );
        // The count `WorkRunner::discover` takes is what the rule is
        // about, so it is the count this asserts: a refusal that left a
        // second journal behind would have done the thing it refused.
        assert_eq!(provider_setups(dir.path()), 1);
    }

    /// Success is a statement about the disk. The journal is closed
    /// before this reads it, so this open is the one a restarted runner
    /// makes, and it takes the exclusive lock the writer would still
    /// hold.
    #[test]
    fn the_offer_is_on_the_disk_before_the_command_returns() {
        let dir = tempfile::tempdir().unwrap();
        let Ok(made) = provision(dir.path(), &admits(), 40) else {
            panic!("the offer is made");
        };

        let Ok(store) = open_provider_journal(dir.path(), network(), made.bond_edge) else {
            panic!("the journal reopens");
        };
        assert_eq!(store.state().revision(), Some(1));
        assert!(
            !store.recovered_torn_tail(),
            "the offer this command reported was an interrupted write",
        );
        assert_eq!(
            store.len(),
            2,
            "the armed floor and the revision are both frames in the file",
        );
    }

    /// §4's evidence rule is about a countersignature, and this is not
    /// one. An unmeasured provider journals the same offer, byte for
    /// byte, that a measured one journals — which is why an artifact
    /// measured later serves this very revision instead of needing a new
    /// one.
    #[test]
    fn an_unmeasured_provider_makes_the_offer_a_measured_one_would() {
        let measured_root = tempfile::tempdir().unwrap();
        let assumed_root = tempfile::tempdir().unwrap();

        let Ok(measured) = provision(measured_root.path(), &admits(), 40) else {
            panic!("a measured provider makes its offer");
        };
        let Ok(assumed) = provision(assumed_root.path(), &assumed(), 40) else {
            panic!("an unmeasured provider still makes its offer");
        };
        assert_eq!(assumed, measured);

        let (Ok(measured_store), Ok(assumed_store)) = (
            open_provider_journal(measured_root.path(), network(), measured.bond_edge),
            open_provider_journal(assumed_root.path(), network(), assumed.bond_edge),
        ) else {
            panic!("both journals reopen");
        };
        assert_eq!(
            measured_store.state().bundle_bytes(),
            assumed_store.state().bundle_bytes(),
            "the journal records which bond was staked, never which artifact was read",
        );
    }

    /// No policy is no endpoint, so there is nothing to make an offer
    /// with — and the refusal names which of §4's cases produced it.
    #[test]
    fn a_provider_with_no_policy_has_no_offer_to_make() {
        for duties in [
            PaidWorkDuties::NotConfigured,
            PaidWorkDuties::NotFound,
            PaidWorkDuties::Changed,
            PaidWorkDuties::Refused(FloorError::NoLowerTail),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let Err(error) = provision(dir.path(), &duties, 40) else {
                panic!("a node with no policy has no offer: {duties:?}");
            };

            let said = format!("{error:#}");
            assert!(
                said.contains("no offer to make"),
                "unexpected refusal for {duties:?}: {said}",
            );
            assert!(
                said.contains(&duties.summary()),
                "the refusal does not name the evidence case: {said}",
            );
            assert_eq!(provider_setups(dir.path()), 0, "a refusal wrote a journal");
        }
    }

    /// A stake no open could carry is refused rather than quietly cut
    /// down to the four coins a party may fund with.
    #[test]
    fn a_stake_wider_than_an_open_is_refused_rather_than_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path(), 40);
        options.stake_coins = (0..=u8::try_from(MAX_PARTY_INPUTS).unwrap())
            .map(|byte| hex::encode([byte; 32]))
            .collect();

        let Err(error) = Offer::plan(&options, &admits()) else {
            panic!("an open funded by five coins is not one this stake can be");
        };
        assert!(
            format!("{error:#}").contains("at most 4"),
            "the refusal does not name the bound: {error:#}",
        );
    }

    /// One block answers both halves of a floor. A payload taken from
    /// any block but the one at the tip is a history that can never be
    /// contiguous, and nothing later would say so.
    #[tokio::test]
    async fn the_floor_is_the_payload_of_the_block_at_the_tip() {
        let source = Chain {
            tip: Some(9),
            block: Some(FinalizedWork {
                height: 9,
                parent: [0x08; 32],
                payload: [0x09; 32],
                txs: Vec::new(),
            }),
        };

        let Ok(read) = floor_of(&source).await else {
            panic!("a finalized chain answers with a floor");
        };
        assert_eq!(
            read,
            Some(SetupScan {
                height: 9,
                payload: [0x09; 32],
            }),
        );

        let empty = Chain {
            tip: None,
            block: None,
        };
        let Ok(read) = floor_of(&empty).await else {
            panic!("a chain that has finalized nothing is an answer, not a failure");
        };
        assert_eq!(read, None);
    }

    /// A chain holding at most one finalized block.
    struct Chain {
        tip: Option<u64>,
        block: Option<FinalizedWork>,
    }

    impl FinalizedBlocks for Chain {
        fn latest_height(
            &self,
        ) -> impl core::future::Future<Output = Result<Option<u64>, BlockSourceError>> + Send
        {
            core::future::ready(Ok(self.tip))
        }

        fn block_at(
            &self,
            height: u64,
        ) -> impl core::future::Future<Output = Result<Option<FinalizedWork>, BlockSourceError>> + Send
        {
            core::future::ready(Ok(self
                .block
                .clone()
                .filter(|block| block.height == height)))
        }
    }
}
