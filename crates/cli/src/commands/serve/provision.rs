//! Making the offers a fresh provider has nothing to serve without.
//!
//! `WorkRunner::discover` answers `WorkSetup` from the setup journals it
//! finds under the configured work root, and finding is the whole of what
//! it does. A correctly configured provider with no journal therefore
//! refuses every client that dials it, and the paid path is unreachable
//! from a clean install. This is the operator's step that writes them.
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
//! # One recourse backs one route
//!
//! A provider offer reserves a route, a bond, and every coin funding that
//! bond. A second offer is safe only when all three are disjoint from every
//! provider offer already under the root. Existing peers come from the
//! durable route table, while existing coins come from the bond funding in
//! each retained setup bundle. Revision one is enough: it holds the funding
//! before a client has answered, while [`SetupState::funding_coins`] is still
//! empty because there is no executable Open yet.
//!
//! Discovery, route agreement, and funding comparison all happen while the
//! candidate is only a value. The candidate journal is not opened until
//! afterwards, so every collision is refused before a floor is written or a
//! bond signature is made.
//!
//! # Evidence gates the countersignature, not the journal
//!
//! §4's evidence rule is spelled once, in [`PaidWorkDuties`], and it is a
//! rule about a signature: an assumed artifact normally yields
//! [`PaymentAdmission::Proposes`], which declines every payment a client
//! proposes, and the identical policy under a measured artifact yields
//! `Admits`. The one exception is the explicitly unsafe, exact-network
//! devnet switch: it yields `Admits` from assumed evidence and remains named
//! as unsafe in [`PaidWorkDuties`]. This command does not ask that question a second time. It
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
//! [`SetupState::funding_coins`]: hellas_rpc::work_store::SetupState::funding_coins

use std::collections::BTreeSet;
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

use super::work_config::{PaidWorkDuties, WorkConfig, WorkRoute, load_paid_work_duties};
use crate::commands::CliResult;

/// What an operator asks for when they make one offer.
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
/// A configuration that builds no provider policy or no matching bilateral
/// route, a route, bond, or funding coin already reserved by another offer,
/// a key or coin id that is not one, no configured validator with a finalized
/// block to read a floor from, and whatever the setup journal says about the
/// revision it refused or could not make durable.
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
        let route = route_for_candidate(&options.work_config, bond_edge, &bond_terms)?;
        refuse_offer_collisions(&options.work_config, route, &bond_funding)?;
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

/// Returns the configured bilateral route the candidate would occupy.
///
/// The bond is derived from the exact funding and terms first. Matching by
/// that canonical value means a route cannot be selected by insertion order,
/// and checking the client here refuses a journal the next startup would
/// reject before the provider signs it.
fn route_for_candidate<'config>(
    config: &'config WorkConfig,
    bond_edge: EdgeId,
    bond_terms: &WorkStakeBondTerms,
) -> CliResult<&'config WorkRoute> {
    let Some(route) = config.routes.iter().find(|route| route.bond == bond_edge) else {
        bail!(
            "bond {} has no bilateral route in this work configuration; an offer is signed only \
             after its peer, bond, and client are named together",
            hex::encode(bond_edge.to_bytes()),
        );
    };
    let client = bond_terms.parties.taker();
    if route.client != client {
        bail!(
            "route for peer {:#} expects client {}, but candidate bond {} names {} as its taker",
            route.peer,
            hex::encode(route.client.to_bytes()),
            hex::encode(bond_edge.to_bytes()),
            hex::encode(client.to_bytes()),
        );
    }
    Ok(route)
}

/// Refuses every collision before the candidate journal is opened.
///
/// An existing bond is named by discovery, its peer is named by the durable
/// route table, and its funding is named by the retained bundle. Failure to
/// recover any one of those facts is a refusal: absence of evidence is not
/// evidence that the candidate is disjoint.
fn refuse_offer_collisions(
    config: &WorkConfig,
    candidate: &WorkRoute,
    candidate_funding: &Funding,
) -> CliResult<()> {
    let root = &config.journal_root;
    let network = config.chain.network;
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
    if let Some(unnamed) = found.unidentified.first() {
        bail!(
            "setup journal {} cannot be identified, so a new offer cannot be proved disjoint: {}",
            unnamed.path.display(),
            unnamed.reason,
        );
    }

    let candidate_coins = funding_coins(candidate_funding);
    for held in found
        .setups
        .iter()
        .filter(|setup| setup.role == Role::Provider)
    {
        if held.bond_edge == candidate.bond {
            bail!(
                "candidate bond {} collides with a provider offer already under {}",
                hex::encode(candidate.bond.to_bytes()),
                root.display(),
            );
        }
        let Some(route) = config
            .routes
            .iter()
            .find(|route| route.bond == held.bond_edge)
        else {
            bail!(
                "provider offer over bond {} under {} has no configured route, so the candidate \
                 route cannot be proved disjoint",
                hex::encode(held.bond_edge.to_bytes()),
                root.display(),
            );
        };
        let store = open_provider_journal(root, network, held.bond_edge)?;
        let Some(bundle) = store.state().bundle() else {
            bail!(
                "provider offer over bond {} was discovered without a retained revision",
                hex::encode(held.bond_edge.to_bytes()),
            );
        };
        let held_client = bundle.bond_terms().parties.taker();
        if route.client != held_client {
            bail!(
                "route for peer {:#} expects client {}, but provider offer over bond {} names {} \
                 as its taker",
                route.peer,
                hex::encode(route.client.to_bytes()),
                hex::encode(held.bond_edge.to_bytes()),
                hex::encode(held_client.to_bytes()),
            );
        }
        if route.peer == candidate.peer {
            bail!(
                "candidate route peer {:#} collides with the provider offer over bond {}",
                candidate.peer,
                hex::encode(held.bond_edge.to_bytes()),
            );
        }
        // The retained revision's own staked funding, not the executable
        // Opens: the provider signed these coins when it made the offer, so
        // they are promised from that moment, while `funding_coins` answers
        // from Opens that do not exist until the client countersigns. Read
        // from there, every offer no client has answered would look like it
        // reserved nothing.
        let reserved = funding_coins(bundle.bond_funding());
        if let Some(coin) = candidate_coins.intersection(&reserved).next() {
            bail!(
                "candidate stake coin {} is already reserved by provider offer over bond {}",
                hex::encode(coin.to_bytes()),
                hex::encode(held.bond_edge.to_bytes()),
            );
        }
    }
    Ok(())
}

/// Every input one bond funding consumes, irrespective of party position.
fn funding_coins(funding: &Funding) -> BTreeSet<CoinId> {
    funding
        .maker()
        .iter()
        .chain(funding.taker().iter())
        .copied()
        .collect()
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
    use std::fs;

    use hellas_kernel::{EdgeValues, Fees, MIN_OMIT_RESPONSE_BLOCKS};
    use hellas_rpc::protocol::Digest;
    use hellas_rpc::protocol::mount::{FloorError, MountBudget};
    use hellas_rpc::protocol::work::{PaidChannelPolicyV1, PaidExecutionPolicyV1};
    use hellas_rpc::protocol::work_setup::{OmissionMeasurements, ProviderChannelPolicy};
    use hellas_rpc::work_close::{BlockSourceError, FinalizedWork};

    use super::super::work_config::{ArtifactProvenance, MeasuredEvidence, load_work_config};
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

    /// A threshold identity the real work-config loader accepts.
    const THRESHOLD_IDENTITY: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ];

    fn route(peer: u8, bond: EdgeId, client: Key) -> serde_json::Value {
        serde_json::json!({
            "peer": hex::encode([peer; 32]),
            "bond": hex::encode(bond.to_bytes()),
            "client": hex::encode(client.to_bytes()),
        })
    }

    /// Loads routes through the production parser, so their duplicate-peer
    /// and duplicate-bond invariants are facts these provisioning tests use,
    /// not a test-only constructor that can make impossible route tables.
    fn routed_work_config(root: &Path, routes: Vec<serde_json::Value>) -> CliResult<WorkConfig> {
        let validators: Vec<String> = (1..=6)
            .map(|index| format!("http://127.0.0.1:900{index}"))
            .collect();
        let file = serde_json::json!({
            "chain": {
                "network_id": network().as_str(),
                "genesis_payload_digest": hex::encode([0x01; 32]),
                "threshold_identity": hex::encode(THRESHOLD_IDENTITY),
            },
            "validators": validators,
            "journal": { "root": root.display().to_string() },
            "routes": routes,
            "policies": {
                "policy_salt": hex::encode([0x5a; 32]),
                "channel": {
                    "compute_credit_limit": 40,
                    "delivery_credit_limit": 40,
                },
                "execution": {
                    "allowed_environment": hex::encode([0x11; 32]),
                    "generation_policy_digest": hex::encode([0x12; 32]),
                    "identity_source_digest": hex::encode([0x13; 32]),
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
            "response_alarm_margin_blocks": 16,
        });
        let path = root.join("work-config.json");
        fs::write(&path, file.to_string())
            .with_context(|| format!("the route fixture writes {}", path.display()))?;
        load_work_config(&path)
    }

    fn options(root: &Path, max_job_price: u64) -> ProvisionOptions {
        let client = client().party_key();
        let bond = expected_bond_for(client, &[0xa1], max_job_price);
        let work_config = routed_work_config(root, vec![route(0x51, bond, client)])
            .unwrap_or_else(|error| panic!("the route fixture loads: {error:#}"));
        options_for(work_config, client, &[0xa1], max_job_price)
    }

    fn options_for(
        work_config: WorkConfig,
        client: Key,
        stake_coins: &[u8],
        max_job_price: u64,
    ) -> ProvisionOptions {
        ProvisionOptions {
            work_config,
            settlement_key: provider(),
            client: hex::encode(client.to_bytes()),
            stake_coins: stake_coins
                .iter()
                .map(|coin| hex::encode([*coin; 32]))
                .collect(),
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
        provision_options(&options(root, max_job_price), duties)
    }

    fn provision_options(
        options: &ProvisionOptions,
        duties: &PaidWorkDuties,
    ) -> CliResult<Provisioned> {
        Offer::plan(options, duties)?.journal(floor())
    }

    /// The bond the fixture inputs name, spelled out here rather than
    /// taken from the command: the parties are positional, so a maker
    /// and taker the other way round is a different edge and this
    /// notices.
    fn bond_funding_for(stake_coins: &[u8]) -> Funding {
        let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
        for (slot, coin) in slots.iter_mut().zip(stake_coins) {
            *slot = CoinId::from_bytes([*coin; CoinId::LENGTH]);
        }
        Funding::new(
            List::take(slots, stake_coins.len()),
            List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
        )
    }

    fn bond_terms_for(client: Key, max_job_price: u64) -> WorkStakeBondTerms {
        WorkStakeBondTerms {
            parties: Parties::new(provider().party_key(), client),
            timeout: BlockHeight::new(500),
            timeout_outputs: List::take(
                [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price,
        }
    }

    fn expected_bond_for(client: Key, stake_coins: &[u8], max_job_price: u64) -> EdgeId {
        Tx::edge_id_of(
            &bond_funding_for(stake_coins),
            &Terms::work_stake_bond(bond_terms_for(client, max_job_price)),
        )
    }

    fn expected_bond(max_job_price: u64) -> EdgeId {
        expected_bond_for(client().party_key(), &[0xa1], max_job_price)
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

    fn proposal_signature(client: Key, stake_coins: &[u8], max_job_price: u64) -> [u8; 64] {
        provider()
            .sign(Tx::open_hash(
                network(),
                &bond_funding_for(stake_coins),
                &Terms::work_stake_bond(bond_terms_for(client, max_job_price)),
            ))
            .to_bytes()
    }

    /// Whether any file under `root` holds `signature` verbatim.
    ///
    /// A settlement signature is deterministic (RFC 6979), so the exact bytes
    /// a refused candidate would have exported are computable without letting
    /// it export them. This is asked of an offer that *was* made as well as
    /// of one that was refused: a scan that finds nothing everywhere would
    /// answer "no signature was written" about a root full of them.
    fn root_holds_signature(root: &Path, signature: &[u8]) -> bool {
        fs::read_dir(root)
            .unwrap_or_else(|error| panic!("the fixture root enumerates: {error}"))
            .any(|entry| {
                let entry = entry.unwrap_or_else(|error| panic!("a fixture entry reads: {error}"));
                let bytes = fs::read(entry.path())
                    .unwrap_or_else(|error| panic!("a fixture file reads: {error}"));
                bytes
                    .windows(signature.len())
                    .any(|window| window == signature)
            })
    }

    /// No file, no discoverable revision, and no retained signature are three
    /// assertions because opening the absent store to inspect it would create
    /// the revisionless journal this test is meant to rule out.
    fn assert_no_offer_artifact(root: &Path, bond: EdgeId, signature: &[u8]) {
        let key = hellas_rpc::work_store::setup::setup_key(network(), bond);
        let stem = format!("setup-{}.", hex::encode(key.into_bytes()));
        let entries: Vec<_> = fs::read_dir(root)
            .unwrap_or_else(|error| panic!("the fixture root enumerates: {error}"))
            .map(|entry| entry.unwrap_or_else(|error| panic!("a fixture entry reads: {error}")))
            .collect();
        assert!(
            entries
                .iter()
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(&stem)),
            "the refused candidate left its setup journal behind",
        );
        assert!(
            !root_holds_signature(root, signature),
            "the refused candidate's bond signature was retained under the root",
        );

        let found = discover_setups(root, network())
            .unwrap_or_else(|error| panic!("the fixture root enumerates: {error}"));
        assert!(
            found.unidentified.is_empty(),
            "the refusal left an unidentified, revisionless journal: {:?}",
            found.unidentified,
        );
        assert!(
            found.setups.iter().all(|setup| setup.bond_edge != bond),
            "the refused candidate left revision one discoverable",
        );
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

    /// More than one offer is safe when its complete capital and routing
    /// identity are separate. Discovery sees both without needing either
    /// client to have answered revision one.
    #[test]
    fn disjoint_routes_bonds_and_stakes_make_two_discoverable_offers() {
        let dir = tempfile::tempdir().unwrap();
        let first_client = client().party_key();
        let second_client = signer(0x23).party_key();
        let first_bond = expected_bond_for(first_client, &[0xa1], 40);
        let second_bond = expected_bond_for(second_client, &[0xb1], 41);
        let config = routed_work_config(
            dir.path(),
            vec![
                route(0x51, first_bond, first_client),
                route(0x52, second_bond, second_client),
            ],
        )
        .unwrap_or_else(|error| panic!("the two-route fixture loads: {error:#}"));
        let first = options_for(config.clone(), first_client, &[0xa1], 40);
        let second = options_for(config, second_client, &[0xb1], 41);

        provision_options(&first, &admits())
            .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));
        provision_options(&second, &admits())
            .unwrap_or_else(|error| panic!("the disjoint second offer is made: {error:#}"));

        let found = discover_setups(dir.path(), network())
            .unwrap_or_else(|error| panic!("the two-offer root enumerates: {error}"));
        assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
        assert_eq!(provider_setups(dir.path()), 2);
        assert!(
            found
                .setups
                .iter()
                .any(|setup| setup.bond_edge == first_bond)
        );
        assert!(
            found
                .setups
                .iter()
                .any(|setup| setup.bond_edge == second_bond)
        );
    }

    /// The reservation comes back from A's revision-one bytes after every
    /// in-memory value has been dropped. In particular, `funding_coins()` is
    /// empty at that stage, so it cannot be the source this refusal uses.
    #[test]
    fn a_restart_refuses_a_coin_reserved_by_an_unanswered_offer_before_signing_or_writing() {
        let dir = tempfile::tempdir().unwrap();
        let first_client = client().party_key();
        let second_client = signer(0x23).party_key();
        let first_bond = expected_bond_for(first_client, &[0xa1, 0xa2], 40);
        let second_bond = expected_bond_for(second_client, &[0xa2, 0xb2], 41);
        let config = routed_work_config(
            dir.path(),
            vec![
                route(0x51, first_bond, first_client),
                route(0x52, second_bond, second_client),
            ],
        )
        .unwrap_or_else(|error| panic!("the two-route fixture loads: {error:#}"));
        let first = options_for(config.clone(), first_client, &[0xa1, 0xa2], 40);
        provision_options(&first, &admits())
            .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));

        let store = open_provider_journal(dir.path(), network(), first_bond)
            .unwrap_or_else(|error| panic!("the first offer reopens: {error:#}"));
        assert_eq!(store.state().revision(), Some(1));
        assert!(
            store.state().funding_coins().is_empty(),
            "revision one unexpectedly exposes an executable Open",
        );
        drop(store);
        drop(first);
        drop(config);

        // The configuration and every setup fact are loaded again from disk;
        // no reservation value from the first call crosses this line.
        let config_path = dir.path().join("work-config.json");
        let restarted = load_work_config(&config_path)
            .unwrap_or_else(|error| panic!("the restarted configuration loads: {error:#}"));
        let second = options_for(restarted, second_client, &[0xa2, 0xb2], 41);
        let Err(error) = provision_options(&second, &admits()) else {
            panic!("a restarted provider accepted stake reserved by revision one");
        };

        let said = format!("{error:#}");
        assert!(
            said.contains(&hex::encode([0xa2; CoinId::LENGTH])),
            "the refusal does not name the colliding coin: {said}",
        );
        assert!(
            said.contains(&hex::encode(first_bond.to_bytes())),
            "the refusal does not name the offer holding the coin: {said}",
        );
        assert_eq!(provider_setups(dir.path()), 1);
        // The same scan, over the offer that was made: what rules out B's
        // signature has to be able to find A's, or it rules out nothing.
        assert!(
            root_holds_signature(
                dir.path(),
                &proposal_signature(first_client, &[0xa1, 0xa2], 40),
            ),
            "the signature scan cannot find the offer that was made",
        );
        assert_no_offer_artifact(
            dir.path(),
            second_bond,
            &proposal_signature(second_client, &[0xa2, 0xb2], 41),
        );
    }

    /// Route-table construction itself is the pre-signing peer collision
    /// gate. A duplicate peer cannot become the configuration passed to the
    /// second provisioning attempt.
    #[test]
    fn a_second_offer_cannot_reuse_the_first_offers_peer() {
        let dir = tempfile::tempdir().unwrap();
        let first_client = client().party_key();
        let second_client = signer(0x23).party_key();
        let first_bond = expected_bond_for(first_client, &[0xa1], 40);
        let second_bond = expected_bond_for(second_client, &[0xb1], 41);
        let first_config =
            routed_work_config(dir.path(), vec![route(0x51, first_bond, first_client)])
                .unwrap_or_else(|error| panic!("the first route loads: {error:#}"));
        let first = options_for(first_config, first_client, &[0xa1], 40);
        provision_options(&first, &admits())
            .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));

        let error = routed_work_config(
            dir.path(),
            vec![
                route(0x51, first_bond, first_client),
                route(0x51, second_bond, second_client),
            ],
        )
        .expect_err("one authenticated peer cannot name the second offer too");
        let said = format!("{error:#}");
        assert!(
            said.contains("names peer") && said.contains("twice"),
            "unexpected duplicate-peer refusal: {said}",
        );
        assert_eq!(provider_setups(dir.path()), 1);
        assert!(
            root_holds_signature(dir.path(), &proposal_signature(first_client, &[0xa1], 40)),
            "the signature scan cannot find the offer that was made",
        );
        assert_no_offer_artifact(
            dir.path(),
            second_bond,
            &proposal_signature(second_client, &[0xb1], 41),
        );
    }

    /// A repeated provision is still a second promise over the same bond.
    /// It is refused during planning even though the journal could replay an
    /// identical revision idempotently.
    #[test]
    fn a_second_offer_cannot_reuse_the_first_offers_bond() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path(), 40);
        let first = provision_options(&options, &admits())
            .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));

        let Err(error) = provision_options(&options, &admits()) else {
            panic!("a second offer reused the first offer's bond");
        };
        let said = format!("{error:#}");
        assert!(
            said.contains("candidate bond")
                && said.contains("collides")
                && said.contains(&hex::encode(first.bond_edge.to_bytes())),
            "unexpected duplicate-bond refusal: {said}",
        );
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
