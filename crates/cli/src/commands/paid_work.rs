//! Operator entry points for one paid-work channel and one paid job.
//!
//! This deliberately stays a thin orchestration layer over the setup,
//! journal, light-client, and work APIs.  The durable state remains in the
//! production setup and channel journals; this command does not keep a
//! parallel receipt or invent a second protocol.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use hellas_chain::client::{RemoteLightClient, VerifiedRemoteLightClient};
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedBlockQuery, FinalizedBlockView,
    FinalizedWorkView as _, LightClient as _, WorkBlocks, WorkChannelQuery,
};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::{CollectResultOutcome, collect_result};
use hellas_kernel::{
    CoinId, EdgeId, Funding, List, MAX_PARTY_INPUTS, MAX_START_VALIDITY_BLOCKS, Secp256k1Signer,
    Secp256k1Verifier, WorkPaymentTerms,
};
use hellas_rpc::protocol::artifacts::{Canonical as _, PreparedPaidInputV1};
use hellas_rpc::protocol::work::{
    JobDeadlines, generation_policy_digest, identity_source_digest, private_policy_commitment,
};
use hellas_rpc::protocol::work_setup::{ProviderChannelPolicy, WorkChannelDescriptor};
use hellas_rpc::work::{ClientEndpoint, JobProposal, propose_work};
use hellas_rpc::work_close::CloseProgress;
use hellas_rpc::work_close::FinalizedBlocks as _;
use hellas_rpc::work_handshake::{
    PaymentAdmission, SetupEndpoint, SetupService, apply_setup_exchange, prepare_setup_exchange,
    send_setup_exchange,
};
use hellas_rpc::work_open::{SetupAdvance, SetupProgress};
use hellas_rpc::work_store::journal::MAX_RECORD_BYTES;
use hellas_rpc::work_store::{Role, SetupScan, SetupStore};
use hellas_wire::ServiceMarker;
use hellas_wire::iroh::IrohTransport;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use super::CliResult;
use super::serve::work_config::{WorkConfig, load_paid_work_duties, load_work_config};

/// Paid-work commands intended for deployment bring-up and smoke tests.
#[derive(Debug, Subcommand)]
pub enum PaidWorkCommand {
    /// Build canonical paid input from a causal-LM environment and prompt.
    #[cfg(feature = "llm")]
    PrepareInput(PrepareInputArgs),
    /// Print the identities a prepared input requires in a provider policy.
    InspectInput(InspectInputArgs),
    /// Read the chain identity and genesis payload from validator RPCs.
    InspectChain(InspectChainArgs),
    /// Open (or resume) a durable channel, run one job, and pay for it.
    Run(Box<RunArgs>),
}

#[cfg(feature = "llm")]
#[derive(Debug, Args)]
pub struct PrepareInputArgs {
    /// Canonical causal-LM environment file (for example smollm2.environment).
    #[arg(long = "environment", value_name = "FILE")]
    environment: PathBuf,

    /// Tokenizer JSON used to turn the prompt into committed token IDs.
    #[arg(long = "tokenizer", value_name = "FILE")]
    tokenizer: PathBuf,

    /// Plain-text prompt to commit.
    #[arg(long)]
    prompt: String,

    /// Maximum output tokens committed by the generation policy.
    #[arg(long = "max-new-tokens", default_value_t = 32)]
    max_new_tokens: u32,

    /// Caller-selected stop token ID. Repeat or comma-separate.
    #[arg(long = "stop-token", value_delimiter = ',')]
    stop_token_ids: Vec<u32>,

    /// Destination for canonical PreparedPaidInputV1 bytes.
    #[arg(long = "out", value_name = "FILE")]
    out: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectInputArgs {
    /// Canonical PreparedPaidInputV1 bytes.
    #[arg(long = "prepared-input", value_name = "FILE")]
    prepared_input: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectChainArgs {
    /// Validator light-client WebSocket URL. Repeat exactly six times.
    #[arg(long = "validator", value_name = "URL")]
    validators: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Provider work configuration, including chain identity and policy.
    #[arg(long = "work-config", value_name = "FILE")]
    work_config: PathBuf,

    /// Client-owned directory for durable setup and channel journals.
    #[arg(long = "journal-root", value_name = "DIR")]
    journal_root: PathBuf,

    /// Provider's authenticated Iroh endpoint ID.
    #[arg(long = "provider", value_name = "ENDPOINT_ID")]
    provider: EndpointId,

    /// Direct UDP address for the provider. Repeat or comma-separate.
    #[arg(long = "provider-addr", value_delimiter = ',', value_name = "IP:PORT")]
    provider_addrs: Vec<SocketAddr>,

    /// Provider bond edge advertised for this client.
    #[arg(long = "bond", value_name = "HEX")]
    bond: String,

    /// Client coin funding the payment edge. Repeat or comma-separate.
    #[arg(long = "payment-coin", value_delimiter = ',', value_name = "HEX")]
    payment_coins: Vec<String>,

    /// Capacity reserved as the understatement-omission penalty.
    #[arg(long = "omission-bond")]
    omission_bond: u64,

    /// Canonical PreparedPaidInputV1 bytes to execute.
    #[arg(long = "prepared-input", value_name = "FILE")]
    prepared_input: PathBuf,

    /// Write the authenticated canonical result transcript here.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Blocks from proposal to the last acceptance height.
    #[arg(long = "acceptance-blocks", default_value_t = 16)]
    acceptance_blocks: u64,

    /// Additional blocks from acceptance to the terminal-result deadline.
    #[arg(long = "terminal-blocks", default_value_t = 64)]
    terminal_blocks: u64,

    /// Additional blocks from terminal result to the payment deadline.
    #[arg(long = "payment-blocks", default_value_t = 32)]
    payment_blocks: u64,

    /// Wall-clock limit for setup, execution, collection, and payment.
    #[arg(long = "timeout-secs", default_value_t = 300)]
    timeout_secs: u64,

    /// After payment, open the client close and wait for finalized settlement.
    #[arg(long = "settle", visible_alias = "close-after-payment")]
    settle: bool,
}

/// Runs a paid-work operator command under an existing client identity.
pub async fn run(
    command: PaidWorkCommand,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> CliResult<()> {
    match command {
        #[cfg(feature = "llm")]
        PaidWorkCommand::PrepareInput(args) => prepare_input(args, &transport_key, &settlement_key),
        PaidWorkCommand::InspectInput(args) => {
            inspect_input(&args.prepared_input, &transport_key, &settlement_key)
        }
        PaidWorkCommand::InspectChain(args) => inspect_chain(&args.validators).await,
        PaidWorkCommand::Run(args) => {
            anyhow::ensure!(
                args.timeout_secs > 0,
                "--timeout-secs must be greater than zero"
            );
            let timeout = Duration::from_secs(args.timeout_secs);
            tokio::time::timeout(timeout, run_one(*args, transport_key, settlement_key))
                .await
                .map_err(|_| anyhow::anyhow!("paid-work run exceeded its {timeout:?} limit"))?
        }
    }
}

#[cfg(feature = "llm")]
fn prepare_input(
    args: PrepareInputArgs,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed as _, OutputAddressed as _, SourceRef, TextArtifact,
        TextExecution, TextPolicy, TokenIds,
    };

    anyhow::ensure!(
        args.max_new_tokens > 0,
        "--max-new-tokens must be greater than zero"
    );
    let environment_bytes = super::read_bounded_regular_file(
        &args.environment,
        "causal-LM environment",
        hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    )?;
    let environment = hellas_rpc::CausalLmEnvironment::from_canonical_bytes(&environment_bytes)
        .map_err(|error| {
            anyhow::anyhow!(
                "invalid canonical environment {}: {error}",
                args.environment.display(),
            )
        })?;
    let manifest = environment.manifest();
    let presentation = hellas_presentation::TextPresentation::load(&args.tokenizer)?;
    let prompt_tokens = TokenIds::from_u32s(presentation.encode(&args.prompt)?);
    let text_policy = TextPolicy::from_u32_stop_tokens(args.max_new_tokens, args.stop_token_ids);
    let identity_artifact =
        TextArtifact::identity(BoundTermId::from_digest(manifest.content_id().digest()));
    let text_execution = TextExecution::new(
        SourceRef::output(identity_artifact.output_id()),
        prompt_tokens.output_id(),
        text_policy.output_id(),
    );
    let evaluate_request = hellas_rpc::EvaluateRequest {
        text_execution: text_execution.input_id().digest(),
        runner_public_key: hellas_rpc::PublicKey::Secp256k1(settlement_key.party_key().to_bytes()),
        execution_environment: manifest.content_id(),
        nonce: rand::random(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    let prepared = PreparedPaidInputV1::new(
        &evaluate_request,
        &manifest,
        &text_execution,
        &prompt_tokens,
        &text_policy,
        &identity_artifact,
    );
    write_private(&args.out, &prepared.encode()?)?;
    println!("prepared_input: {}", args.out.display());
    println!("prepared_input_bytes: {}", prepared.encode()?.len());
    inspect_prepared(&prepared, transport_key, settlement_key)
}

fn inspect_input(
    path: &Path,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    let prepared = read_prepared_input(path)?;
    inspect_prepared(&prepared, transport_key, settlement_key)
}

fn inspect_prepared(
    prepared: &PreparedPaidInputV1,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    let identities = InputIdentities::from_prepared(prepared)?;
    let output = serde_json::json!({
        "client_transport_peer": hex::encode(transport_key.public().as_bytes()),
        "client_settlement_key": hex::encode(settlement_key.party_key().to_bytes()),
        // ContentId's textual form is Xet's canonical per-limb hex spelling,
        // which is what WorkConfig parses. Raw digest-byte hex is different
        // for non-uniform hashes and would make the printed JSON unusable.
        "allowed_environment": identities.allowed_environment.to_string(),
        "generation_policy_digest": hex::encode(identities.generation_policy_digest.as_bytes()),
        "identity_source_digest": hex::encode(identities.identity_source_digest.as_bytes()),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputIdentities {
    allowed_environment: hellas_rpc::ContentId,
    generation_policy_digest: hellas_rpc::Digest,
    identity_source_digest: hellas_rpc::Digest,
}

impl InputIdentities {
    fn from_prepared(prepared: &PreparedPaidInputV1) -> CliResult<Self> {
        let parts = prepared
            .parts()
            .context("prepared input contains a non-canonical body")?;
        let allowed_environment = parts.manifest.content_id();
        anyhow::ensure!(
            parts.evaluate_request.execution_environment == allowed_environment,
            "prepared input request names environment {}, but its manifest derives {}",
            parts.evaluate_request.execution_environment,
            allowed_environment,
        );
        Ok(Self {
            allowed_environment,
            generation_policy_digest: generation_policy_digest(
                &parts.text_policy.canonical_bytes(),
            )?,
            identity_source_digest: identity_source_digest(
                &parts.identity_artifact.canonical_bytes(),
            )?,
        })
    }
}

async fn inspect_chain(validators: &[String]) -> CliResult<()> {
    anyhow::ensure!(
        validators.len() == 6,
        "--validator must be passed exactly six times, got {}",
        validators.len(),
    );
    let mut observed: Option<(ConsensusInfo, [u8; 32])> = None;
    for url in validators {
        let client = RemoteLightClient::connect(url.clone())
            .await
            .with_context(|| format!("failed to connect to validator {url}"))?;
        let info = client
            .get_consensus_info()
            .await
            .with_context(|| format!("failed to read consensus info from {url}"))?;
        let first = client
            .get_finalized_block(FinalizedBlockQuery::Height(1))
            .await
            .with_context(|| format!("failed to read finalized block 1 from {url}"))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator {url} has no finalized block 1; genesis cannot be authenticated until block 1 is finalized",
                )
            })?;
        ConsensusVerifier::new(&info)
            .with_context(|| format!("validator {url} reported an unusable threshold identity"))?
            .verify_snapshot(&first.snapshot)
            .with_context(|| format!("validator {url} returned an unauthenticated block 1"))?;
        let first = FinalizedBlockView::decode(&first)
            .with_context(|| format!("validator {url} returned malformed finalized block 1"))?;
        anyhow::ensure!(
            first.height() == 1,
            "validator {url} answered the height-1 query with finalized height {}",
            first.height(),
        );
        let genesis: [u8; 32] = first.parent().into();
        match &observed {
            None => observed = Some((info, genesis)),
            Some((expected, payload)) => {
                anyhow::ensure!(
                    info.network_id == expected.network_id
                        && info.threshold_identity == expected.threshold_identity,
                    "validator {url} reports a different consensus identity",
                );
                anyhow::ensure!(
                    genesis == *payload,
                    "validator {url} reports a different genesis payload",
                );
            }
        }
    }
    let (info, genesis) = observed.expect("six validators produced one observation");
    let output = serde_json::json!({
        "chain": {
            "network_id": info.network_id,
            "genesis_payload_digest": hex::encode(genesis),
            "threshold_identity": hex::encode(info.threshold_identity),
        },
        "validators": validators,
        "reported_consensus_validators": info.validators,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn run_one(
    args: RunArgs,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> CliResult<()> {
    anyhow::ensure!(
        args.acceptance_blocks > 0 && args.terminal_blocks > 0 && args.payment_blocks > 0,
        "all three deadline spans must be greater than zero",
    );
    anyhow::ensure!(
        !args.payment_coins.is_empty(),
        "at least one --payment-coin is required",
    );

    let config = load_work_config(&args.work_config)?;
    let duties = load_paid_work_duties(&config)?;
    let policy = duties
        .evidence()
        .map(|evidence| evidence.policy.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the work config supplies no usable channel policy: {}",
                duties.summary(),
            )
        })?;
    let prepared = read_prepared_input(&args.prepared_input)?;
    let identities = InputIdentities::from_prepared(&prepared)?;
    check_policy_input(&policy, identities)?;
    let bond = edge_id("--bond", &args.bond)?;
    let payment_funding = Funding::new(coins(&args.payment_coins)?, empty_coins());
    let chain = connect_chain(&config).await?;
    check_genesis(&config, &chain).await?;

    std::fs::create_dir_all(&args.journal_root).with_context(|| {
        format!(
            "failed to create client journal root {}",
            args.journal_root.display(),
        )
    })?;
    let store = SetupStore::open(
        &args.journal_root,
        config.chain.network,
        bond,
        Role::Client,
        &Secp256k1Verifier::new(),
    )
    .with_context(|| {
        format!(
            "failed to open client setup journal under {}",
            args.journal_root.display(),
        )
    })?;
    let mut setup = SetupEndpoint::new(
        store,
        settlement_key.clone(),
        PaymentAdmission::Proposes(Box::new(policy.clone())),
    );
    let dialer =
        ProviderDialer::bind(args.provider, args.provider_addrs.clone(), transport_key).await?;

    if setup.state().revision().is_none() {
        exchange_setup(&dialer, &mut setup).await?;
    }
    let bundle = setup
        .state()
        .bundle()
        .cloned()
        .context("provider returned no bond proposal")?;
    anyhow::ensure!(
        bundle.bond_edge() == bond,
        "provider proposed a different bond edge"
    );
    anyhow::ensure!(
        bundle.bond_terms().parties.taker() == settlement_key.party_key(),
        "provider bond names client settlement key {}, not this identity's {}",
        hex::encode(bundle.bond_terms().parties.taker().to_bytes()),
        hex::encode(settlement_key.party_key().to_bytes()),
    );
    if setup.state().scan_armed().is_none() {
        setup.arm_scan(finalized_floor(&chain).await?)?;
    }
    if setup.state().revision() == Some(1) {
        let terms = payment_terms(&config, &policy, &bundle, args.omission_bond);
        setup.propose_payment(payment_funding, terms)?;
    }
    if setup.state().revision() == Some(2) {
        exchange_setup(&dialer, &mut setup).await?;
    }
    anyhow::ensure!(
        setup.state().revision() == Some(3),
        "setup did not reach its countersigned revision",
    );

    let setup_service = SetupService::new(setup);
    let (mounted, descriptor) = drive_setup(&setup_service, &policy, &chain, config.poll).await?;
    let ready = ready_channel(&descriptor, &chain).await?;
    let mut client = ClientEndpoint::new(ready.clone(), mounted, settlement_key)?;
    client.catch_up(&chain).await?;
    let ready = ready_channel(&descriptor, &chain).await?;
    ready.check_caught_up(client.state().cursor().0)?;
    println!(
        "bond_edge: {}",
        hex::encode(descriptor.bond_edge().to_bytes())
    );
    println!(
        "payment_edge: {}",
        hex::encode(descriptor.channel().payment_edge().to_bytes()),
    );
    println!(
        "channel_id: {}",
        hex::encode(descriptor.channel().id().as_bytes()),
    );

    let prepared_bytes = prepared.encode()?;
    let current = client.state().cursor().0;
    let deadlines = relative_deadlines(current, &args)?;
    let proposal = JobProposal {
        prepared_input: prepared,
        deadlines,
    };
    let existing = client
        .state()
        .jobs()
        .filter(|job| job.prepared_input() == prepared_bytes.as_slice())
        .map(|job| (job.work_id(), job.phase(), *job.authorization()))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        existing.len() <= 1,
        "more than one active job matches this prepared input; use a fresh journal root",
    );
    let (work_id, already_collected) = match existing.first().copied() {
        Some((_work_id, hellas_rpc::work_store::JobPhase::HalfSigned, authorization)) => {
            let resumed = JobProposal {
                prepared_input: proposal.prepared_input.clone(),
                deadlines: JobDeadlines {
                    acceptance: authorization.acceptance_deadline,
                    terminal: authorization.terminal_deadline,
                    payment: authorization.payment_deadline,
                },
            };
            let transport = dialer.work().await?;
            (propose_work(transport, &mut client, &resumed).await?, false)
        }
        Some((work_id, hellas_rpc::work_store::JobPhase::Ready, _))
        | Some((work_id, hellas_rpc::work_store::JobPhase::Matched, _)) => (work_id, true),
        Some((work_id, _, _)) => (work_id, false),
        None => {
            let transport = dialer.work().await?;
            (
                propose_work(transport, &mut client, &proposal).await?,
                false,
            )
        }
    };
    println!("work_id: {}", hex::encode(work_id.as_bytes()));

    let transcript = if already_collected {
        client
            .state()
            .job_by_id(work_id)
            .map(|job| job.transcript().to_vec())
            .context("collected job disappeared from its journal")?
    } else {
        collect_until_ready(&dialer, &mut client, &ready, &chain, work_id, config.poll).await?
    };
    if let Some(output) = args.output {
        std::fs::write(&output, &transcript).with_context(|| {
            format!("failed to write result transcript to {}", output.display())
        })?;
        println!("result: {} ({} bytes)", output.display(), transcript.len());
    } else {
        println!("result_bytes: {}", transcript.len());
    }

    let credited = pay_for_result(dialer.work().await?, &mut client, work_id).await?;
    println!("job_price: {}", ready.execution_policy().fixed_price);
    println!("credited_cumulative: {credited}");
    println!("authenticated_result: true");
    if args.settle {
        client
            .prepare_close()
            .context("failed to prepare the client payment close")?;
        loop {
            match client
                .advance_close(&chain, &chain)
                .await
                .context("failed to advance the client payment close")?
            {
                CloseProgress::Settled { provider_payout } => {
                    println!("settled: true");
                    println!("settled_provider_payout: {provider_payout}");
                    println!("settled_finalized_height: {}", client.state().cursor().0);
                    break;
                }
                CloseProgress::Submitted { outcome, .. } => {
                    tracing::info!(?outcome, "client payment close submitted");
                }
                CloseProgress::Opened { .. } | CloseProgress::Nothing => {}
            }
            tokio::time::sleep(config.poll).await;
        }
    } else {
        println!("settled: false");
    }
    println!("client_journals: {}", args.journal_root.display());
    Ok(())
}

fn check_policy_input(policy: &ProviderChannelPolicy, input: InputIdentities) -> CliResult<()> {
    let expected = policy.execution_policy;
    anyhow::ensure!(
        expected.allowed_environment == input.allowed_environment,
        "work config allows environment {}, but prepared input uses {}",
        expected.allowed_environment,
        input.allowed_environment,
    );
    anyhow::ensure!(
        expected.generation_policy_digest == input.generation_policy_digest,
        "work config generation_policy_digest does not match prepared input",
    );
    anyhow::ensure!(
        expected.identity_source_digest == input.identity_source_digest,
        "work config identity_source_digest does not match prepared input",
    );
    Ok(())
}

fn payment_terms(
    config: &WorkConfig,
    policy: &ProviderChannelPolicy,
    bundle: &hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1,
    omission_bond: u64,
) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bundle.bond_edge(),
        bond_terms: bundle.bond_terms().clone(),
        private_policy_commitment: private_policy_commitment(
            config.chain.network,
            &policy.policy_salt,
            &policy.channel_policy,
        ),
        omit_response_blocks: policy.omission.response_blocks,
        start_validity_blocks: MAX_START_VALIDITY_BLOCKS,
        omission_bond,
    }
}

async fn drive_setup(
    setup: &SetupService,
    policy: &ProviderChannelPolicy,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
    poll: Duration,
) -> CliResult<(hellas_rpc::work_store::ChannelStore, WorkChannelDescriptor)> {
    loop {
        let SetupAdvance { progress, mounted } = setup
            .advance_setup(chain, chain, chain)
            .await
            .context("failed to advance paid-work setup")?;
        if let Some(store) = mounted {
            let channel = store.state().channel();
            let descriptor = policy
                .admit(channel.payment_edge(), channel.payment_terms().clone())
                .context("the funded channel no longer satisfies the configured policy")?;
            return Ok((store, descriptor));
        }
        match progress {
            SetupProgress::Aborted(reason) => bail!("paid-work setup aborted: {reason:?}"),
            SetupProgress::Faulted(reason) => bail!("paid-work setup faulted: {reason:?}"),
            SetupProgress::TimeoutBond => bail!("provider bond timed out before setup completed"),
            _ => tokio::time::sleep(poll).await,
        }
    }
}

async fn ready_channel(
    descriptor: &WorkChannelDescriptor,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> CliResult<hellas_rpc::protocol::work_setup::ReadyChannel> {
    let query = WorkChannelQuery {
        bond_edge: descriptor.bond_edge(),
        payment_edge: descriptor.channel().payment_edge(),
        funding: Default::default(),
    };
    let snapshot = chain
        .work_channel_snapshot(query)
        .await?
        .context("no finalized channel snapshot is available")?;
    descriptor
        .check_ready(&snapshot.observed_channel())
        .context("the finalized channel is not ready")
}

async fn collect_until_ready(
    dialer: &ProviderDialer,
    client: &mut ClientEndpoint,
    ready: &hellas_rpc::protocol::work_setup::ReadyChannel,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
    work_id: hellas_rpc::Digest,
    poll: Duration,
) -> CliResult<Vec<u8>> {
    loop {
        match collect_result(dialer.work().await?, client, ready, chain, work_id).await? {
            CollectResultOutcome::Collected(result) => return Ok(result.transcript),
            CollectResultOutcome::NotReady { reason } => {
                tracing::info!(%reason, "paid result is not ready yet");
                tokio::time::sleep(poll).await;
            }
        }
    }
}

fn relative_deadlines(current: u64, args: &RunArgs) -> CliResult<JobDeadlines> {
    let acceptance = current
        .checked_add(args.acceptance_blocks)
        .context("acceptance deadline overflow")?;
    let terminal = acceptance
        .checked_add(args.terminal_blocks)
        .context("terminal deadline overflow")?;
    let payment = terminal
        .checked_add(args.payment_blocks)
        .context("payment deadline overflow")?;
    Ok(JobDeadlines {
        acceptance,
        terminal,
        payment,
    })
}

async fn exchange_setup(dialer: &ProviderDialer, setup: &mut SetupEndpoint) -> CliResult<()> {
    let request = prepare_setup_exchange(setup);
    let response = send_setup_exchange(dialer.setup().await?, request).await?;
    apply_setup_exchange(setup, response)?;
    Ok(())
}

struct ProviderDialer {
    endpoint: Endpoint,
    provider: EndpointAddr,
}

impl ProviderDialer {
    async fn bind(
        provider: EndpointId,
        addresses: Vec<SocketAddr>,
        secret_key: SecretKey,
    ) -> CliResult<Self> {
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![
                hellas_rpc::services::work_setup::WorkSetup::ALPN
                    .as_bytes()
                    .to_vec(),
                hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
            ])
            .bind()
            .await
            .context("failed to bind paid-work Iroh endpoint")?;
        Ok(Self {
            endpoint,
            provider: EndpointAddr::from_parts(
                provider,
                addresses.into_iter().map(TransportAddr::Ip),
            ),
        })
    }

    async fn setup(&self) -> CliResult<IrohTransport> {
        self.connect(hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes())
            .await
    }

    async fn work(&self) -> CliResult<IrohTransport> {
        self.connect(hellas_rpc::services::work::Work::ALPN.as_bytes())
            .await
    }

    async fn connect(&self, alpn: &[u8]) -> CliResult<IrohTransport> {
        let connection = self
            .endpoint
            .connect(self.provider.clone(), alpn)
            .await
            .with_context(|| format!("failed to connect to provider {}", self.provider.id))?;
        Ok(IrohTransport::new(connection))
    }
}

async fn connect_chain(config: &WorkConfig) -> CliResult<WorkBlocks<VerifiedRemoteLightClient>> {
    let verifier = ConsensusVerifier::new(&ConsensusInfo {
        validators: config.validators.clone(),
        threshold_identity: config.chain.threshold_identity.clone(),
        network_id: config.chain.network.as_str().to_owned(),
    })
    .context("configured threshold identity is unusable")?;
    let mut failures = Vec::new();
    for url in &config.validators {
        match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => return Ok(WorkBlocks::new(client)),
            Err(error) => failures.push(format!("{url}: {error}")),
        }
    }
    bail!("no configured validator answered: {}", failures.join("; "))
}

async fn check_genesis(
    config: &WorkConfig,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> CliResult<()> {
    let first = chain
        .block_at(1)
        .await?
        .context(
            "configured validator has no finalized block 1; genesis cannot be authenticated until block 1 is finalized",
        )?;
    check_genesis_payload(
        config.chain.genesis_payload_digest.as_bytes(),
        &first.parent,
    )
}

fn check_genesis_payload(expected: &[u8; 32], actual: &[u8; 32]) -> CliResult<()> {
    anyhow::ensure!(
        actual == expected,
        "validator genesis payload {} does not match configured {}",
        hex::encode(actual),
        hex::encode(expected),
    );
    Ok(())
}

async fn finalized_floor(chain: &WorkBlocks<VerifiedRemoteLightClient>) -> CliResult<SetupScan> {
    let height = chain
        .latest_height()
        .await?
        .context("configured validator has finalized no blocks")?;
    let block = chain
        .block_at(height)
        .await?
        .context("configured validator did not return its finalized tip")?;
    Ok(SetupScan {
        height,
        payload: block.payload,
    })
}

fn read_prepared_input(path: &Path) -> CliResult<PreparedPaidInputV1> {
    let bytes = super::read_bounded_regular_file(path, "prepared paid input", MAX_RECORD_BYTES)?;
    PreparedPaidInputV1::decode(&bytes, MAX_RECORD_BYTES)
        .map_err(|error| anyhow::anyhow!("invalid prepared paid input {}: {error}", path.display()))
}

#[cfg(feature = "llm")]
fn write_private(path: &Path, bytes: &[u8]) -> CliResult<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict {}", path.display()))?;
    }
    Ok(())
}

fn edge_id(flag: &str, value: &str) -> CliResult<EdgeId> {
    Ok(EdgeId::from_bytes(fixed_hex(flag, value)?))
}

fn coins(values: &[String]) -> CliResult<List<CoinId, MAX_PARTY_INPUTS>> {
    let ids = values
        .iter()
        .map(|value| fixed_hex("--payment-coin", value).map(CoinId::from_bytes))
        .collect::<CliResult<Vec<_>>>()?;
    let slots: [CoinId; MAX_PARTY_INPUTS] = std::array::from_fn(|index| {
        ids.get(index)
            .copied()
            .unwrap_or_else(|| CoinId::from_bytes([0; CoinId::LENGTH]))
    });
    List::new(slots, ids.len()).context("too many --payment-coin values")
}

fn empty_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
    List::take(
        [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        0,
    )
}

fn fixed_hex<const N: usize>(flag: &str, value: &str) -> CliResult<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{flag} is not hex"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{flag} is {} bytes; expected {N}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::NetworkId;
    use hellas_rpc::peers::PeerId;

    #[test]
    fn relative_deadlines_are_ordered_from_the_current_cursor() {
        let args = RunArgs {
            work_config: "work.json".into(),
            journal_root: "journal".into(),
            provider: SecretKey::generate().public(),
            provider_addrs: Vec::new(),
            bond: hex::encode([1_u8; 32]),
            payment_coins: vec![hex::encode([2_u8; 32])],
            omission_bond: 3,
            prepared_input: "input.bin".into(),
            output: None,
            acceptance_blocks: 4,
            terminal_blocks: 5,
            payment_blocks: 6,
            timeout_secs: 7,
            settle: false,
        };
        assert_eq!(
            relative_deadlines(10, &args).unwrap(),
            JobDeadlines {
                acceptance: 14,
                terminal: 19,
                payment: 25,
            },
        );
    }

    #[test]
    fn payment_coin_parser_refuses_the_fifth_coin() {
        let values = (0..=MAX_PARTY_INPUTS)
            .map(|byte| hex::encode([byte as u8; 32]))
            .collect::<Vec<_>>();
        assert!(coins(&values).is_err());
    }

    #[test]
    fn fixed_hex_names_wrong_widths() {
        let error = fixed_hex::<32>("--bond", "00").unwrap_err().to_string();
        assert!(error.contains("1 bytes; expected 32"), "{error}");
    }

    #[test]
    fn genesis_check_compares_the_configured_digest_with_block_ones_parent() {
        let configured = [0x31; 32];
        assert!(check_genesis_payload(&configured, &configured).is_ok());

        let observed_parent = [0x32; 32];
        let error = check_genesis_payload(&configured, &observed_parent)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&hex::encode(observed_parent)), "{error}");
        assert!(error.contains(&hex::encode(configured)), "{error}");
    }

    #[test]
    fn peer_id_hex_is_the_route_spelling() {
        let key = SecretKey::generate();
        let peer = PeerId::from_bytes(*key.public().as_bytes());
        assert_eq!(
            hex::encode(peer.as_bytes()),
            hex::encode(key.public().as_bytes())
        );
    }

    #[test]
    fn terms_are_bound_to_the_configured_network() {
        let network = NetworkId::new("paid-work-cli-test").unwrap();
        let policy = hellas_rpc::protocol::work::PaidChannelPolicyV1 {
            compute_credit_limit: 4,
            delivery_credit_limit: 5,
        };
        assert_ne!(
            private_policy_commitment(network, &[7; 32], &policy),
            private_policy_commitment(
                NetworkId::new("paid-work-cli-other").unwrap(),
                &[7; 32],
                &policy,
            ),
        );
    }

    #[cfg(feature = "llm")]
    #[test]
    fn prepare_input_builds_a_bundle_from_an_environment_and_prompt() {
        use hellas_rpc::{CausalLmEnvironment, ContentId, ContentRef, PublicKey};

        let root = tempfile::tempdir().unwrap();
        let environment_path = root.path().join("model.environment");
        let tokenizer_path = root.path().join("tokenizer.json");
        let output = root.path().join("paid-input.bin");
        let environment = CausalLmEnvironment::new(
            ContentRef::new(ContentId::from_bytes([9; 32]), 1),
            "main",
            Vec::new(),
            Vec::new(),
            vec![4],
            3,
            128,
        )
        .unwrap();
        std::fs::write(&environment_path, environment.canonical_bytes()).unwrap();
        std::fs::write(
            &tokenizer_path,
            br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"world":1,"<unk>":2},"unk_token":"<unk>"}}"#,
        )
        .unwrap();
        let transport = SecretKey::generate();
        let settlement = Secp256k1Signer::from_secret_scalar([7; 32]).unwrap();
        prepare_input(
            PrepareInputArgs {
                environment: environment_path,
                tokenizer: tokenizer_path,
                prompt: "hello world".to_owned(),
                max_new_tokens: 8,
                stop_token_ids: vec![2],
                out: output.clone(),
            },
            &transport,
            &settlement,
        )
        .unwrap();

        let prepared = read_prepared_input(&output).unwrap();
        let parts = prepared.parts().unwrap();
        assert_eq!(
            parts
                .prompt_tokens
                .as_slice()
                .iter()
                .map(|token| token.as_u32())
                .collect::<Vec<_>>(),
            [0, 1],
        );
        assert_eq!(parts.text_policy.max_new_tokens(), 8);
        assert_eq!(
            parts.evaluate_request.runner_public_key,
            PublicKey::Secp256k1(settlement.party_key().to_bytes()),
        );
        assert!(parts.evaluate_request.retain);
        assert_eq!(
            parts.evaluate_request.execution_environment,
            environment.manifest().content_id(),
        );
    }
}
