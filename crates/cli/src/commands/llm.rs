use crate::commands::CliResult;
use anyhow::Context;
use futures::StreamExt;
use hellas_client::ExecutionRoute;
use hellas_executor::{Executor, ExecutorError};
use hellas_gateway::{
    CliRuntime, ExecutionEvent, ExecutionRequest, ExecutionRequestOptions, ExecutionStrategy,
    Outcome,
};
use hellas_models::{ChatMessage, ModelAssets, TextOutputDecoder};
use hellas_rpc::{Assurance, ContentId, Dtype, ProducerSigningKey, Retention};
use iroh::{EndpointId, SecretKey};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub model: String,
    pub prompt: String,
    pub max_seq: u32,
    pub retries: usize,
    #[cfg(feature = "evaluate")]
    pub local: bool,
    #[cfg(feature = "evaluate")]
    pub verify_local: bool,
    pub producer_key: ProducerSigningKey,
    pub provider_genesis: Vec<u8>,
    pub expected_provider_genesis: Option<ContentId>,
    pub apple_app_attest_app_id: Option<String>,
    pub apple_app_attest_cdhashes: Vec<[u8; 32]>,
    pub assurance: Assurance,
    pub raw: bool,
    pub retain: bool,
    /// Ordered preference list. The first entry is what the client *first*
    /// builds the program at; later entries are tried via fallback if the
    /// remote executor refuses with `DtypeNotSupported`. For `--local` /
    /// `--verify-local` the embedded executor's `supported_dtypes` is the
    /// full list so no fallback occurs.
    pub dtype: Vec<Dtype>,
}

/// Returns `true` if `err`'s chain carries an executor's
/// `DtypeNotSupported` decision — either as a local `ExecutorError` (the
/// `--local` route) or as a remote `hellas_wire::WireStatus` with `FailedPrecondition`
/// and the canonical message prefix.
fn is_dtype_not_supported(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(ExecutorError::DtypeNotSupported { .. }) = cause.downcast_ref::<ExecutorError>()
        {
            return true;
        }
        if let Some(status) = cause.downcast_ref::<hellas_wire::WireStatus>()
            && status.code == hellas_wire::WireCode::FailedPrecondition
            && status.message.starts_with("program was built for dtype")
        {
            return true;
        }
    }
    false
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    if options.dtype.is_empty() {
        anyhow::bail!("--dtype must list at least one of f32, f16, bf16");
    }
    #[cfg(feature = "evaluate")]
    let uses_remote = !options.local || options.verify_local;
    #[cfg(not(feature = "evaluate"))]
    let uses_remote = true;
    let provider_trust = if uses_remote {
        Some(crate::identity::provider_trust(
            options.expected_provider_genesis,
            options.assurance,
            options.apple_app_attest_app_id.clone(),
            options.apple_app_attest_cdhashes.clone(),
        )?)
    } else {
        None
    };

    // Pre-tokenize the prompt once. Tokenization is dtype-independent, so the
    // `assets` we use here is throwaway; we reload per attempt below to get
    // the dtype-specific courtesy request construction needs.
    let bootstrap_assets = Arc::new(ModelAssets::load(&options.model, options.dtype[0])?);
    let messages = vec![ChatMessage::user(&options.prompt)];
    let prepared = if options.raw || !bootstrap_assets.has_chat_template() {
        if options.raw {
            info!("executing raw prompt without chat template");
        } else {
            info!("model has no chat template; using raw prompt");
        }
        bootstrap_assets.prepare_plain(&options.prompt)?
    } else {
        info!("executing prompt with model chat template");
        bootstrap_assets.prepare_chat(&messages)?
    };
    let mut decoder = TextOutputDecoder::new(bootstrap_assets.clone(), &prepared.stop_token_ids);
    let runner_key = options.producer_key.clone();
    #[cfg(feature = "evaluate")]
    let provider_terms = if options.local || options.verify_local {
        Some((options.provider_genesis.clone(), options.assurance))
    } else {
        None
    };

    let last_index = options.dtype.len() - 1;
    for (idx, &dtype) in options.dtype.iter().enumerate() {
        if idx > 0 {
            info!(?dtype, "previous dtype rejected, retrying");
        }

        // Per-attempt assets: same tokenizer/template as bootstrap, but the
        // courtesy request below asks the provider for this dtype.
        let assets = Arc::new(ModelAssets::load(&options.model, dtype)?);

        #[cfg(feature = "evaluate")]
        let runtime = if options.local || options.verify_local {
            let (provider_genesis, assurance) = provider_terms.clone().unwrap();
            // Embedded executor accepts the full preference list so a future
            // dialer can pin any of them. The CLI itself only ever builds
            // the program at the first acceptable entry.
            CliRuntime::local(
                Executor::spawn_with_producer_key(
                    hellas_rpc::policy::ExecutePolicy::Eager,
                    hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
                    options.dtype.clone(),
                    runner_key.clone(),
                    provider_genesis,
                    assurance,
                )
                .context("failed to initialize local execution backend")?,
            )
            .with_remote(secret_key.clone())
            .await?
        } else {
            CliRuntime::remote(secret_key.clone()).await?
        };
        #[cfg(not(feature = "evaluate"))]
        let runtime = CliRuntime::remote(secret_key.clone()).await?;

        #[cfg(feature = "evaluate")]
        let strategy = if options.verify_local {
            if idx == 0 {
                info!("executing remotely and verifying against local catgrad backend");
            }
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::remote(
                    options.node_id,
                    options.node_addrs.clone(),
                    options.retries,
                    provider_trust
                        .clone()
                        .expect("remote route requires provider trust"),
                ),
                shadow: ExecutionRoute::Local,
            }
        } else if options.local {
            if idx == 0 {
                info!(?dtype, "executing locally with catgrad backend");
            }
            ExecutionStrategy::Run(ExecutionRoute::Local)
        } else {
            ExecutionStrategy::Run(ExecutionRoute::remote(
                options.node_id,
                options.node_addrs.clone(),
                options.retries,
                provider_trust
                    .clone()
                    .expect("remote route requires provider trust"),
            ))
        };
        #[cfg(not(feature = "evaluate"))]
        let strategy = ExecutionStrategy::Run(ExecutionRoute::remote(
            options.node_id,
            options.node_addrs.clone(),
            options.retries,
            provider_trust
                .clone()
                .expect("remote route requires provider trust"),
        ));

        let request = ExecutionRequest::new(
            runtime,
            assets,
            prepared.clone(),
            ExecutionRequestOptions {
                max_seq: options.max_seq,
                assurance: options.assurance,
                retention: Retention::from_retain(options.retain),
            },
            strategy,
            runner_key.clone(),
        )?;
        let uses_remote = request.uses_remote_transport();

        let result: anyhow::Result<()> = async {
            let stream = request.stream();
            tokio::pin!(stream);
            let mut completed = false;
            while let Some(event) = stream.next().await {
                match event? {
                    ExecutionEvent::Chunk { tokens, .. } => {
                        let delta = decoder.push_bytes(&tokens)?;
                        if !delta.is_empty() {
                            print!("{delta}");
                            io::stdout().flush()?;
                        }
                    }
                    ExecutionEvent::Done(Outcome::Completed { .. }) => {
                        completed = true;
                        break;
                    }
                    ExecutionEvent::Done(Outcome::Failed { error, .. }) => {
                        anyhow::bail!("execution failed: {error}");
                    }
                }
            }
            if !completed {
                anyhow::bail!("execution stream ended without terminal outcome");
            }
            Ok(())
        }
        .await;

        if uses_remote {
            crate::tracing_config::suppress_execute_tail_logs();
        }

        match result {
            Ok(()) => return Ok(()),
            Err(err) if idx < last_index && is_dtype_not_supported(&err) => {
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("loop returns on Ok or last-index error")
}
