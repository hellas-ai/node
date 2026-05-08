use crate::commands::CliResult;
use crate::execution::{
    ExecutionEvent, ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy, Outcome,
};
use crate::text_output::TextOutputDecoder;
use catgrad::prelude::Dtype;
use catgrad_llm::types::{Message, openai::ChatMessage};
use futures::StreamExt;
use hellas_rpc::ExecutorError;
use hellas_rpc::model::ModelAssets;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub model: String,
    pub prompt: String,
    pub max_seq: u32,
    pub retries: usize,
    #[cfg(feature = "hellas-executor")]
    pub local: bool,
    #[cfg(feature = "hellas-executor")]
    pub verify_local: bool,
    pub raw: bool,
    /// Ordered preference list. The first entry is what the client *first*
    /// builds the program at; later entries are tried via fallback if the
    /// remote executor refuses with `DtypeNotSupported`. For `--local` /
    /// `--verify-local` the embedded executor's `supported_dtypes` is the
    /// full list so no fallback occurs.
    pub dtype: Vec<Dtype>,
}

/// Returns `true` if `err`'s chain carries an executor's
/// `DtypeNotSupported` decision — either as a local `ExecutorError` (the
/// `--local` route) or as a remote `tonic::Status` with `FailedPrecondition`
/// and the canonical message prefix.
fn is_dtype_not_supported(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(ExecutorError::DtypeNotSupported { .. }) = cause.downcast_ref::<ExecutorError>()
        {
            return true;
        }
        if let Some(status) = cause.downcast_ref::<tonic::Status>()
            && status.code() == tonic::Code::FailedPrecondition
            && status.message().starts_with("program was built for dtype")
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

    // Pre-tokenize the prompt once. Tokenization is dtype-independent, so the
    // `assets` we use here is throwaway; we reload per attempt below to get
    // the dtype-specific courtesy request construction needs.
    let bootstrap_assets = Arc::new(ModelAssets::load(&options.model, options.dtype[0])?);
    let messages = vec![Message::openai(ChatMessage::user(&options.prompt))];
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

    let last_index = options.dtype.len() - 1;
    for (idx, &dtype) in options.dtype.iter().enumerate() {
        if idx > 0 {
            info!(?dtype, "previous dtype rejected, retrying");
        }

        // Per-attempt assets: same tokenizer/template as bootstrap, but the
        // courtesy request below asks the provider for this dtype.
        let assets = Arc::new(ModelAssets::load(&options.model, dtype)?);

        #[cfg(feature = "hellas-executor")]
        let runtime = if options.local || options.verify_local {
            // Embedded executor accepts the full preference list so a future
            // dialer can pin any of them. The CLI itself only ever builds
            // the program at the first acceptable entry.
            ExecutionRuntime::spawn_default_local(
                hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
                options.dtype.clone(),
            )?
            .with_secret_key(secret_key.clone())
        } else {
            ExecutionRuntime::default().with_secret_key(secret_key.clone())
        };
        #[cfg(not(feature = "hellas-executor"))]
        let runtime = ExecutionRuntime::default().with_secret_key(secret_key.clone());

        #[cfg(feature = "hellas-executor")]
        let strategy = if options.verify_local {
            if idx == 0 {
                info!("executing remotely and verifying against local catgrad backend");
            }
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::remote(
                    options.node_id,
                    options.node_addrs.clone(),
                    options.retries,
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
            ))
        };
        #[cfg(not(feature = "hellas-executor"))]
        let strategy = ExecutionStrategy::Run(ExecutionRoute::remote(
            options.node_id,
            options.node_addrs.clone(),
            options.retries,
        ));

        let request =
            ExecutionRequest::new(runtime, assets, prepared.clone(), options.max_seq, strategy)?;
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
