use crate::commands::CliResult;
use anyhow::Context;
use futures::StreamExt;
use hellas_client::ExecutionRoute;
#[cfg(feature = "evaluate")]
use hellas_executor::{Executor, PackageSource};
use hellas_gateway::{
    CliRuntime, ExecutionEvent, ExecutionRequest, ExecutionRequestOptions, ExecutionStrategy,
    Outcome,
};
use hellas_presentation::{TextOutputDecoder, TextPresentation};
use hellas_rpc::{Assurance, ContentId, ExecutionPackageId, ProducerSigningKey, Retention};
use iroh::{EndpointId, SecretKey};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub package_name: String,
    pub execution_package: Option<ExecutionPackageId>,
    #[cfg(feature = "evaluate")]
    pub local_package: Option<PackageSource>,
    pub tokenizer: PathBuf,
    pub stop_token_ids: Vec<u32>,
    pub prompt: String,
    pub max_new_tokens: u32,
    pub retries: usize,
    #[cfg(feature = "evaluate")]
    pub local: bool,
    #[cfg(feature = "evaluate")]
    pub verify_local: bool,
    pub producer_key: ProducerSigningKey,
    #[cfg(feature = "evaluate")]
    pub provider_genesis: Vec<u8>,
    pub expected_provider_genesis: Option<ContentId>,
    pub apple_app_attest_app_id: Option<String>,
    pub apple_app_attest_cdhashes: Vec<[u8; 32]>,
    pub assurance: Assurance,
    pub retain: bool,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
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

    // Presentation is an explicitly separate local input. Hellas commits the
    // resulting token IDs, not this tokenizer or the decoded text it produces.
    let presentation = Arc::new(TextPresentation::load(&options.tokenizer)?);
    let input_ids = presentation.encode(&options.prompt)?;
    let mut decoder = TextOutputDecoder::new(presentation);
    let package_name = options.package_name;
    let runner_key = options.producer_key.clone();

    #[cfg(feature = "evaluate")]
    let (runtime, execution_package) = if options.local || options.verify_local {
        let executor = Executor::spawn_with_producer_key(
            hellas_rpc::policy::ExecutePolicy::Eager,
            hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            runner_key.clone(),
            options.provider_genesis,
            options.assurance,
        )
        .context("failed to initialize local Catena executor")?;
        let local_package = options.local_package.context(
            "local Catena execution needs a package manifest path; pass --package NAME=PATH",
        )?;
        let execution_package = executor
            .materialize_package(local_package)
            .await
            .with_context(|| format!("failed to load Catena package {package_name}"))?;
        info!(
            package = %package_name,
            execution_package = %execution_package,
            "verified local Catena package"
        );
        let runtime = CliRuntime::local(executor);
        if options.verify_local {
            (
                runtime.with_remote(secret_key.clone()).await?,
                execution_package,
            )
        } else {
            (runtime, execution_package)
        }
    } else {
        let execution_package = options
            .execution_package
            .context("remote Catena execution requires --package-id <64-hex Catena package ID>")?;
        (
            CliRuntime::remote(secret_key.clone()).await?,
            execution_package,
        )
    };
    #[cfg(not(feature = "evaluate"))]
    let (runtime, execution_package) = {
        let execution_package = options
            .execution_package
            .context("remote Catena execution requires --package-id <64-hex Catena package ID>")?;
        (
            CliRuntime::remote(secret_key.clone()).await?,
            execution_package,
        )
    };

    #[cfg(feature = "evaluate")]
    let strategy = if options.verify_local {
        info!(package = %package_name, "executing remotely and verifying against local Catena");
        ExecutionStrategy::Verify {
            primary: ExecutionRoute::remote(
                options.node_id,
                options.node_addrs,
                options.retries,
                provider_trust.expect("remote route requires provider trust"),
            ),
            shadow: ExecutionRoute::Local,
        }
    } else if options.local {
        info!(package = %package_name, "executing locally with Catena");
        ExecutionStrategy::Run(ExecutionRoute::Local)
    } else {
        info!(package = %package_name, "executing remotely with Catena");
        ExecutionStrategy::Run(ExecutionRoute::remote(
            options.node_id,
            options.node_addrs,
            options.retries,
            provider_trust.expect("remote route requires provider trust"),
        ))
    };
    #[cfg(not(feature = "evaluate"))]
    let strategy = ExecutionStrategy::Run(ExecutionRoute::remote(
        options.node_id,
        options.node_addrs,
        options.retries,
        provider_trust.expect("remote route requires provider trust"),
    ));

    let remote_runtime = uses_remote.then(|| runtime.clone());
    let request = ExecutionRequest::new(
        runtime,
        package_name,
        input_ids,
        options.stop_token_ids,
        ExecutionRequestOptions {
            max_new_tokens: options.max_new_tokens,
            execution_package,
            assurance: options.assurance,
            retention: Retention::from_retain(options.retain),
        },
        strategy,
        runner_key,
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
    if let Some(runtime) = remote_runtime {
        runtime.close_remote().await;
    }
    result
}
