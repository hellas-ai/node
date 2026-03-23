use crate::commands::CliResult;
use crate::execution::{ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy};
use crate::text_output::TextOutputDecoder;
use catgrad_llm::PromptRequest;
use hellas_executor::ModelAssets;
use std::io::{self, Write};
use std::sync::Arc;
use tonic_iroh_transport::iroh::EndpointId;

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub model: String,
    pub prompt: String,
    pub max_seq: u32,
    pub retries: usize,
    pub local: bool,
    pub verify_local: bool,
    pub metrics_port: Option<u16>,
}

pub async fn run(options: ExecuteOptions) -> CliResult<()> {
    if let Some(metrics_port) = options.metrics_port {
        let registry = std::sync::Arc::new(prometheus_client::registry::Registry::default());
        crate::metrics::spawn_metrics_server(metrics_port, registry);
    }

    let assets = Arc::new(ModelAssets::load(&options.model)?);
    let prompt_request = PromptRequest::plain(&options.prompt);
    let prepared = assets.prepare_request(&prompt_request)?;
    let mut decoder = TextOutputDecoder::new(assets.clone(), &prepared.stop_token_ids);
    let runtime = if options.local || options.verify_local {
        ExecutionRuntime::spawn_default_local(hellas_executor::DEFAULT_EXECUTION_QUEUE_CAPACITY)?
    } else {
        ExecutionRuntime::default()
    };
    let request = ExecutionRequest::new(
        runtime,
        assets,
        prepared,
        options.max_seq,
        if options.verify_local {
            info!("executing remotely and verifying against local catgrad backend");
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::remote(
                    options.node_id,
                    options.retries,
                ),
                shadow: ExecutionRoute::Local,
            }
        } else if options.local {
            info!("executing locally with catgrad backend");
            ExecutionStrategy::Run(ExecutionRoute::Local)
        } else {
            ExecutionStrategy::Run(ExecutionRoute::remote(
                options.node_id,
                options.retries,
            ))
        },
    )?;

    let mut stdout_sink = |output: &[u8]| {
        let delta = decoder.push_output(output)?;
        if !delta.is_empty() {
            print!("{delta}");
            io::stdout().flush()?;
        }
        Ok(())
    };

    if request.uses_remote_transport() {
        let mut prepared = request.prepare().await?;
        let result = prepared.run(&mut stdout_sink).await;
        crate::tracing_config::suppress_execute_tail_logs();
        drop(prepared);
        let _ = result?;
    } else {
        let _ = request.run(&mut stdout_sink).await?;
    }

    Ok(())
}
