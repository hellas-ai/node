use crate::commands::CliResult;
use crate::execution::{ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy};
use crate::text_output::TextOutputDecoder;
use catgrad_llm::ChatInput;
use hellas_executor::ModelAssets;
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
    pub local: bool,
    pub verify_local: bool,
    pub raw: bool,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    let assets = Arc::new(ModelAssets::load(&options.model)?);
    let prepared = if options.raw || !assets.has_chat_template() {
        if options.raw {
            info!("executing raw prompt without chat template");
        } else {
            info!("model has no chat template; using raw prompt");
        }
        assets.prepare_plain(&options.prompt)?
    } else {
        info!("executing prompt with model chat template");
        assets.prepare_chat(&ChatInput::single(&options.prompt))?
    };
    let mut decoder = TextOutputDecoder::new(assets.clone(), &prepared.stop_token_ids);
    let runtime = if options.local || options.verify_local {
        ExecutionRuntime::spawn_default_local(hellas_executor::DEFAULT_EXECUTION_QUEUE_CAPACITY)?
            .with_secret_key(secret_key)
    } else {
        ExecutionRuntime::default().with_secret_key(secret_key)
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
                    options.node_addrs.clone(),
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
                options.node_addrs,
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
