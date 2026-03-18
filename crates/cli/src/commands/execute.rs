use crate::commands::CliResult;
use crate::execution::{
    ExecutionInvocation, ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy,
};
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
    pub backup_quotes: usize,
    pub local: bool,
    pub verify_local: bool,
}

pub async fn run(options: ExecuteOptions) -> CliResult<()> {
    let assets = Arc::new(ModelAssets::load(&options.model)?);
    let prepared = assets.prepare_plain_prompt(&options.prompt)?;
    let runtime = if options.local || options.verify_local {
        ExecutionRuntime::spawn_default_local(hellas_executor::DEFAULT_EXECUTION_QUEUE_CAPACITY)?
    } else {
        ExecutionRuntime::default()
    };
    let request = ExecutionRequest::new(
        runtime,
        ExecutionInvocation::from_prepared_prompt(assets, prepared, options.max_seq)?,
        if options.verify_local {
            info!("executing remotely and verifying against local catgrad backend");
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::remote(options.node_id, options.retries, options.backup_quotes),
                shadow: ExecutionRoute::Local,
            }
        } else if options.local {
            info!("executing locally with catgrad backend");
            ExecutionStrategy::Run(ExecutionRoute::Local)
        } else {
            ExecutionStrategy::Run(ExecutionRoute::remote(
                options.node_id,
                options.retries,
                options.backup_quotes,
            ))
        },
    );

    let mut stdout_sink = |delta: &str| {
        if !delta.is_empty() {
            print!("{delta}");
            io::stdout().flush()?;
        }
        Ok(())
    };
    let _ = request.run(&mut stdout_sink).await?;

    Ok(())
}

