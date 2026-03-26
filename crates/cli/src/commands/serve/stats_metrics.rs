use hellas_executor::ExecutorHandle;
use hellas_rpc::pb::hellas::{GetStatsResponse, TokenStats as ProtoTokenStats};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::time::{Duration, interval};

type U64Gauge = Gauge<u64, AtomicU64>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ModelLabel {
    model_id: String,
}

struct StatsGauges {
    executions_started: U64Gauge,
    executions_completed: U64Gauge,
    executions_failed: U64Gauge,
    prompt_tokens: U64Gauge,
    cached_prompt_tokens: U64Gauge,
    cached_output_tokens: U64Gauge,
    prefill_tokens: U64Gauge,
    generated_tokens: U64Gauge,
}

struct ModelStatsGauges {
    executions_started: Family<ModelLabel, U64Gauge>,
    executions_completed: Family<ModelLabel, U64Gauge>,
    executions_failed: Family<ModelLabel, U64Gauge>,
    prompt_tokens: Family<ModelLabel, U64Gauge>,
    cached_prompt_tokens: Family<ModelLabel, U64Gauge>,
    cached_output_tokens: Family<ModelLabel, U64Gauge>,
    prefill_tokens: Family<ModelLabel, U64Gauge>,
    generated_tokens: Family<ModelLabel, U64Gauge>,
}

pub fn register_and_spawn(registry: &mut Registry, executor: ExecutorHandle) {
    let sub = registry.sub_registry_with_prefix("hellas");

    let global = Arc::new(StatsGauges {
        executions_started: Default::default(),
        executions_completed: Default::default(),
        executions_failed: Default::default(),
        prompt_tokens: Default::default(),
        cached_prompt_tokens: Default::default(),
        cached_output_tokens: Default::default(),
        prefill_tokens: Default::default(),
        generated_tokens: Default::default(),
    });

    sub.register("executions_started", "Executions started", global.executions_started.clone());
    sub.register("executions_completed", "Executions completed", global.executions_completed.clone());
    sub.register("executions_failed", "Executions failed", global.executions_failed.clone());
    sub.register("prompt_tokens", "Total prompt tokens", global.prompt_tokens.clone());
    sub.register("cached_prompt_tokens", "Prompt tokens from cache", global.cached_prompt_tokens.clone());
    sub.register("cached_output_tokens", "Output tokens from cache", global.cached_output_tokens.clone());
    sub.register("prefill_tokens", "Prefill tokens computed", global.prefill_tokens.clone());
    sub.register("generated_tokens", "Output tokens generated", global.generated_tokens.clone());

    let model = Arc::new(ModelStatsGauges {
        executions_started: Default::default(),
        executions_completed: Default::default(),
        executions_failed: Default::default(),
        prompt_tokens: Default::default(),
        cached_prompt_tokens: Default::default(),
        cached_output_tokens: Default::default(),
        prefill_tokens: Default::default(),
        generated_tokens: Default::default(),
    });

    let model_sub = sub.sub_registry_with_prefix("model");
    model_sub.register("executions_started", "Executions started", model.executions_started.clone());
    model_sub.register("executions_completed", "Executions completed", model.executions_completed.clone());
    model_sub.register("executions_failed", "Executions failed", model.executions_failed.clone());
    model_sub.register("prompt_tokens", "Total prompt tokens", model.prompt_tokens.clone());
    model_sub.register("cached_prompt_tokens", "Prompt tokens from cache", model.cached_prompt_tokens.clone());
    model_sub.register("cached_output_tokens", "Output tokens from cache", model.cached_output_tokens.clone());
    model_sub.register("prefill_tokens", "Prefill tokens computed", model.prefill_tokens.clone());
    model_sub.register("generated_tokens", "Output tokens generated", model.generated_tokens.clone());

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            if let Ok(resp) = executor.get_stats().await {
                apply_stats(&global, &model, &resp);
            }
        }
    });
}

fn apply_stats(global: &StatsGauges, model: &ModelStatsGauges, resp: &GetStatsResponse) {
    if let Some(s) = &resp.stats {
        set_gauges(global, s);
    }
    for ms in &resp.model_stats {
        if let Some(s) = &ms.stats {
            let label = ModelLabel {
                model_id: ms.model_id.clone(),
            };
            set_family_gauges(model, &label, s);
        }
    }
}

fn set_gauges(g: &StatsGauges, s: &ProtoTokenStats) {
    g.executions_started.set(s.executions_started);
    g.executions_completed.set(s.executions_completed);
    g.executions_failed.set(s.executions_failed);
    g.prompt_tokens.set(s.prompt_tokens);
    g.cached_prompt_tokens.set(s.cached_prompt_tokens);
    g.cached_output_tokens.set(s.cached_output_tokens);
    g.prefill_tokens.set(s.prefill_tokens);
    g.generated_tokens.set(s.generated_tokens);
}

fn set_family_gauges(g: &ModelStatsGauges, label: &ModelLabel, s: &ProtoTokenStats) {
    g.executions_started.get_or_create(label).set(s.executions_started);
    g.executions_completed.get_or_create(label).set(s.executions_completed);
    g.executions_failed.get_or_create(label).set(s.executions_failed);
    g.prompt_tokens.get_or_create(label).set(s.prompt_tokens);
    g.cached_prompt_tokens.get_or_create(label).set(s.cached_prompt_tokens);
    g.cached_output_tokens.get_or_create(label).set(s.cached_output_tokens);
    g.prefill_tokens.get_or_create(label).set(s.prefill_tokens);
    g.generated_tokens.get_or_create(label).set(s.generated_tokens);
}
