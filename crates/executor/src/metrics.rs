//! Live executor counters.
//!
//! Counters are mutated inline at the event source (start/complete/fail),
//! so there is no polling step that copies internal state into a separate
//! prometheus registry. Detached metrics can be created with
//! [`ExecutorMetrics::default`] for tests and non-server callers.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

type U64Counter = Counter<u64, AtomicU64>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ModelLabel {
    pub model_id: String,
}

/// Single source of truth for executor counters. Each field is a prometheus
/// counter that can be both registered for scraping and read directly via
/// [`Counter::get`] (used by the GetStats RPC path).
#[derive(Default)]
pub struct ExecutorMetrics {
    pub(crate) executions_started: U64Counter,
    pub(crate) executions_completed: U64Counter,
    pub(crate) executions_failed: U64Counter,
    pub(crate) prompt_tokens: U64Counter,
    pub(crate) cached_prompt_tokens: U64Counter,
    pub(crate) cached_output_tokens: U64Counter,
    pub(crate) prefill_tokens: U64Counter,
    pub(crate) generated_tokens: U64Counter,

    pub(crate) by_model_executions_started: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_executions_completed: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_executions_failed: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_prompt_tokens: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_cached_prompt_tokens: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_cached_output_tokens: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_prefill_tokens: Family<ModelLabel, U64Counter>,
    pub(crate) by_model_generated_tokens: Family<ModelLabel, U64Counter>,

    // `Family::read()` is private in prometheus-client, so we mirror the set
    // of model ids we've ever incremented to power the GetStats RPC.
    seen_models: Mutex<BTreeSet<String>>,
}

impl ExecutorMetrics {
    /// Register all counters with the supplied registry under the `hellas`
    /// (global) and `hellas_model_*` (per-model labelled) prefixes. The
    /// counter handles are shared (`Arc` internally), so clones registered
    /// here observe the same updates as the executor's `Arc<Self>`.
    pub fn register_with(&self, registry: &mut Registry) {
        let sub = registry.sub_registry_with_prefix("hellas");
        for (name, desc, ctr) in [
            (
                "executions_started",
                "Executions started",
                &self.executions_started,
            ),
            (
                "executions_completed",
                "Executions completed",
                &self.executions_completed,
            ),
            (
                "executions_failed",
                "Executions failed",
                &self.executions_failed,
            ),
            ("prompt_tokens", "Total prompt tokens", &self.prompt_tokens),
            (
                "cached_prompt_tokens",
                "Prompt tokens from cache",
                &self.cached_prompt_tokens,
            ),
            (
                "cached_output_tokens",
                "Output tokens from cache",
                &self.cached_output_tokens,
            ),
            (
                "prefill_tokens",
                "Prefill tokens computed",
                &self.prefill_tokens,
            ),
            (
                "generated_tokens",
                "Output tokens generated",
                &self.generated_tokens,
            ),
        ] {
            sub.register(name, desc, ctr.clone());
        }
        let model_sub = sub.sub_registry_with_prefix("model");
        for (name, desc, fam) in [
            (
                "executions_started",
                "Executions started",
                &self.by_model_executions_started,
            ),
            (
                "executions_completed",
                "Executions completed",
                &self.by_model_executions_completed,
            ),
            (
                "executions_failed",
                "Executions failed",
                &self.by_model_executions_failed,
            ),
            (
                "prompt_tokens",
                "Total prompt tokens",
                &self.by_model_prompt_tokens,
            ),
            (
                "cached_prompt_tokens",
                "Prompt tokens from cache",
                &self.by_model_cached_prompt_tokens,
            ),
            (
                "cached_output_tokens",
                "Output tokens from cache",
                &self.by_model_cached_output_tokens,
            ),
            (
                "prefill_tokens",
                "Prefill tokens computed",
                &self.by_model_prefill_tokens,
            ),
            (
                "generated_tokens",
                "Output tokens generated",
                &self.by_model_generated_tokens,
            ),
        ] {
            model_sub.register(name, desc, fam.clone());
        }
    }

    fn note_model(&self, model_id: &str) -> ModelLabel {
        if let Ok(mut seen) = self.seen_models.lock()
            && !seen.contains(model_id)
        {
            seen.insert(model_id.to_string());
        }
        ModelLabel {
            model_id: model_id.to_string(),
        }
    }

    pub(crate) fn record_execution_started(
        &self,
        model_id: &str,
        prompt: u64,
        cached_prompt: u64,
        cached_output: u64,
        prefill: u64,
    ) {
        self.executions_started.inc();
        self.prompt_tokens.inc_by(prompt);
        self.cached_prompt_tokens.inc_by(cached_prompt);
        self.cached_output_tokens.inc_by(cached_output);
        self.prefill_tokens.inc_by(prefill);

        let label = self.note_model(model_id);
        self.by_model_executions_started.get_or_create(&label).inc();
        self.by_model_prompt_tokens
            .get_or_create(&label)
            .inc_by(prompt);
        self.by_model_cached_prompt_tokens
            .get_or_create(&label)
            .inc_by(cached_prompt);
        self.by_model_cached_output_tokens
            .get_or_create(&label)
            .inc_by(cached_output);
        self.by_model_prefill_tokens
            .get_or_create(&label)
            .inc_by(prefill);
    }

    pub(crate) fn record_execution_completed(&self, model_id: &str, generated: u64) {
        self.generated_tokens.inc_by(generated);
        self.executions_completed.inc();
        let label = self.note_model(model_id);
        self.by_model_generated_tokens
            .get_or_create(&label)
            .inc_by(generated);
        self.by_model_executions_completed
            .get_or_create(&label)
            .inc();
    }

    pub(crate) fn record_execution_failed(&self, model_id: &str, generated: u64) {
        self.generated_tokens.inc_by(generated);
        self.executions_failed.inc();
        let label = self.note_model(model_id);
        self.by_model_generated_tokens
            .get_or_create(&label)
            .inc_by(generated);
        self.by_model_executions_failed.get_or_create(&label).inc();
    }

    /// Snapshot the global counters for the GetStats RPC.
    pub(crate) fn global_snapshot(&self) -> hellas_pb::hellas::TokenStats {
        hellas_pb::hellas::TokenStats {
            executions_started: self.executions_started.get(),
            executions_completed: self.executions_completed.get(),
            executions_failed: self.executions_failed.get(),
            prompt_tokens: self.prompt_tokens.get(),
            cached_prompt_tokens: self.cached_prompt_tokens.get(),
            cached_output_tokens: self.cached_output_tokens.get(),
            prefill_tokens: self.prefill_tokens.get(),
            generated_tokens: self.generated_tokens.get(),
        }
    }

    /// Snapshot a per-model row for the GetStats RPC. Only counters that have
    /// observed events for this model are nonzero.
    pub(crate) fn model_snapshot(&self, model_id: &str) -> hellas_pb::hellas::TokenStats {
        let label = ModelLabel {
            model_id: model_id.to_string(),
        };
        hellas_pb::hellas::TokenStats {
            executions_started: self.by_model_executions_started.get_or_create(&label).get(),
            executions_completed: self
                .by_model_executions_completed
                .get_or_create(&label)
                .get(),
            executions_failed: self.by_model_executions_failed.get_or_create(&label).get(),
            prompt_tokens: self.by_model_prompt_tokens.get_or_create(&label).get(),
            cached_prompt_tokens: self
                .by_model_cached_prompt_tokens
                .get_or_create(&label)
                .get(),
            cached_output_tokens: self
                .by_model_cached_output_tokens
                .get_or_create(&label)
                .get(),
            prefill_tokens: self.by_model_prefill_tokens.get_or_create(&label).get(),
            generated_tokens: self.by_model_generated_tokens.get_or_create(&label).get(),
        }
    }

    /// Iterate over all model ids that have ever been observed, for
    /// enumerating per-model rows in the GetStats RPC.
    pub(crate) fn known_model_ids(&self) -> Vec<String> {
        self.seen_models
            .lock()
            .map(|seen| seen.iter().cloned().collect())
            .unwrap_or_default()
    }
}
