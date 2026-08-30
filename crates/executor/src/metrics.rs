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
pub struct ExecutionLabel {
    pub scheme: String,
    pub name: String,
}

/// Single source of truth for executor counters. Each field is a prometheus
/// counter that can be both registered for scraping and read directly via
/// [`Counter::get`] (used by the GetStats RPC path).
#[derive(Default)]
pub struct ExecutorMetrics {
    pub(crate) evaluate_executions_started: U64Counter,
    pub(crate) evaluate_executions_completed: U64Counter,
    pub(crate) evaluate_executions_failed: U64Counter,
    pub(crate) evaluate_prompt_tokens: U64Counter,
    pub(crate) evaluate_prefill_tokens: U64Counter,
    pub(crate) evaluate_generated_tokens: U64Counter,

    pub(crate) by_execution_started: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_completed: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_failed: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_prompt_tokens: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_prefill_tokens: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_generated_tokens: Family<ExecutionLabel, U64Counter>,

    // `Family::read()` is private in prometheus-client, so we mirror the set
    // of execution labels we've ever incremented to power the GetStats RPC.
    seen_executions: Mutex<BTreeSet<(String, String)>>,
}

impl ExecutorMetrics {
    /// Register all counters with the supplied registry under the
    /// `hellas_evaluate_*` and `hellas_execution_*` prefixes. The
    /// counter handles are shared (`Arc` internally), so clones registered
    /// here observe the same updates as the executor's `Arc<Self>`.
    pub fn register_with(&self, registry: &mut Registry) {
        let sub = registry.sub_registry_with_prefix("hellas");
        for (name, desc, ctr) in [
            (
                "evaluate_executions_started",
                "Catena evaluate executions started",
                &self.evaluate_executions_started,
            ),
            (
                "evaluate_executions_completed",
                "Catena evaluate executions completed",
                &self.evaluate_executions_completed,
            ),
            (
                "evaluate_executions_failed",
                "Catena evaluate executions failed",
                &self.evaluate_executions_failed,
            ),
            (
                "evaluate_prompt_tokens",
                "Catena evaluate prompt tokens",
                &self.evaluate_prompt_tokens,
            ),
            (
                "evaluate_prefill_tokens",
                "Catena evaluate prefill tokens computed",
                &self.evaluate_prefill_tokens,
            ),
            (
                "evaluate_generated_tokens",
                "Catena evaluate output tokens generated",
                &self.evaluate_generated_tokens,
            ),
        ] {
            sub.register(name, desc, ctr.clone());
        }
        let execution_sub = sub.sub_registry_with_prefix("execution");
        for (name, desc, fam) in [
            (
                "executions_started",
                "Executions started",
                &self.by_execution_started,
            ),
            (
                "executions_completed",
                "Executions completed",
                &self.by_execution_completed,
            ),
            (
                "executions_failed",
                "Executions failed",
                &self.by_execution_failed,
            ),
            (
                "prompt_tokens",
                "Total prompt tokens",
                &self.by_execution_prompt_tokens,
            ),
            (
                "prefill_tokens",
                "Prefill tokens computed",
                &self.by_execution_prefill_tokens,
            ),
            (
                "generated_tokens",
                "Output tokens generated",
                &self.by_execution_generated_tokens,
            ),
        ] {
            execution_sub.register(name, desc, fam.clone());
        }
    }

    fn note_execution(&self, scheme: &str, name: &str) -> ExecutionLabel {
        let key = (scheme.to_string(), name.to_string());
        if let Ok(mut seen) = self.seen_executions.lock()
            && !seen.contains(&key)
        {
            seen.insert(key.clone());
        }
        ExecutionLabel {
            scheme: key.0,
            name: key.1,
        }
    }

    pub(crate) fn record_execution_started(
        &self,
        scheme: &str,
        name: &str,
        prompt: u64,
        prefill: u64,
    ) {
        let label = self.note_execution(scheme, name);
        self.by_execution_started.get_or_create(&label).inc();
        if scheme == "evaluate" {
            self.evaluate_executions_started.inc();
            self.evaluate_prompt_tokens.inc_by(prompt);
            self.evaluate_prefill_tokens.inc_by(prefill);
            self.by_execution_prompt_tokens
                .get_or_create(&label)
                .inc_by(prompt);
            self.by_execution_prefill_tokens
                .get_or_create(&label)
                .inc_by(prefill);
        }
    }

    pub(crate) fn record_execution_completed(&self, scheme: &str, name: &str, generated: u64) {
        let label = self.note_execution(scheme, name);
        self.by_execution_completed.get_or_create(&label).inc();
        if scheme == "evaluate" {
            self.evaluate_generated_tokens.inc_by(generated);
            self.evaluate_executions_completed.inc();
            self.by_execution_generated_tokens
                .get_or_create(&label)
                .inc_by(generated);
        }
    }

    pub(crate) fn record_execution_failed(&self, scheme: &str, name: &str, generated: u64) {
        let label = self.note_execution(scheme, name);
        self.by_execution_failed.get_or_create(&label).inc();
        if scheme == "evaluate" {
            self.evaluate_generated_tokens.inc_by(generated);
            self.evaluate_executions_failed.inc();
            self.by_execution_generated_tokens
                .get_or_create(&label)
                .inc_by(generated);
        }
    }

    /// Snapshot Catena evaluate counters for the Courtesy GetStats RPC.
    pub(crate) fn global_snapshot(&self) -> hellas_rpc::pb::courtesy::TokenStats {
        hellas_rpc::pb::courtesy::TokenStats {
            executions_started: self.evaluate_executions_started.get(),
            executions_completed: self.evaluate_executions_completed.get(),
            executions_failed: self.evaluate_executions_failed.get(),
            prompt_tokens: self.evaluate_prompt_tokens.get(),
            prefill_tokens: self.evaluate_prefill_tokens.get(),
            generated_tokens: self.evaluate_generated_tokens.get(),
        }
    }

    /// Snapshot one scheme/name row. Only counters that have observed events
    /// for this exact label are nonzero.
    pub(crate) fn execution_snapshot(
        &self,
        scheme: &str,
        name: &str,
    ) -> hellas_rpc::pb::courtesy::TokenStats {
        let label = ExecutionLabel {
            scheme: scheme.to_string(),
            name: name.to_string(),
        };
        let value = |family: &Family<ExecutionLabel, U64Counter>| {
            family.get(&label).map(|counter| counter.get()).unwrap_or(0)
        };
        hellas_rpc::pb::courtesy::TokenStats {
            executions_started: value(&self.by_execution_started),
            executions_completed: value(&self.by_execution_completed),
            executions_failed: value(&self.by_execution_failed),
            prompt_tokens: value(&self.by_execution_prompt_tokens),
            prefill_tokens: value(&self.by_execution_prefill_tokens),
            generated_tokens: value(&self.by_execution_generated_tokens),
        }
    }

    /// Iterate over names observed for one scheme. Fetch labels therefore
    /// cannot appear in Courtesy's Catena-package rows.
    pub(crate) fn known_execution_names(&self, scheme: &str) -> Vec<String> {
        self.seen_executions
            .lock()
            .map(|seen| {
                seen.iter()
                    .filter(|(seen_scheme, _)| seen_scheme == scheme)
                    .map(|(_, name)| name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutorMetrics;

    #[test]
    fn courtesy_totals_are_evaluate_tokens_not_fetch_units() {
        let metrics = ExecutorMetrics::default();
        metrics.record_execution_started("fetch", "codex/responses", 0, 0);
        metrics.record_execution_completed("fetch", "codex/responses", 99);

        let empty = metrics.global_snapshot();
        assert_eq!(empty.executions_started, 0);
        assert_eq!(empty.executions_completed, 0);
        assert_eq!(empty.generated_tokens, 0);

        metrics.record_execution_started("evaluate", "smollm2-135m", 3, 3);
        metrics.record_execution_completed("evaluate", "smollm2-135m", 2);
        let evaluate = metrics.global_snapshot();
        assert_eq!(evaluate.executions_started, 1);
        assert_eq!(evaluate.executions_completed, 1);
        assert_eq!(evaluate.prompt_tokens, 3);
        assert_eq!(evaluate.prefill_tokens, 3);
        assert_eq!(evaluate.generated_tokens, 2);
    }

    #[test]
    fn reading_an_unknown_label_does_not_allocate_it() {
        let metrics = ExecutorMetrics::default();
        let snapshot = metrics.execution_snapshot("evaluate", "attacker-input");
        assert_eq!(snapshot.executions_started, 0);
        assert!(metrics.known_execution_names("evaluate").is_empty());
    }
}
