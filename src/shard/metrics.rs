use commonware_runtime::Metrics;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::atomic::AtomicI64;

#[derive(Clone)]
pub(crate) struct ShardMetrics {
    pub(crate) active_recoveries: Gauge<i64, AtomicI64>,
    pub(crate) known_keys: Gauge<i64, AtomicI64>,
    pub(crate) pre_leader_keys: Gauge<i64, AtomicI64>,
    pub(crate) recovery_success_total: Counter,
    pub(crate) recovery_failed_total: Counter,
    pub(crate) recovery_evictions_total: Counter,
    pub(crate) coding_tasks_dispatched_total: Counter,
    pub(crate) coding_tasks_completed_total: Counter,
    pub(crate) scheduler_queue_depth: Gauge<i64, AtomicI64>,
    pub(crate) scheduler_batch_duration_ns: Gauge<i64, AtomicI64>,
}

impl ShardMetrics {
    pub(crate) fn register<E: Metrics>(context: &E) -> Self {
        let metrics = Self {
            active_recoveries: Gauge::default(),
            known_keys: Gauge::default(),
            pre_leader_keys: Gauge::default(),
            recovery_success_total: Counter::default(),
            recovery_failed_total: Counter::default(),
            recovery_evictions_total: Counter::default(),
            coding_tasks_dispatched_total: Counter::default(),
            coding_tasks_completed_total: Counter::default(),
            scheduler_queue_depth: Gauge::default(),
            scheduler_batch_duration_ns: Gauge::default(),
        };

        context.register(
            "active_recoveries",
            "current number of active shard recovery entries",
            metrics.active_recoveries.clone(),
        );
        context.register(
            "known_keys",
            "current number of known block keys in recovery machine",
            metrics.known_keys.clone(),
        );
        context.register(
            "pre_leader_keys",
            "current number of pre-leader buffered block keys",
            metrics.pre_leader_keys.clone(),
        );
        context.register(
            "recovery_success_total",
            "successful shard recovery reconstructions",
            metrics.recovery_success_total.clone(),
        );
        context.register(
            "recovery_failed_total",
            "failed shard recovery attempts (evicted or decode failure)",
            metrics.recovery_failed_total.clone(),
        );
        context.register(
            "recovery_evictions_total",
            "recovery entries evicted to make room for new recoveries",
            metrics.recovery_evictions_total.clone(),
        );
        context.register(
            "coding_tasks_dispatched_total",
            "coding scheduler tasks dispatched (reshard + check)",
            metrics.coding_tasks_dispatched_total.clone(),
        );
        context.register(
            "coding_tasks_completed_total",
            "coding scheduler tasks completed",
            metrics.coding_tasks_completed_total.clone(),
        );
        context.register(
            "scheduler_queue_depth",
            "current number of tasks pending in coding scheduler queue",
            metrics.scheduler_queue_depth.clone(),
        );
        context.register(
            "scheduler_batch_duration_ns",
            "duration of last coding scheduler batch in nanoseconds",
            metrics.scheduler_batch_duration_ns.clone(),
        );

        metrics.active_recoveries.set(0);
        metrics.known_keys.set(0);
        metrics.pre_leader_keys.set(0);
        metrics.scheduler_queue_depth.set(0);
        metrics.scheduler_batch_duration_ns.set(0);
        metrics
    }

    /// Create unregistered metrics for tests.
    #[cfg(test)]
    pub(crate) fn test_default() -> Self {
        Self {
            active_recoveries: Gauge::default(),
            known_keys: Gauge::default(),
            pre_leader_keys: Gauge::default(),
            recovery_success_total: Counter::default(),
            recovery_failed_total: Counter::default(),
            recovery_evictions_total: Counter::default(),
            coding_tasks_dispatched_total: Counter::default(),
            coding_tasks_completed_total: Counter::default(),
            scheduler_queue_depth: Gauge::default(),
            scheduler_batch_duration_ns: Gauge::default(),
        }
    }
}
