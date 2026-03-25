use commonware_runtime::Metrics;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::atomic::AtomicI64;

#[derive(Clone)]
pub(super) struct ApplicationMetrics {
    pub(crate) propose_total: Counter,
    pub(crate) propose_missing_anchor_total: Counter,
    pub(crate) verify_requests_total: Counter,
    pub(crate) verify_deferred_anchor_total: Counter,
    pub(crate) verify_valid_total: Counter,
    pub(crate) verify_invalid_total: Counter,
    pub(crate) anchor_mismatch_total: Counter,
    pub(crate) persistence_dispatch_total: Counter,
    pub(crate) persistence_ack_total: Counter,
    pub(crate) persistence_ack_unexpected_total: Counter,
    pub(crate) genesis_anchor_seeded_total: Counter,
    pub(crate) mempool_size: Gauge<i64, AtomicI64>,
    pub(crate) persisted_roots: Gauge<i64, AtomicI64>,
    pub(crate) inflight_persistence: Gauge<i64, AtomicI64>,
    pub(crate) finalization_timestamp_drift: Gauge<i64, AtomicI64>,
    pub(crate) validation_timestamp_drift: Gauge<i64, AtomicI64>,
}

impl ApplicationMetrics {
    pub(super) fn register<E: Metrics>(context: &E) -> Self {
        let metrics = Self {
            propose_total: Counter::default(),
            propose_missing_anchor_total: Counter::default(),
            verify_requests_total: Counter::default(),
            verify_deferred_anchor_total: Counter::default(),
            verify_valid_total: Counter::default(),
            verify_invalid_total: Counter::default(),
            anchor_mismatch_total: Counter::default(),
            persistence_dispatch_total: Counter::default(),
            persistence_ack_total: Counter::default(),
            persistence_ack_unexpected_total: Counter::default(),
            genesis_anchor_seeded_total: Counter::default(),
            mempool_size: Gauge::default(),
            persisted_roots: Gauge::default(),
            inflight_persistence: Gauge::default(),
            finalization_timestamp_drift: Gauge::default(),
            validation_timestamp_drift: Gauge::default(),
        };

        context.register(
            "propose_total",
            "proposal attempts",
            metrics.propose_total.clone(),
        );
        context.register(
            "propose_missing_anchor_total",
            "proposal aborts due to missing persisted anchor",
            metrics.propose_missing_anchor_total.clone(),
        );
        context.register(
            "verify_requests_total",
            "verify requests processed by application",
            metrics.verify_requests_total.clone(),
        );
        context.register(
            "verify_deferred_anchor_total",
            "verify deferrals due to missing persisted anchor root",
            metrics.verify_deferred_anchor_total.clone(),
        );
        context.register(
            "verify_valid_total",
            "verify requests accepted as valid",
            metrics.verify_valid_total.clone(),
        );
        context.register(
            "verify_invalid_total",
            "verify requests rejected as invalid",
            metrics.verify_invalid_total.clone(),
        );
        context.register(
            "anchor_mismatch_total",
            "verify failures due to anchor root mismatch",
            metrics.anchor_mismatch_total.clone(),
        );
        context.register(
            "persistence_dispatch_total",
            "finalized blocks dispatched to persistence",
            metrics.persistence_dispatch_total.clone(),
        );
        context.register(
            "persistence_ack_total",
            "persistence acknowledgements processed",
            metrics.persistence_ack_total.clone(),
        );
        context.register(
            "persistence_ack_unexpected_total",
            "persistence acknowledgements for unexpected blocks",
            metrics.persistence_ack_unexpected_total.clone(),
        );
        context.register(
            "genesis_anchor_seeded_total",
            "genesis anchor roots successfully seeded",
            metrics.genesis_anchor_seeded_total.clone(),
        );
        context.register(
            "mempool_size",
            "current number of transactions in the mempool",
            metrics.mempool_size.clone(),
        );
        context.register(
            "persisted_roots",
            "current number of cached persisted roots",
            metrics.persisted_roots.clone(),
        );
        context.register(
            "inflight_persistence",
            "whether a finalized block is currently waiting on persistence (0/1)",
            metrics.inflight_persistence.clone(),
        );
        context.register(
            "finalization_timestamp_drift",
            "signed ms drift between wall clock and persisted block timestamp (now - block_ts)",
            metrics.finalization_timestamp_drift.clone(),
        );
        context.register(
            "validation_timestamp_drift",
            "signed ms drift between wall clock and validated block timestamp (now - block_ts)",
            metrics.validation_timestamp_drift.clone(),
        );

        metrics.mempool_size.set(0);
        metrics.persisted_roots.set(0);
        metrics.inflight_persistence.set(0);
        metrics.finalization_timestamp_drift.set(0);
        metrics.validation_timestamp_drift.set(0);
        metrics
    }
}

#[derive(Clone)]
pub(super) struct PersistenceMetrics {
    pub(crate) worker_ready_total: Counter,
    pub(crate) enqueue_commands_total: Counter,
    pub(crate) persist_attempt_total: Counter,
    pub(crate) persist_success_total: Counter,
    pub(crate) persist_failure_total: Counter,
    pub(crate) anchor_history_entries: Gauge<i64, AtomicI64>,
    pub(crate) anchor_history_evictions_total: Counter,
    pub(crate) queue_depth: Gauge<i64, AtomicI64>,
    pub(crate) utxo_committed_position: Gauge<i64, AtomicI64>,
}

impl PersistenceMetrics {
    pub(super) fn register<E: Metrics>(context: &E) -> Self {
        let metrics = Self {
            worker_ready_total: Counter::default(),
            enqueue_commands_total: Counter::default(),
            persist_attempt_total: Counter::default(),
            persist_success_total: Counter::default(),
            persist_failure_total: Counter::default(),
            anchor_history_entries: Gauge::default(),
            anchor_history_evictions_total: Counter::default(),
            queue_depth: Gauge::default(),
            utxo_committed_position: Gauge::default(),
        };

        context.register(
            "worker_ready_total",
            "persistence worker successful startup notifications",
            metrics.worker_ready_total.clone(),
        );
        context.register(
            "enqueue_commands_total",
            "enqueue commands received by persistence worker",
            metrics.enqueue_commands_total.clone(),
        );
        context.register(
            "persist_attempt_total",
            "persistence apply attempts",
            metrics.persist_attempt_total.clone(),
        );
        context.register(
            "persist_success_total",
            "successful persistence apply operations",
            metrics.persist_success_total.clone(),
        );
        context.register(
            "persist_failure_total",
            "failed persistence apply operations",
            metrics.persist_failure_total.clone(),
        );
        context.register(
            "anchor_history_entries",
            "current number of persisted anchor history entries",
            metrics.anchor_history_entries.clone(),
        );
        context.register(
            "anchor_history_evictions_total",
            "evicted persisted anchor history entries",
            metrics.anchor_history_evictions_total.clone(),
        );
        context.register(
            "queue_depth",
            "durable persistence queue depth",
            metrics.queue_depth.clone(),
        );
        context.register(
            "utxo_committed_position",
            "last committed persistence queue position",
            metrics.utxo_committed_position.clone(),
        );

        metrics.anchor_history_entries.set(0);
        metrics.queue_depth.set(0);
        metrics.utxo_committed_position.set(-1);
        metrics
    }
}
