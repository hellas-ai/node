use commonware_runtime::Metrics;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::atomic::AtomicI64;

pub(super) fn gauge_set_len(gauge: &Gauge<i64, AtomicI64>, len: usize) {
    gauge.set(i64::try_from(len).unwrap_or(i64::MAX));
}

#[derive(Clone)]
pub(super) struct ApplicationMetrics {
    pub(crate) external_events_total: Counter,
    pub(crate) finalization_notices_total: Counter,
    pub(crate) shard_messages_received_total: Counter,
    pub(crate) persistence_dispatch_total: Counter,
    pub(crate) persistence_ack_total: Counter,
    pub(crate) persistence_ack_unexpected_total: Counter,
    pub(crate) genesis_anchor_seeded_total: Counter,
    pub(crate) inflight_persistence: Gauge<i64, AtomicI64>,
}

impl ApplicationMetrics {
    pub(super) fn register<E: Metrics>(context: &E) -> Self {
        let metrics = Self {
            external_events_total: Counter::default(),
            finalization_notices_total: Counter::default(),
            shard_messages_received_total: Counter::default(),
            persistence_dispatch_total: Counter::default(),
            persistence_ack_total: Counter::default(),
            persistence_ack_unexpected_total: Counter::default(),
            genesis_anchor_seeded_total: Counter::default(),
            inflight_persistence: Gauge::default(),
        };

        context.register(
            "external_events_total",
            "external events processed by app actor",
            metrics.external_events_total.clone(),
        );
        context.register(
            "finalization_notices_total",
            "finalization notices received by app actor",
            metrics.finalization_notices_total.clone(),
        );
        context.register(
            "shard_messages_received_total",
            "shard messages received by app actor mailbox",
            metrics.shard_messages_received_total.clone(),
        );
        context.register(
            "persistence_dispatch_total",
            "finalization persistence intents dispatched",
            metrics.persistence_dispatch_total.clone(),
        );
        context.register(
            "persistence_ack_total",
            "persistence acknowledgements processed",
            metrics.persistence_ack_total.clone(),
        );
        context.register(
            "persistence_ack_unexpected_total",
            "persistence acknowledgements for non-inflight payloads",
            metrics.persistence_ack_unexpected_total.clone(),
        );
        context.register(
            "genesis_anchor_seeded_total",
            "genesis anchor roots successfully seeded",
            metrics.genesis_anchor_seeded_total.clone(),
        );
        context.register(
            "inflight_persistence",
            "whether a persistence intent is currently inflight (0/1)",
            metrics.inflight_persistence.clone(),
        );

        metrics.inflight_persistence.set(0);
        metrics
    }
}

#[derive(Clone)]
pub(super) struct CoreMetrics {
    pub(crate) propose_total: Counter,
    pub(crate) propose_missing_anchor_total: Counter,
    pub(crate) verify_requests_total: Counter,
    pub(crate) verify_deferred_dependency_total: Counter,
    pub(crate) verify_deferred_anchor_total: Counter,
    pub(crate) verify_valid_total: Counter,
    pub(crate) verify_invalid_total: Counter,
    pub(crate) anchor_mismatch_total: Counter,
    pub(crate) waiter_keys: Gauge<i64, AtomicI64>,
    pub(crate) waiter_total: Gauge<i64, AtomicI64>,
    pub(crate) mempool_size: Gauge<i64, AtomicI64>,
    pub(crate) pending_payloads: Gauge<i64, AtomicI64>,
    pub(crate) persisted_roots: Gauge<i64, AtomicI64>,
    pub(crate) unpersisted_finalizations: Gauge<i64, AtomicI64>,
}

impl CoreMetrics {
    pub(super) fn register<E: Metrics>(context: &E) -> Self {
        let metrics = Self {
            propose_total: Counter::default(),
            propose_missing_anchor_total: Counter::default(),
            verify_requests_total: Counter::default(),
            verify_deferred_dependency_total: Counter::default(),
            verify_deferred_anchor_total: Counter::default(),
            verify_valid_total: Counter::default(),
            verify_invalid_total: Counter::default(),
            anchor_mismatch_total: Counter::default(),
            waiter_keys: Gauge::default(),
            waiter_total: Gauge::default(),
            mempool_size: Gauge::default(),
            pending_payloads: Gauge::default(),
            persisted_roots: Gauge::default(),
            unpersisted_finalizations: Gauge::default(),
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
            "verify requests processed by core",
            metrics.verify_requests_total.clone(),
        );
        context.register(
            "verify_deferred_dependency_total",
            "verify deferrals due to missing payload/parent execution dependency",
            metrics.verify_deferred_dependency_total.clone(),
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
            "waiter_keys",
            "current number of waiter keys",
            metrics.waiter_keys.clone(),
        );
        context.register(
            "waiter_total",
            "current number of deferred waiters",
            metrics.waiter_total.clone(),
        );
        context.register(
            "mempool_size",
            "current number of transactions in mempool",
            metrics.mempool_size.clone(),
        );
        context.register(
            "pending_payloads",
            "current number of pending proposal payloads",
            metrics.pending_payloads.clone(),
        );
        context.register(
            "persisted_roots",
            "current number of cached persisted roots",
            metrics.persisted_roots.clone(),
        );
        context.register(
            "unpersisted_finalizations",
            "current number of finalized payloads awaiting persistence",
            metrics.unpersisted_finalizations.clone(),
        );

        metrics.waiter_keys.set(0);
        metrics.waiter_total.set(0);
        metrics.mempool_size.set(0);
        metrics.pending_payloads.set(0);
        metrics.persisted_roots.set(0);
        metrics.unpersisted_finalizations.set(0);
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
    pub(crate) staged_pending: Gauge<i64, AtomicI64>,
    pub(crate) finalization_cache_entries: Gauge<i64, AtomicI64>,
    pub(crate) finalization_cache_evictions_total: Counter,
    pub(crate) payload_cache_evictions_total: Counter,
    pub(crate) anchor_history_evictions_total: Counter,
}

impl PersistenceMetrics {
    pub(super) fn register<E: Metrics>(context: &E) -> Self {
        let metrics = Self {
            worker_ready_total: Counter::default(),
            enqueue_commands_total: Counter::default(),
            persist_attempt_total: Counter::default(),
            persist_success_total: Counter::default(),
            persist_failure_total: Counter::default(),
            staged_pending: Gauge::default(),
            finalization_cache_entries: Gauge::default(),
            finalization_cache_evictions_total: Counter::default(),
            payload_cache_evictions_total: Counter::default(),
            anchor_history_evictions_total: Counter::default(),
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
            "staged_pending",
            "whether a persistence intent is staged pending queue flush (0/1)",
            metrics.staged_pending.clone(),
        );
        context.register(
            "finalization_cache_entries",
            "current number of volatile finalization cache entries",
            metrics.finalization_cache_entries.clone(),
        );

        context.register(
            "finalization_cache_evictions_total",
            "volatile finalization cache evictions due to capacity",
            metrics.finalization_cache_evictions_total.clone(),
        );
        context.register(
            "payload_cache_evictions_total",
            "volatile payload cache evictions due to capacity",
            metrics.payload_cache_evictions_total.clone(),
        );
        context.register(
            "anchor_history_evictions_total",
            "anchor history evictions due to capacity",
            metrics.anchor_history_evictions_total.clone(),
        );

        metrics.staged_pending.set(0);
        metrics.finalization_cache_entries.set(0);
        metrics
    }
}
