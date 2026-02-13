use super::protocol::{
    BlockKey, CodingImpl, ZodaCheckedShard, ZodaCheckingData, ZodaCommitment, ZodaReShard,
    ZodaShard,
};
use crate::trace::Traced;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::sha256::Digest;
use commonware_parallel::Strategy;
use futures::{StreamExt, channel::mpsc};
use std::collections::{BTreeMap, VecDeque};

pub(super) enum Command {
    Reshard {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        shard: ZodaShard,
    },
    Check {
        key: BlockKey,
        commitment: ZodaCommitment,
        checking_data: ZodaCheckingData,
        shard_index: u16,
        shard_hash: Digest,
        reshard: ZodaReShard,
    },
    Cancel {
        key: BlockKey,
    },
}

pub(super) enum Event {
    ReshardDone {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        result: Result<(ZodaCheckingData, ZodaCheckedShard, ZodaReShard), ()>,
    },
    CheckDone {
        key: BlockKey,
        shard_index: u16,
        shard_hash: Digest,
        result: Result<ZodaCheckedShard, ()>,
    },
}

enum Task {
    Reshard {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        shard: ZodaShard,
    },
    Check {
        key: BlockKey,
        commitment: ZodaCommitment,
        checking_data: ZodaCheckingData,
        shard_index: u16,
        shard_hash: Digest,
        reshard: ZodaReShard,
    },
}

pub(super) struct Scheduler<S: Strategy> {
    command_rx: mpsc::UnboundedReceiver<Traced<Command>>,
    event_tx: mpsc::UnboundedSender<Traced<Event>>,
    queue: BTreeMap<BlockKey, VecDeque<Task>>,
    coding_config: CodingConfig,
    strategy: S,
}

impl<S: Strategy> Scheduler<S> {
    pub(super) fn new(
        command_rx: mpsc::UnboundedReceiver<Traced<Command>>,
        event_tx: mpsc::UnboundedSender<Traced<Event>>,
        coding_config: CodingConfig,
        strategy: S,
    ) -> Self {
        Self {
            command_rx,
            event_tx,
            queue: BTreeMap::new(),
            coding_config,
            strategy,
        }
    }

    pub(super) async fn run(mut self) {
        debug!(
            minimum_shards = self.coding_config.minimum_shards,
            extra_shards = self.coding_config.extra_shards,
            "coding scheduler started"
        );
        loop {
            // Block until at least one command arrives (or channel closes).
            if self.queue.is_empty() {
                let Some(traced) = self.command_rx.next().await else {
                    debug!("coding scheduler command channel closed; shutting down");
                    break;
                };
                let (cmd, _span) = traced.into_parts();
                self.enqueue(cmd);
            }

            // Drain all additional commands without blocking.
            while let Ok(Some(traced)) = self.command_rx.try_next() {
                let (cmd, _span) = traced.into_parts();
                self.enqueue(cmd);
            }

            // Flatten tasks from queue in BTreeMap key order (earliest first).
            let tasks: Vec<Task> = self
                .queue
                .values_mut()
                .flat_map(|deque| deque.drain(..))
                .collect();
            self.queue.clear();

            if tasks.is_empty() {
                continue;
            }

            let task_count = tasks.len();
            let _span = debug_span!("coding_worker.batch", task_count).entered();
            trace!(task_count, "processing coding batch");

            // Process all tasks in parallel via strategy.
            let config = self.coding_config;
            let results: Vec<Event> =
                self.strategy
                    .map_collect_vec(tasks, move |task| execute_task(config, task));

            // Send results back.
            for event in results {
                if self.event_tx.unbounded_send(Traced::capture(event)).is_err() {
                    warn!("coding scheduler event channel closed; shutting down");
                    return;
                }
            }
        }
        debug!("coding scheduler stopped");
    }

    fn enqueue(&mut self, cmd: Command) {
        match cmd {
            Command::Reshard {
                key,
                commitment,
                shard_index,
                shard_hash,
                shard,
            } => {
                trace!(
                    digest = ?key.digest,
                    round = ?key.round,
                    shard_index,
                    "enqueued reshard task"
                );
                self.queue
                    .entry(key)
                    .or_default()
                    .push_back(Task::Reshard {
                        key,
                        commitment,
                        shard_index,
                        shard_hash,
                        shard,
                    });
            }
            Command::Check {
                key,
                commitment,
                checking_data,
                shard_index,
                shard_hash,
                reshard,
            } => {
                trace!(
                    digest = ?key.digest,
                    round = ?key.round,
                    shard_index,
                    "enqueued check task"
                );
                self.queue
                    .entry(key)
                    .or_default()
                    .push_back(Task::Check {
                        key,
                        commitment,
                        checking_data,
                        shard_index,
                        shard_hash,
                        reshard,
                    });
            }
            Command::Cancel { key } => {
                let removed = self.queue.remove(&key);
                if removed.is_some() {
                    debug!(
                        digest = ?key.digest,
                        round = ?key.round,
                        "cancelled pending coding tasks for key"
                    );
                }
            }
        }
    }
}

fn execute_task(config: CodingConfig, task: Task) -> Event {
    match task {
        Task::Reshard {
            key,
            commitment,
            shard_index,
            shard_hash,
            shard,
        } => {
            let result =
                CodingImpl::reshard(&config, &commitment, shard_index, shard).map_err(|err| {
                    warn!(
                        digest = ?key.digest,
                        round = ?key.round,
                        shard_index,
                        ?err,
                        "reshard failed"
                    );
                });
            Event::ReshardDone {
                key,
                commitment,
                shard_index,
                shard_hash,
                result,
            }
        }
        Task::Check {
            key,
            commitment,
            checking_data,
            shard_index,
            shard_hash,
            reshard,
        } => {
            let result =
                CodingImpl::check(&config, &commitment, &checking_data, shard_index, reshard)
                    .map_err(|err| {
                        warn!(
                            digest = ?key.digest,
                            round = ?key.round,
                            shard_index,
                            ?err,
                            "check failed"
                        );
                    });
            Event::CheckDone {
                key,
                shard_index,
                shard_hash,
                result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::{coding_config, hash_encoded};
    use commonware_coding::Scheme as CodingScheme;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_parallel::Sequential;

    fn make_key(view: u64) -> BlockKey {
        BlockKey::new(
            Round::new(Epoch::new(1), View::new(view)),
            Sha256::hash(format!("payload-{view}").as_bytes()),
        )
    }

    fn sample_artifacts(
        payload: &[u8],
        validators: u16,
    ) -> (CodingConfig, ZodaCommitment, Vec<ZodaShard>) {
        let config = coding_config(validators);
        let (commitment, shards) =
            CodingImpl::encode(&config, payload, &Sequential).unwrap();
        (config, commitment, shards)
    }

    #[test_log::test(tokio::test)]
    async fn worker_processes_reshard_and_returns_result() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, mut event_rx) = mpsc::unbounded();
        let config = coding_config(6);
        let worker = Scheduler::new(cmd_rx, event_tx, config, Sequential);
        let handle = tokio::spawn(worker.run());

        let (_, commitment, shards) = sample_artifacts(b"test-payload", 6);
        let shard = shards[1].clone();
        let shard_hash = hash_encoded(&shard);
        let key = make_key(1);

        cmd_tx
            .unbounded_send(Traced::capture(Command::Reshard {
                key,
                commitment,
                shard_index: 1,
                shard_hash,
                shard,
            }))
            .unwrap();
        drop(cmd_tx);

        let event = event_rx.next().await.expect("should receive event");
        let (event, _span) = event.into_parts();
        match event {
            Event::ReshardDone {
                key: k,
                shard_index,
                shard_hash: h,
                result,
                ..
            } => {
                assert_eq!(k, key);
                assert_eq!(shard_index, 1);
                assert_eq!(h, shard_hash);
                assert!(result.is_ok());
            }
            _ => panic!("expected ReshardDone"),
        }

        handle.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn worker_processes_check_and_returns_result() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, mut event_rx) = mpsc::unbounded();
        let config = coding_config(6);
        let worker = Scheduler::new(cmd_rx, event_tx, config, Sequential);
        let handle = tokio::spawn(worker.run());

        let (_, commitment, shards) = sample_artifacts(b"check-payload", 6);
        let shard = shards[1].clone();
        let _shard_hash = hash_encoded(&shard);
        let key = make_key(1);

        // First reshard to get checking_data and reshard.
        let (checking_data, _checked, _reshard) =
            CodingImpl::reshard(&config, &commitment, 1, shard).unwrap();

        // Send a reshare from another validator (index 2).
        let other_shard = shards[2].clone();
        let (_, _, other_reshard) =
            CodingImpl::reshard(&config, &commitment, 2, other_shard).unwrap();
        let other_shard_hash = hash_encoded(&other_reshard);

        cmd_tx
            .unbounded_send(Traced::capture(Command::Check {
                key,
                commitment,
                checking_data,
                shard_index: 2,
                shard_hash: other_shard_hash,
                reshard: other_reshard,
            }))
            .unwrap();
        drop(cmd_tx);

        let event = event_rx.next().await.expect("should receive event");
        let (event, _span) = event.into_parts();
        match event {
            Event::CheckDone {
                key: k,
                shard_index,
                shard_hash: h,
                result,
            } => {
                assert_eq!(k, key);
                assert_eq!(shard_index, 2);
                assert_eq!(h, other_shard_hash);
                assert!(result.is_ok());
            }
            _ => panic!("expected CheckDone"),
        }

        handle.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn cancel_removes_pending_tasks() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, mut event_rx) = mpsc::unbounded();
        let config = coding_config(6);
        let worker = Scheduler::new(cmd_rx, event_tx, config, Sequential);
        let handle = tokio::spawn(worker.run());

        let (_, commitment, shards) = sample_artifacts(b"cancel-test", 6);
        let key = make_key(1);
        let shard = shards[1].clone();
        let shard_hash = hash_encoded(&shard);

        // Enqueue then immediately cancel.
        cmd_tx
            .unbounded_send(Traced::capture(Command::Reshard {
                key,
                commitment,
                shard_index: 1,
                shard_hash,
                shard,
            }))
            .unwrap();
        cmd_tx
            .unbounded_send(Traced::capture(Command::Cancel { key }))
            .unwrap();
        drop(cmd_tx);

        handle.await.unwrap();

        // No events should have been produced for the cancelled key.
        assert!(event_rx.try_next().unwrap().is_none());
    }

    #[test_log::test(tokio::test)]
    async fn earlier_keys_are_processed_first() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, mut event_rx) = mpsc::unbounded();
        let config = coding_config(6);
        let worker = Scheduler::new(cmd_rx, event_tx, config, Sequential);
        let handle = tokio::spawn(worker.run());

        let (_, commitment_a, shards_a) = sample_artifacts(b"early-payload", 6);
        let (_, commitment_b, shards_b) = sample_artifacts(b"later-payload", 6);
        let key_early = make_key(1);
        let key_late = make_key(5);

        let shard_b = shards_b[1].clone();
        let shard_a = shards_a[1].clone();

        // Send later key first, then earlier key.
        cmd_tx
            .unbounded_send(Traced::capture(Command::Reshard {
                key: key_late,
                commitment: commitment_b,
                shard_index: 1,
                shard_hash: hash_encoded(&shard_b),
                shard: shard_b,
            }))
            .unwrap();
        cmd_tx
            .unbounded_send(Traced::capture(Command::Reshard {
                key: key_early,
                commitment: commitment_a,
                shard_index: 1,
                shard_hash: hash_encoded(&shard_a),
                shard: shard_a,
            }))
            .unwrap();
        drop(cmd_tx);

        // With Sequential strategy, tasks are processed in order. The BTreeMap
        // orders by key, so key_early (view 1) should come before key_late (view 5).
        let first = event_rx.next().await.expect("first event");
        let (first, _) = first.into_parts();
        let first_key = match &first {
            Event::ReshardDone { key, .. } => *key,
            _ => panic!("expected ReshardDone"),
        };

        let second = event_rx.next().await.expect("second event");
        let (second, _) = second.into_parts();
        let second_key = match &second {
            Event::ReshardDone { key, .. } => *key,
            _ => panic!("expected ReshardDone"),
        };

        assert_eq!(first_key, key_early);
        assert_eq!(second_key, key_late);

        handle.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn worker_exits_when_command_channel_closes() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, _event_rx) = mpsc::unbounded();
        let config = coding_config(6);
        let worker = Scheduler::new(cmd_rx, event_tx, config, Sequential);
        let handle = tokio::spawn(worker.run());

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn reshard_with_wrong_commitment_returns_error() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, mut event_rx) = mpsc::unbounded();
        let config = coding_config(6);
        let worker = Scheduler::new(cmd_rx, event_tx, config, Sequential);
        let handle = tokio::spawn(worker.run());

        let (_, commitment_a, _) = sample_artifacts(b"payload-a", 6);
        let (_, _commitment_b, shards_b) = sample_artifacts(b"payload-b", 6);
        let key = make_key(1);
        let shard = shards_b[1].clone();

        // Send shard from payload-b with commitment from payload-a.
        cmd_tx
            .unbounded_send(Traced::capture(Command::Reshard {
                key,
                commitment: commitment_a,
                shard_index: 1,
                shard_hash: hash_encoded(&shard),
                shard,
            }))
            .unwrap();
        drop(cmd_tx);

        let event = event_rx.next().await.expect("should receive event");
        let (event, _) = event.into_parts();
        match event {
            Event::ReshardDone { result, .. } => {
                assert!(result.is_err());
            }
            _ => panic!("expected ReshardDone"),
        }

        handle.await.unwrap();
    }
}
