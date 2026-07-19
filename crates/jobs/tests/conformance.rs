use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use futures::executor::block_on;
use hellas_jobs::{
    JobError, JobId, JobResult, JobSpec, JobState, LocalJobRepository, LogicalInstant, ManualClock,
    MemoryJobRepository, MemoryJobRepositoryBacking, WorkerId,
};

const LEASE: Duration = Duration::from_secs(10);

fn spec(value: u8) -> JobSpec {
    JobSpec::from([value].as_slice())
}

fn result(value: u8) -> JobResult {
    JobResult::from([value].as_slice())
}

fn worker(value: u8) -> WorkerId {
    WorkerId::from([value; 32])
}

fn memory_repository(
    capacity: usize,
) -> (
    MemoryJobRepository<ManualClock>,
    MemoryJobRepositoryBacking,
    ManualClock,
) {
    let clock = ManualClock::new(LogicalInstant::ZERO);
    let repository = MemoryJobRepository::new(capacity, LEASE, clock.clone());
    let backing = repository.backing();
    (repository, backing, clock)
}

async fn assert_idempotent_submit_and_complete<R>(repository: &R)
where
    R: LocalJobRepository,
{
    let submitted = spec(1);
    let id = repository.submit(submitted.clone()).await.unwrap();
    let duplicate_id = repository.submit(submitted).await.unwrap();

    assert_eq!(id, duplicate_id);
    assert_eq!(repository.list().await.unwrap().len(), 1);

    let (_, epoch) = repository.claim(id, worker(1)).await.unwrap();
    let completed = result(9);
    repository
        .complete(id, epoch, completed.clone())
        .await
        .unwrap();
    repository.complete(id, epoch, completed).await.unwrap();

    assert_eq!(
        repository.complete(id, epoch, result(10)).await,
        Err(JobError::Conflict)
    );
}

async fn assert_fencing_and_first_write_wins<R>(repository: &R, clock: &ManualClock)
where
    R: LocalJobRepository,
{
    let id = repository.submit(spec(1)).await.unwrap();
    let (_, old_epoch) = repository.claim(id, worker(1)).await.unwrap();
    clock.advance(LEASE);
    let (_, new_epoch) = repository.claim(id, worker(2)).await.unwrap();

    assert!(new_epoch > old_epoch);
    assert_eq!(
        repository.complete(id, old_epoch, result(1)).await,
        Err(JobError::FencedOut)
    );

    repository.complete(id, new_epoch, result(2)).await.unwrap();
    assert_eq!(
        repository.complete(id, new_epoch, result(3)).await,
        Err(JobError::Conflict)
    );
    assert_eq!(
        repository.get(id).await.unwrap().unwrap().state,
        JobState::Done(result(2))
    );
}

async fn assert_crash_reconcile<R, Reopen>(repository: R, reopen: Reopen, clock: &ManualClock)
where
    R: LocalJobRepository,
    Reopen: FnOnce() -> R,
{
    let done_id = repository.submit(spec(1)).await.unwrap();
    let (_, done_epoch) = repository.claim(done_id, worker(1)).await.unwrap();
    repository
        .complete(done_id, done_epoch, result(1))
        .await
        .unwrap();

    let running_id = repository.submit(spec(2)).await.unwrap();
    let (_, old_epoch) = repository.claim(running_id, worker(1)).await.unwrap();
    let uncommitted_spec = spec(3);
    let uncommitted_id = JobId::from_spec(&uncommitted_spec);
    drop(repository.submit(uncommitted_spec));
    drop(repository);
    clock.advance(LEASE);

    let reopened = reopen();
    assert_eq!(reopened.get(uncommitted_id).await.unwrap(), None);
    assert_eq!(
        reopened.get(done_id).await.unwrap().unwrap().state,
        JobState::Done(result(1))
    );
    let (_, new_epoch) = reopened.claim(running_id, worker(2)).await.unwrap();
    assert!(new_epoch > old_epoch);
}

async fn assert_lease_expiry_takeover<R>(repository: &R, clock: &ManualClock)
where
    R: LocalJobRepository,
{
    let id = repository.submit(spec(1)).await.unwrap();
    let (_, epoch_a) = repository.claim(id, worker(1)).await.unwrap();
    assert_eq!(
        repository.claim(id, worker(2)).await,
        Err(JobError::Conflict)
    );

    clock.advance(LEASE / 2);
    repository.heartbeat(id, epoch_a).await.unwrap();
    clock.advance(LEASE / 2);
    assert_eq!(
        repository.claim(id, worker(2)).await,
        Err(JobError::Conflict)
    );

    clock.advance(LEASE / 2);
    let (_, epoch_b) = repository.claim(id, worker(2)).await.unwrap();
    assert!(epoch_b > epoch_a);
    assert_eq!(
        repository.heartbeat(id, epoch_a).await,
        Err(JobError::FencedOut)
    );
    assert_eq!(
        repository.complete(id, epoch_a, result(1)).await,
        Err(JobError::FencedOut)
    );
}

async fn assert_total_ordering<R>(repository: &R)
where
    R: LocalJobRepository,
{
    for value in [3, 1, 4, 2] {
        repository.submit(spec(value)).await.unwrap();
    }

    let first = repository.list().await.unwrap();
    let second = repository.list().await.unwrap();
    assert_eq!(first, second);
    assert!(first.windows(2).all(|jobs| {
        let left = &jobs[0];
        let right = &jobs[1];
        (left.seq, left.id) < (right.seq, right.id)
    }));
}

async fn assert_capacity<R>(repository: &R)
where
    R: LocalJobRepository,
{
    let first = spec(1);
    let id = repository.submit(first.clone()).await.unwrap();
    assert_eq!(repository.submit(spec(2)).await, Err(JobError::RepoFull));
    assert_eq!(repository.submit(first).await, Ok(id));
}

fn assert_exclusive_claim<R>(repository: R)
where
    R: LocalJobRepository + Clone + Send + Sync + 'static,
{
    let id = block_on(repository.submit(spec(1))).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();

    for worker_id in [worker(1), worker(2)] {
        let repository = repository.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            block_on(repository.claim(id, worker_id))
        }));
    }

    barrier.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(JobError::Conflict))
            .count(),
        1
    );
}

#[test]
fn memory_exclusive_claim() {
    let (repository, _, _) = memory_repository(1);
    assert_exclusive_claim(repository);
}

#[test]
fn memory_fencing_and_first_write_wins() {
    let (repository, _, clock) = memory_repository(1);
    block_on(assert_fencing_and_first_write_wins(&repository, &clock));
}

#[test]
fn memory_idempotent_submit_and_complete() {
    let (repository, _, _) = memory_repository(1);
    block_on(assert_idempotent_submit_and_complete(&repository));
}

#[test]
fn memory_crash_reconcile() {
    let (repository, backing, clock) = memory_repository(2);
    let reopen_clock = clock.clone();
    block_on(assert_crash_reconcile(
        repository,
        move || MemoryJobRepository::from_backing(backing, LEASE, reopen_clock),
        &clock,
    ));
}

#[test]
fn memory_lease_expiry_takeover() {
    let (repository, _, clock) = memory_repository(1);
    block_on(assert_lease_expiry_takeover(&repository, &clock));
}

#[test]
fn memory_total_ordering() {
    let (repository, _, _) = memory_repository(4);
    block_on(assert_total_ordering(&repository));
}

#[test]
fn memory_capacity() {
    let (repository, _, _) = memory_repository(1);
    block_on(assert_capacity(&repository));
}
