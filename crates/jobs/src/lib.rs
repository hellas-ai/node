#![forbid(unsafe_code)]

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JobSpec(Vec<u8>);

impl JobSpec {
    pub fn new(canonical_bytes: impl Into<Vec<u8>>) -> Self {
        Self(canonical_bytes.into())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for JobSpec {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for JobSpec {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId([u8; 32]);

impl JobId {
    pub fn from_spec(spec: &JobSpec) -> Self {
        Self(*blake3::hash(spec.canonical_bytes()).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerId([u8; 32]);

impl WorkerId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for WorkerId {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JobResult(Vec<u8>);

impl JobResult {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for JobResult {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for JobResult {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Running,
    Done(JobResult),
    Failed(String),
    Cancelled,
    Rejected(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub spec: JobSpec,
    pub state: JobState,
    pub seq: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogicalInstant(u64);

impl LogicalInstant {
    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    fn saturating_add(self, duration: Duration) -> Self {
        let ticks = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(ticks))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub owner: WorkerId,
    pub epoch: u64,
    pub lease_deadline: LogicalInstant,
}

pub trait Clock {
    fn now(&self) -> LogicalInstant;
}

#[derive(Clone, Debug)]
pub struct RealClock {
    origin: Instant,
}

impl RealClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for RealClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for RealClock {
    fn now(&self) -> LogicalInstant {
        LogicalInstant::ZERO.saturating_add(self.origin.elapsed())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ManualClock {
    ticks: Arc<AtomicU64>,
}

impl ManualClock {
    pub fn new(now: LogicalInstant) -> Self {
        Self {
            ticks: Arc::new(AtomicU64::new(now.as_nanos())),
        }
    }

    pub fn advance(&self, duration: Duration) {
        let delta = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .ticks
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |ticks| {
                Some(ticks.saturating_add(delta))
            });
    }
}

impl Clock for ManualClock {
    fn now(&self) -> LogicalInstant {
        LogicalInstant::from_nanos(self.ticks.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobError {
    Conflict,
    FencedOut,
    RepoFull,
    NotFound,
    EpochExhausted,
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Conflict => "job operation conflicts with committed state",
            Self::FencedOut => "job attempt has been fenced out",
            Self::RepoFull => "job repository is full",
            Self::NotFound => "job was not found",
            Self::EpochExhausted => "job attempt epoch is exhausted",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for JobError {}

#[trait_variant::make(JobRepository: Send)]
pub trait LocalJobRepository {
    async fn submit(&self, spec: JobSpec) -> Result<JobId, JobError>;
    async fn get(&self, id: JobId) -> Result<Option<Job>, JobError>;
    async fn claim(&self, id: JobId, worker: WorkerId) -> Result<(Job, u64), JobError>;
    async fn heartbeat(&self, id: JobId, epoch: u64) -> Result<(), JobError>;
    async fn complete(&self, id: JobId, epoch: u64, result: JobResult) -> Result<(), JobError>;
    async fn list(&self) -> Result<Vec<Job>, JobError>;
}

#[derive(Clone, Debug)]
pub struct MemoryJobRepositoryBacking {
    inner: Arc<Mutex<Inner>>,
}

impl MemoryJobRepositoryBacking {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                capacity,
                next_seq: 0,
                records: Vec::new(),
            })),
        }
    }
}

#[derive(Clone)]
pub struct MemoryJobRepository<C> {
    backing: MemoryJobRepositoryBacking,
    clock: Arc<C>,
    lease_duration: Duration,
}

impl<C> MemoryJobRepository<C> {
    pub fn new(capacity: usize, lease_duration: Duration, clock: C) -> Self {
        Self::from_backing(
            MemoryJobRepositoryBacking::new(capacity),
            lease_duration,
            clock,
        )
    }

    pub fn from_backing(
        backing: MemoryJobRepositoryBacking,
        lease_duration: Duration,
        clock: C,
    ) -> Self {
        Self {
            backing,
            clock: Arc::new(clock),
            lease_duration,
        }
    }

    pub fn backing(&self) -> MemoryJobRepositoryBacking {
        self.backing.clone()
    }
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    next_seq: u64,
    records: Vec<Record>,
}

#[derive(Debug)]
struct Record {
    job: Job,
    attempt: Option<Attempt>,
}

impl<C: Clock> MemoryJobRepository<C> {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.backing
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn submit_sync(&self, spec: JobSpec) -> Result<JobId, JobError> {
        let id = JobId::from_spec(&spec);
        let mut inner = self.lock();

        if inner.records.iter().any(|record| record.job.id == id) {
            return Ok(id);
        }
        if inner.records.len() >= inner.capacity {
            return Err(JobError::RepoFull);
        }

        let seq = inner.next_seq;
        inner.next_seq = inner.next_seq.checked_add(1).ok_or(JobError::RepoFull)?;
        inner.records.push(Record {
            job: Job {
                id,
                spec,
                state: JobState::Queued,
                seq,
            },
            attempt: None,
        });
        Ok(id)
    }

    fn get_sync(&self, id: JobId) -> Result<Option<Job>, JobError> {
        let inner = self.lock();
        Ok(inner
            .records
            .iter()
            .find(|record| record.job.id == id)
            .map(|record| record.job.clone()))
    }

    fn claim_sync(&self, id: JobId, worker: WorkerId) -> Result<(Job, u64), JobError> {
        let now = self.clock.now();
        let lease_deadline = now.saturating_add(self.lease_duration);
        let mut inner = self.lock();
        let record = inner
            .records
            .iter_mut()
            .find(|record| record.job.id == id)
            .ok_or(JobError::NotFound)?;

        match record.job.state {
            JobState::Queued => {}
            JobState::Running => {
                let attempt = record.attempt.as_ref().ok_or(JobError::Conflict)?;
                if now < attempt.lease_deadline {
                    return Err(JobError::Conflict);
                }
            }
            JobState::Done(_)
            | JobState::Failed(_)
            | JobState::Cancelled
            | JobState::Rejected(_) => return Err(JobError::Conflict),
        }

        let epoch = record
            .attempt
            .as_ref()
            .map_or(Some(1), |attempt| attempt.epoch.checked_add(1))
            .ok_or(JobError::EpochExhausted)?;
        record.job.state = JobState::Running;
        record.attempt = Some(Attempt {
            owner: worker,
            epoch,
            lease_deadline,
        });
        Ok((record.job.clone(), epoch))
    }

    fn heartbeat_sync(&self, id: JobId, epoch: u64) -> Result<(), JobError> {
        let now = self.clock.now();
        let lease_deadline = now.saturating_add(self.lease_duration);
        let mut inner = self.lock();
        let record = inner
            .records
            .iter_mut()
            .find(|record| record.job.id == id)
            .ok_or(JobError::NotFound)?;
        let attempt = record.attempt.as_mut().ok_or(JobError::FencedOut)?;

        if attempt.epoch != epoch {
            return Err(JobError::FencedOut);
        }
        if record.job.state != JobState::Running {
            return Err(JobError::Conflict);
        }

        attempt.lease_deadline = lease_deadline;
        Ok(())
    }

    fn complete_sync(&self, id: JobId, epoch: u64, result: JobResult) -> Result<(), JobError> {
        let mut inner = self.lock();
        let record = inner
            .records
            .iter_mut()
            .find(|record| record.job.id == id)
            .ok_or(JobError::NotFound)?;
        let attempt = record.attempt.as_ref().ok_or(JobError::FencedOut)?;

        if attempt.epoch != epoch {
            return Err(JobError::FencedOut);
        }

        match &record.job.state {
            JobState::Running => {
                record.job.state = JobState::Done(result);
                Ok(())
            }
            JobState::Done(committed) if committed == &result => Ok(()),
            JobState::Done(_)
            | JobState::Queued
            | JobState::Failed(_)
            | JobState::Cancelled
            | JobState::Rejected(_) => Err(JobError::Conflict),
        }
    }

    fn list_sync(&self) -> Result<Vec<Job>, JobError> {
        let inner = self.lock();
        let mut jobs: Vec<_> = inner
            .records
            .iter()
            .map(|record| record.job.clone())
            .collect();
        jobs.sort_by_key(|job| (job.seq, job.id));
        Ok(jobs)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<C> JobRepository for MemoryJobRepository<C>
where
    C: Clock + Send + Sync,
{
    async fn submit(&self, spec: JobSpec) -> Result<JobId, JobError> {
        self.submit_sync(spec)
    }

    async fn get(&self, id: JobId) -> Result<Option<Job>, JobError> {
        self.get_sync(id)
    }

    async fn claim(&self, id: JobId, worker: WorkerId) -> Result<(Job, u64), JobError> {
        self.claim_sync(id, worker)
    }

    async fn heartbeat(&self, id: JobId, epoch: u64) -> Result<(), JobError> {
        self.heartbeat_sync(id, epoch)
    }

    async fn complete(&self, id: JobId, epoch: u64, result: JobResult) -> Result<(), JobError> {
        self.complete_sync(id, epoch, result)
    }

    async fn list(&self) -> Result<Vec<Job>, JobError> {
        self.list_sync()
    }
}

#[cfg(target_arch = "wasm32")]
impl<C: Clock> LocalJobRepository for MemoryJobRepository<C> {
    async fn submit(&self, spec: JobSpec) -> Result<JobId, JobError> {
        self.submit_sync(spec)
    }

    async fn get(&self, id: JobId) -> Result<Option<Job>, JobError> {
        self.get_sync(id)
    }

    async fn claim(&self, id: JobId, worker: WorkerId) -> Result<(Job, u64), JobError> {
        self.claim_sync(id, worker)
    }

    async fn heartbeat(&self, id: JobId, epoch: u64) -> Result<(), JobError> {
        self.heartbeat_sync(id, epoch)
    }

    async fn complete(&self, id: JobId, epoch: u64, result: JobResult) -> Result<(), JobError> {
        self.complete_sync(id, epoch, result)
    }

    async fn list(&self) -> Result<Vec<Job>, JobError> {
        self.list_sync()
    }
}
