use super::ExecutionContext;
use crate::inputs::{
    self, Bundle, EnsureDisposition, HuggingFaceLocator, Loaded, Status, is_cached_locally,
    load_bundle,
};
use hellas_rpc::ExecutorError;
use hellas_rpc::policy::DownloadPolicy;
use hellas_runtime::cid::Cid;
use hellas_runtime::graph::Program;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn};

const DEFAULT_WEIGHT_LOAD_PARALLELISM: usize = 1;

/// Bound-program cache for the executor. See module docs for the two-level
/// admission/load story.
#[derive(Clone)]
pub(crate) struct Cache {
    inner: Arc<Inner>,
}

struct Inner {
    download_policy: DownloadPolicy,
    max_concurrent_loads: usize,
    state: Mutex<CacheState>,
}

#[derive(Default)]
struct CacheState {
    inputs: inputs::State,
    waiters: HashMap<HuggingFaceLocator, Vec<oneshot::Sender<Result<(), inputs::Error>>>>,
    load_queue: VecDeque<HuggingFaceLocator>,
    loads_in_flight: HashSet<HuggingFaceLocator>,
    // Single-flight admission for program binding: keeps the (potentially
    // expensive) `Inputs::bind` call outside the main mutex while ensuring
    // only one leader performs each build.
    program_builds: HashMap<ProgramBuildKey, Vec<oneshot::Sender<()>>>,
}

struct EnsureAdmission {
    disposition: EnsureDisposition,
    next_loads: Vec<HuggingFaceLocator>,
    waiter: Option<oneshot::Receiver<Result<(), inputs::Error>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProgramBuildKey {
    locator: HuggingFaceLocator,
    generation: u64,
    program_id: Cid<Program>,
}

enum BuildAdmission {
    Leader,
    Follower(oneshot::Receiver<()>),
}

enum BoundProgramStep {
    Ready(Arc<ExecutionContext>),
    BuildProgram {
        generation: u64,
        bundle: Arc<Bundle>,
        build_key: ProgramBuildKey,
    },
    Wait(oneshot::Receiver<()>),
}

impl Cache {
    pub(crate) fn new(download_policy: DownloadPolicy) -> Self {
        Self {
            inner: Arc::new(Inner {
                download_policy,
                max_concurrent_loads: DEFAULT_WEIGHT_LOAD_PARALLELISM,
                state: Mutex::new(CacheState::default()),
            }),
        }
    }

    pub(crate) async fn list_models(&self) -> Vec<(HuggingFaceLocator, Status)> {
        let state = self.inner.state.lock().await;
        state.inputs.list_models()
    }

    pub(crate) async fn ensure_ready(&self, locator: HuggingFaceLocator) -> EnsureDisposition {
        let admission = self.admit(locator, false, false).await;
        self.spawn_loads_if_needed(admission.next_loads);
        admission.disposition
    }

    pub(crate) async fn ensure_ready_wait(
        &self,
        locator: HuggingFaceLocator,
        wait_timeout: Duration,
    ) -> Result<(), ExecutorError> {
        let admission = self.admit(locator.clone(), true, false).await;
        self.spawn_loads_if_needed(admission.next_loads);

        match admission.disposition {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Failed(error) => Err(inputs::Error::Failed {
                locator,
                message: error,
            }
            .into()),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => Ok(Self::wait_for_ready(
                locator,
                wait_timeout,
                admission
                    .waiter
                    .expect("queued or inflight admissions must register a waiter"),
            )
            .await?),
        }
    }

    pub(crate) async fn ensure_preloaded(
        &self,
        locator: HuggingFaceLocator,
    ) -> Result<(), ExecutorError> {
        let admission = self.admit(locator.clone(), true, true).await;
        self.spawn_loads_if_needed(admission.next_loads);

        match admission.disposition {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Failed(error) => Err(inputs::Error::Failed {
                locator,
                message: error,
            }
            .into()),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => Ok(admission
                .waiter
                .expect("queued or inflight preload must register a waiter")
                .await
                .unwrap_or(Err(inputs::Error::NotReady {
                    locator: locator.clone(),
                }))?),
        }
    }

    async fn admit(
        &self,
        locator: HuggingFaceLocator,
        register_waiter: bool,
        bypass_download_policy: bool,
    ) -> EnsureAdmission {
        let denied_error = (!bypass_download_policy)
            .then(|| self.denied_error(&locator))
            .flatten();
        let mut state = self.inner.state.lock().await;
        let disposition = match state.inputs.status(&locator) {
            Some(Status::Ready) => EnsureDisposition::Ready,
            Some(Status::Failed(_)) => match denied_error {
                Some(error) => EnsureDisposition::Failed(error),
                None => {
                    state.inputs.mark_queued(locator.clone());
                    if Self::enqueue_load(&mut state, locator.clone()) {
                        EnsureDisposition::Queued
                    } else {
                        EnsureDisposition::InFlight
                    }
                }
            },
            Some(Status::Queued | Status::Loading) => {
                if Self::is_load_pending(&state, &locator) {
                    EnsureDisposition::InFlight
                } else {
                    state.inputs.mark_queued(locator.clone());
                    let _ = Self::enqueue_load(&mut state, locator.clone());
                    EnsureDisposition::Queued
                }
            }
            None => match denied_error {
                Some(error) => EnsureDisposition::Failed(error),
                None => {
                    state.inputs.mark_queued(locator.clone());
                    let _ = Self::enqueue_load(&mut state, locator.clone());
                    EnsureDisposition::Queued
                }
            },
        };
        let waiter = if register_waiter
            && matches!(
                disposition,
                EnsureDisposition::Queued | EnsureDisposition::InFlight
            ) {
            Some(Self::register_waiter(&mut state, locator))
        } else {
            None
        };
        let next_loads = Self::schedule_loads(&mut state, self.inner.max_concurrent_loads);

        EnsureAdmission {
            disposition,
            next_loads,
            waiter,
        }
    }

    async fn wait_for_ready(
        locator: HuggingFaceLocator,
        wait_timeout: Duration,
        receiver: oneshot::Receiver<Result<(), inputs::Error>>,
    ) -> Result<(), inputs::Error> {
        match timeout(wait_timeout, receiver).await {
            Ok(Ok(result)) => result,
            _ => Err(inputs::Error::NotReady { locator }),
        }
    }

    pub(crate) async fn bound_program(
        &self,
        locator: &HuggingFaceLocator,
        program: &Program,
    ) -> Result<Arc<ExecutionContext>, ExecutorError> {
        let start = Instant::now();
        let program_id = program.id();

        loop {
            let lookup_start = Instant::now();
            let next_step = {
                let mut state = self.inner.state.lock().await;
                let lookup = state.inputs.lookup_program(locator, program_id)?;
                if let Some(cached) = lookup.program {
                    BoundProgramStep::Ready(cached)
                } else {
                    let build_key = ProgramBuildKey {
                        locator: locator.clone(),
                        generation: lookup.generation,
                        program_id,
                    };
                    match Self::admit_build(&mut state.program_builds, build_key.clone()) {
                        BuildAdmission::Leader => BoundProgramStep::BuildProgram {
                            generation: lookup.generation,
                            bundle: lookup.bundle,
                            build_key,
                        },
                        BuildAdmission::Follower(receiver) => BoundProgramStep::Wait(receiver),
                    }
                }
            };
            let cache_lookup_ms = lookup_start.elapsed().as_millis();

            match next_step {
                BoundProgramStep::Ready(cached) => {
                    debug!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        %program_id,
                        cache_lookup_ms,
                        elapsed_ms = start.elapsed().as_millis(),
                        "bound program cache hit"
                    );
                    return Ok(cached);
                }
                BoundProgramStep::Wait(receiver) => {
                    let _ = receiver.await;
                    continue;
                }
                BoundProgramStep::BuildProgram {
                    generation,
                    bundle,
                    build_key,
                } => {
                    let bind_start = Instant::now();
                    let bound_program = match Self::build_program(&bundle, program) {
                        Ok(bound_program) => bound_program,
                        Err(error) => {
                            let mut state = self.inner.state.lock().await;
                            Self::finish_build(&mut state.program_builds, &build_key);
                            return Err(error);
                        }
                    };
                    let bind_ms = bind_start.elapsed().as_millis();

                    let cache_start = Instant::now();
                    let cache_result = {
                        let mut state = self.inner.state.lock().await;
                        let result = state
                            .inputs
                            .cache_program(locator, generation, bound_program);
                        Self::finish_build(&mut state.program_builds, &build_key);
                        result?
                    };
                    let cache_store_ms = cache_start.elapsed().as_millis();

                    match cache_result {
                        inputs::CacheProgramOutcome::Cached(cached) => {
                            debug!(
                                model = %locator.model_id,
                                requested_revision = %locator.revision,
                                cache_lookup_ms,
                                bind_ms,
                                cache_store_ms,
                                total_ms = start.elapsed().as_millis(),
                                "bound program phase timings"
                            );
                            info!(
                                model = %locator.model_id,
                                requested_revision = %locator.revision,
                                elapsed_ms = start.elapsed().as_millis(),
                                "bound program cache miss"
                            );
                            return Ok(cached);
                        }
                        inputs::CacheProgramOutcome::Stale => {
                            debug!(
                                model = %locator.model_id,
                                requested_revision = %locator.revision,
                                %program_id,
                                generation,
                                "bound program cache entry changed during bind, retrying"
                            );
                        }
                    }
                }
            }
        }
    }

    fn denied_error(&self, locator: &HuggingFaceLocator) -> Option<String> {
        if is_cached_locally(locator)
            || self
                .inner
                .download_policy
                .allows_download(&locator.model_id)
        {
            None
        } else {
            Some(format!(
                "download policy '{}' denied download for weights '{}'",
                self.inner.download_policy, locator
            ))
        }
    }

    fn register_waiter(
        state: &mut CacheState,
        locator: HuggingFaceLocator,
    ) -> oneshot::Receiver<Result<(), inputs::Error>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let waiters = state.waiters.entry(locator).or_default();
        waiters.retain(|waiter| !waiter.is_closed());
        waiters.push(reply_tx);
        reply_rx
    }

    fn build_program(
        bundle: &Arc<Bundle>,
        program: &Program,
    ) -> Result<Arc<ExecutionContext>, ExecutorError> {
        let backend = crate::backend::create_backend()?;
        let bound =
            hellas_runtime::graph::BoundProgram::bind(&bundle.inputs, &backend, program.clone())
                .map_err(hellas_runtime::LLMError::from)?;
        Ok(Arc::new(ExecutionContext::new(Arc::new(bound))?))
    }

    fn admit_build<K>(inflight: &mut HashMap<K, Vec<oneshot::Sender<()>>>, key: K) -> BuildAdmission
    where
        K: Eq + std::hash::Hash,
    {
        if let Some(waiters) = inflight.get_mut(&key) {
            let (reply_tx, reply_rx) = oneshot::channel();
            waiters.retain(|waiter| !waiter.is_closed());
            waiters.push(reply_tx);
            BuildAdmission::Follower(reply_rx)
        } else {
            inflight.insert(key, Vec::new());
            BuildAdmission::Leader
        }
    }

    fn finish_build<K>(inflight: &mut HashMap<K, Vec<oneshot::Sender<()>>>, key: &K)
    where
        K: Eq + std::hash::Hash,
    {
        let waiters = inflight.remove(key).unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(());
        }
    }

    fn enqueue_load(state: &mut CacheState, locator: HuggingFaceLocator) -> bool {
        if Self::is_load_pending(state, &locator) {
            return false;
        }

        state.load_queue.push_back(locator);
        true
    }

    fn is_load_pending(state: &CacheState, locator: &HuggingFaceLocator) -> bool {
        state.loads_in_flight.contains(locator)
            || state.load_queue.iter().any(|queued| queued == locator)
    }

    fn schedule_loads(
        state: &mut CacheState,
        max_concurrent_loads: usize,
    ) -> Vec<HuggingFaceLocator> {
        let available = max_concurrent_loads.saturating_sub(state.loads_in_flight.len());
        let mut next_loads = Vec::with_capacity(available);

        for _ in 0..available {
            let Some(locator) = state.load_queue.pop_front() else {
                break;
            };
            if state.inputs.mark_loading(&locator).is_err() {
                continue;
            }
            state.loads_in_flight.insert(locator.clone());
            next_loads.push(locator);
        }

        next_loads
    }

    fn spawn_loads_if_needed(&self, locators: Vec<HuggingFaceLocator>) {
        for locator in locators {
            self.spawn_load(locator);
        }
    }

    fn spawn_load(&self, locator: HuggingFaceLocator) {
        let manager = self.clone();
        info!(
            model = %locator.model_id,
            requested_revision = %locator.revision,
            "weights ensure started"
        );

        tokio::spawn(async move {
            let load_result = tokio::task::spawn_blocking({
                let locator = locator.clone();
                move || load_bundle(&locator)
            })
            .await
            .map_err(|error| format!("weights worker join error: {error}"))
            .and_then(|result| result.map_err(|error| error.to_string()));

            manager.finish_load(locator, load_result).await;
        });
    }

    async fn finish_load(&self, locator: HuggingFaceLocator, load_result: Result<Loaded, String>) {
        let (waiters, next_loads, waiter_result) = {
            let mut state = self.inner.state.lock().await;
            state.loads_in_flight.remove(&locator);
            let waiter_result = match load_result {
                Ok(loaded) => {
                    info!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        resolved_revision = %loaded.resolved_revision,
                        "weights ready"
                    );
                    state.inputs.finish_ready(&locator, loaded.bundle);
                    Ok(())
                }
                Err(error) => {
                    warn!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        error = %error,
                        "weights failed"
                    );
                    state.inputs.finish_failed(&locator, error.clone());
                    Err(inputs::Error::Failed {
                        locator: locator.clone(),
                        message: error,
                    })
                }
            };
            let next_loads = Self::schedule_loads(&mut state, self.inner.max_concurrent_loads);
            let waiters = state.waiters.remove(&locator).unwrap_or_default();
            (waiters, next_loads, waiter_result)
        };

        Self::notify_waiters(waiters, &waiter_result);
        self.spawn_loads_if_needed(next_loads);
    }

    fn notify_waiters(
        waiters: Vec<oneshot::Sender<Result<(), inputs::Error>>>,
        waiter_result: &Result<(), inputs::Error>,
    ) {
        for waiter in waiters {
            let _ = waiter.send(waiter_result.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator() -> HuggingFaceLocator {
        HuggingFaceLocator::new(
            "model".to_string(),
            "main".to_string(),
            catgrad::prelude::Dtype::F32,
        )
    }

    fn locator_with_suffix(suffix: u8) -> HuggingFaceLocator {
        HuggingFaceLocator::new(
            format!("model-{suffix}"),
            "main".to_string(),
            catgrad::prelude::Dtype::F32,
        )
    }

    #[test]
    fn enqueue_load_only_tracks_one_pending_entry() {
        let locator = locator();
        let mut state = CacheState::default();
        state.inputs.mark_queued(locator.clone());

        assert!(Cache::enqueue_load(&mut state, locator.clone()));
        assert!(!Cache::enqueue_load(&mut state, locator.clone()));
        assert_eq!(state.load_queue.len(), 1);
    }

    #[test]
    fn schedule_loads_respects_parallelism_limit() {
        let mut state = CacheState::default();
        for suffix in 0..3 {
            let locator = locator_with_suffix(suffix);
            state.inputs.mark_queued(locator.clone());
            assert!(Cache::enqueue_load(&mut state, locator));
        }

        let started = Cache::schedule_loads(&mut state, 2);
        assert_eq!(started.len(), 2);
        assert_eq!(state.loads_in_flight.len(), 2);
        assert_eq!(state.load_queue.len(), 1);
    }

    #[tokio::test]
    async fn admit_build_allows_single_leader_and_wakes_followers() {
        let key = ProgramBuildKey {
            locator: locator(),
            generation: 1,
            program_id: Cid::<Program>::from_bytes([0; 32]),
        };
        let mut inflight = HashMap::new();

        assert!(matches!(
            Cache::admit_build(&mut inflight, key.clone()),
            BuildAdmission::Leader
        ));
        let follower = match Cache::admit_build(&mut inflight, key.clone()) {
            BuildAdmission::Follower(receiver) => receiver,
            BuildAdmission::Leader => panic!("second admission should follow"),
        };

        Cache::finish_build(&mut inflight, &key);
        follower.await.expect("follower should be notified");
        assert!(inflight.is_empty());
    }
}
