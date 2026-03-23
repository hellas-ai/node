use super::loader::{LoadedWeights, load_weights_bundle};
use super::state::{CacheProgramOutcome, CacheRuntimeOutcome, EntryStatusSnapshot, WeightsState};
use super::{
    EnsureDisposition, ExecutionContext, WeightsBundle, WeightsError, WeightsLocator,
    has_cached_weights,
};
use crate::ExecutorError;
use crate::backend::{ExecBackend, create_backend};
use crate::policy::DownloadPolicy;
use catgrad_llm::helpers::WeightPostProcess;
use catgrad_llm::{Program, Runtime};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn};

const DEFAULT_WEIGHT_LOAD_PARALLELISM: usize = 1;

#[derive(Clone)]
pub(crate) struct RuntimeManager {
    inner: Arc<RuntimeManagerInner>,
}

struct RuntimeManagerInner {
    download_policy: DownloadPolicy,
    max_concurrent_loads: usize,
    state: Mutex<ManagerState>,
}

#[derive(Default)]
struct ManagerState {
    weights: WeightsState,
    waiters: HashMap<WeightsLocator, Vec<oneshot::Sender<Result<(), WeightsError>>>>,
    load_queue: VecDeque<WeightsLocator>,
    loads_in_flight: HashSet<WeightsLocator>,
    // These single-flight maps keep expensive runtime creation and program binding
    // outside the main mutex while ensuring only one leader performs each build.
    runtime_builds: HashMap<RuntimeBuildKey, Vec<oneshot::Sender<()>>>,
    program_builds: HashMap<ProgramBuildKey, Vec<oneshot::Sender<()>>>,
}

struct EnsureAdmission {
    disposition: EnsureDisposition,
    next_loads: Vec<WeightsLocator>,
    waiter: Option<oneshot::Receiver<Result<(), WeightsError>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RuntimeBuildKey {
    locator: WeightsLocator,
    generation: u64,
    weight_post_process: WeightPostProcess,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProgramBuildKey {
    locator: WeightsLocator,
    generation: u64,
    weight_post_process: WeightPostProcess,
    program_id: String,
}

enum BuildAdmission {
    Leader,
    Follower(oneshot::Receiver<()>),
}

enum BoundProgramStep {
    Ready(Arc<ExecutionContext>),
    BuildRuntime {
        generation: u64,
        bundle: Arc<WeightsBundle>,
        build_key: RuntimeBuildKey,
    },
    BuildProgram {
        generation: u64,
        runtime: Arc<Runtime<ExecBackend>>,
        build_key: ProgramBuildKey,
    },
    Wait(oneshot::Receiver<()>),
}

impl RuntimeManager {
    pub(crate) fn new(download_policy: DownloadPolicy) -> Self {
        Self {
            inner: Arc::new(RuntimeManagerInner {
                download_policy,
                max_concurrent_loads: DEFAULT_WEIGHT_LOAD_PARALLELISM,
                state: Mutex::new(ManagerState::default()),
            }),
        }
    }

    pub(crate) async fn ensure_ready(&self, locator: WeightsLocator) -> EnsureDisposition {
        let admission = self.admit(locator, false, false).await;
        self.spawn_loads_if_needed(admission.next_loads);
        admission.disposition
    }

    pub(crate) async fn ensure_ready_wait(
        &self,
        locator: WeightsLocator,
        wait_timeout: Duration,
    ) -> Result<(), WeightsError> {
        let admission = self.admit(locator, true, false).await;
        self.spawn_loads_if_needed(admission.next_loads);

        match admission.disposition {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Failed(error) => Err(WeightsError::Failed(error)),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                Self::wait_for_ready(
                    wait_timeout,
                    admission
                        .waiter
                        .expect("queued or inflight admissions must register a waiter"),
                )
                .await
            }
        }
    }

    pub(crate) async fn ensure_preloaded(
        &self,
        locator: WeightsLocator,
    ) -> Result<(), WeightsError> {
        let admission = self.admit(locator, true, true).await;
        self.spawn_loads_if_needed(admission.next_loads);

        match admission.disposition {
            EnsureDisposition::Ready => Ok(()),
            EnsureDisposition::Failed(error) => Err(WeightsError::Failed(error)),
            EnsureDisposition::Queued | EnsureDisposition::InFlight => admission
                .waiter
                .expect("queued or inflight preload must register a waiter")
                .await
                .unwrap_or(Err(WeightsError::NotReady)),
        }
    }

    async fn admit(
        &self,
        locator: WeightsLocator,
        register_waiter: bool,
        bypass_download_policy: bool,
    ) -> EnsureAdmission {
        let denied_error = (!bypass_download_policy)
            .then(|| self.denied_error(&locator))
            .flatten();
        let mut state = self.inner.state.lock().await;
        let disposition = match state.weights.status(&locator) {
            Some(EntryStatusSnapshot::Ready) => EnsureDisposition::Ready,
            Some(EntryStatusSnapshot::Failed(_)) => match denied_error {
                Some(error) => EnsureDisposition::Failed(error),
                None => {
                    state.weights.mark_queued(locator.clone());
                    if Self::enqueue_load(&mut state, locator.clone()) {
                        EnsureDisposition::Queued
                    } else {
                        EnsureDisposition::InFlight
                    }
                }
            },
            Some(EntryStatusSnapshot::Queued | EntryStatusSnapshot::Loading) => {
                if Self::is_load_pending(&state, &locator) {
                    EnsureDisposition::InFlight
                } else {
                    state.weights.mark_queued(locator.clone());
                    let _ = Self::enqueue_load(&mut state, locator.clone());
                    EnsureDisposition::Queued
                }
            }
            None => match denied_error {
                Some(error) => EnsureDisposition::Failed(error),
                None => {
                    state.weights.mark_queued(locator.clone());
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
        wait_timeout: Duration,
        receiver: oneshot::Receiver<Result<(), WeightsError>>,
    ) -> Result<(), WeightsError> {
        match timeout(wait_timeout, receiver).await {
            Ok(Ok(result)) => result,
            _ => Err(WeightsError::NotReady),
        }
    }

    pub(crate) async fn bound_program(
        &self,
        locator: &WeightsLocator,
        program: &Program,
    ) -> Result<Arc<ExecutionContext>, ExecutorError> {
        let start = Instant::now();
        let program_id = program.id().to_string();
        let weight_post_process = program.weight_post_process;

        loop {
            let lookup_start = Instant::now();
            let next_step = {
                let mut state = self.inner.state.lock().await;
                let lookup = state
                    .weights
                    .lookup_program(locator, weight_post_process, &program_id)
                    .map_err(|error| map_program_cache_error(locator, error))?;
                if let Some(cached) = lookup.program {
                    BoundProgramStep::Ready(cached)
                } else if let Some(runtime) = lookup.runtime {
                    let build_key = ProgramBuildKey {
                        locator: locator.clone(),
                        generation: lookup.generation,
                        weight_post_process,
                        program_id: program_id.clone(),
                    };
                    match Self::admit_build(&mut state.program_builds, build_key.clone()) {
                        BuildAdmission::Leader => BoundProgramStep::BuildProgram {
                            generation: lookup.generation,
                            runtime,
                            build_key,
                        },
                        BuildAdmission::Follower(receiver) => BoundProgramStep::Wait(receiver),
                    }
                } else {
                    let build_key = RuntimeBuildKey {
                        locator: locator.clone(),
                        generation: lookup.generation,
                        weight_post_process,
                    };
                    match Self::admit_build(&mut state.runtime_builds, build_key.clone()) {
                        BuildAdmission::Leader => BoundProgramStep::BuildRuntime {
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
                    info!(
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
                BoundProgramStep::BuildRuntime {
                    generation,
                    bundle,
                    build_key,
                } => {
                    let runtime_create_start = Instant::now();
                    let runtime = match Self::build_runtime(&bundle, weight_post_process) {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let mut state = self.inner.state.lock().await;
                            Self::finish_build(&mut state.runtime_builds, &build_key);
                            return Err(error);
                        }
                    };
                    let runtime_create_ms = runtime_create_start.elapsed().as_millis();
                    let cache_start = Instant::now();
                    let cache_result = {
                        let mut state = self.inner.state.lock().await;
                        let result = state
                            .weights
                            .cache_runtime(locator, generation, weight_post_process, runtime)
                            .map_err(|error| map_program_cache_error(locator, error));
                        Self::finish_build(&mut state.runtime_builds, &build_key);
                        result?
                    };
                    debug!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        runtime_create_ms,
                        "runtime cache miss"
                    );
                    match cache_result {
                        CacheRuntimeOutcome::Cached => {
                            debug!(
                                model = %locator.model_id,
                                requested_revision = %locator.revision,
                                cache_lookup_ms,
                                runtime_create_ms,
                                cache_store_ms = cache_start.elapsed().as_millis(),
                                total_ms = start.elapsed().as_millis(),
                                "runtime phase timings"
                            );
                        }
                        CacheRuntimeOutcome::Stale => {
                            debug!(
                                model = %locator.model_id,
                                requested_revision = %locator.revision,
                                generation,
                                "runtime cache entry changed during build, retrying"
                            );
                        }
                    }
                    continue;
                }
                BoundProgramStep::BuildProgram {
                    generation,
                    runtime,
                    build_key,
                } => {
                    let bind_start = Instant::now();
                    let bound_program = match Self::build_program(&runtime, program) {
                        Ok(bound_program) => bound_program,
                        Err(error) => {
                            let mut state = self.inner.state.lock().await;
                            Self::finish_build(&mut state.program_builds, &build_key);
                            return Err(error);
                        }
                    };
                    let runtime_bind_ms = bind_start.elapsed().as_millis();

                    let cache_start = Instant::now();
                    let cache_result = {
                        let mut state = self.inner.state.lock().await;
                        let result = state
                            .weights
                            .cache_program(
                                locator,
                                generation,
                                weight_post_process,
                                program_id.clone(),
                                bound_program,
                            )
                            .map_err(|error| map_program_cache_error(locator, error));
                        Self::finish_build(&mut state.program_builds, &build_key);
                        result?
                    };
                    let cache_store_ms = cache_start.elapsed().as_millis();

                    match cache_result {
                        CacheProgramOutcome::Cached(cached) => {
                            debug!(
                                model = %locator.model_id,
                                requested_revision = %locator.revision,
                                cache_lookup_ms,
                                runtime_bind_ms,
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
                        CacheProgramOutcome::Stale => {
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

    fn denied_error(&self, locator: &WeightsLocator) -> Option<String> {
        if has_cached_weights(locator)
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
        state: &mut ManagerState,
        locator: WeightsLocator,
    ) -> oneshot::Receiver<Result<(), WeightsError>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let waiters = state.waiters.entry(locator).or_default();
        waiters.retain(|waiter| !waiter.is_closed());
        waiters.push(reply_tx);
        reply_rx
    }

    fn build_runtime(
        bundle: &Arc<WeightsBundle>,
        weight_post_process: WeightPostProcess,
    ) -> Result<Arc<Runtime<ExecBackend>>, ExecutorError> {
        Ok(Arc::new(Runtime::new(
            create_backend()?,
            weight_post_process,
            bundle.parameter_values.clone(),
            bundle.parameter_types.clone(),
        )?))
    }

    fn build_program(
        runtime: &Arc<Runtime<ExecBackend>>,
        program: &Program,
    ) -> Result<Arc<ExecutionContext>, ExecutorError> {
        Ok(Arc::new(ExecutionContext::new(Arc::new(
            runtime.bind(program.clone())?,
        ))))
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

    fn enqueue_load(state: &mut ManagerState, locator: WeightsLocator) -> bool {
        if Self::is_load_pending(state, &locator) {
            return false;
        }

        state.load_queue.push_back(locator);
        true
    }

    fn is_load_pending(state: &ManagerState, locator: &WeightsLocator) -> bool {
        state.loads_in_flight.contains(locator)
            || state.load_queue.iter().any(|queued| queued == locator)
    }

    fn schedule_loads(
        state: &mut ManagerState,
        max_concurrent_loads: usize,
    ) -> Vec<WeightsLocator> {
        let available = max_concurrent_loads.saturating_sub(state.loads_in_flight.len());
        let mut next_loads = Vec::with_capacity(available);

        for _ in 0..available {
            let Some(locator) = state.load_queue.pop_front() else {
                break;
            };
            if state.weights.mark_loading(&locator).is_err() {
                continue;
            }
            state.loads_in_flight.insert(locator.clone());
            next_loads.push(locator);
        }

        next_loads
    }

    fn spawn_loads_if_needed(&self, locators: Vec<WeightsLocator>) {
        for locator in locators {
            self.spawn_load(locator);
        }
    }

    fn spawn_load(&self, locator: WeightsLocator) {
        let manager = self.clone();
        info!(
            model = %locator.model_id,
            requested_revision = %locator.revision,
            "weights ensure started"
        );

        tokio::spawn(async move {
            let load_result = tokio::task::spawn_blocking({
                let locator = locator.clone();
                move || load_weights_bundle(&locator)
            })
            .await
            .map_err(|error| format!("weights worker join error: {error}"))
            .and_then(|result| result.map_err(|error| error.to_string()));

            manager.finish_load(locator, load_result).await;
        });
    }

    async fn finish_load(
        &self,
        locator: WeightsLocator,
        load_result: Result<LoadedWeights, String>,
    ) {
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
                    state.weights.finish_ready(&locator, loaded.bundle);
                    Ok(())
                }
                Err(error) => {
                    warn!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        error = %error,
                        "weights failed"
                    );
                    state.weights.finish_failed(&locator, error.clone());
                    Err(WeightsError::Failed(error))
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
        waiters: Vec<oneshot::Sender<Result<(), WeightsError>>>,
        waiter_result: &Result<(), WeightsError>,
    ) {
        for waiter in waiters {
            let _ = waiter.send(waiter_result.clone());
        }
    }
}

fn map_program_cache_error(locator: &WeightsLocator, error: WeightsError) -> ExecutorError {
    match error {
        WeightsError::NotReady | WeightsError::UnknownKey => {
            ExecutorError::WeightsNotReady(locator.to_string())
        }
        WeightsError::Failed(message) => ExecutorError::WeightsError(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator() -> WeightsLocator {
        WeightsLocator {
            model_id: "model".to_string(),
            revision: "main".to_string(),
        }
    }

    fn locator_with_suffix(suffix: u8) -> WeightsLocator {
        WeightsLocator {
            model_id: format!("model-{suffix}"),
            revision: "main".to_string(),
        }
    }

    #[test]
    fn enqueue_load_only_tracks_one_pending_entry() {
        let locator = locator();
        let mut state = ManagerState::default();
        state.weights.mark_queued(locator.clone());

        assert!(RuntimeManager::enqueue_load(&mut state, locator.clone()));
        assert!(!RuntimeManager::enqueue_load(&mut state, locator.clone()));
        assert_eq!(state.load_queue.len(), 1);
    }

    #[test]
    fn schedule_loads_respects_parallelism_limit() {
        let mut state = ManagerState::default();
        for suffix in 0..3 {
            let locator = locator_with_suffix(suffix);
            state.weights.mark_queued(locator.clone());
            assert!(RuntimeManager::enqueue_load(&mut state, locator));
        }

        let started = RuntimeManager::schedule_loads(&mut state, 2);
        assert_eq!(started.len(), 2);
        assert_eq!(state.loads_in_flight.len(), 2);
        assert_eq!(state.load_queue.len(), 1);
    }

    #[tokio::test]
    async fn admit_build_allows_single_leader_and_wakes_followers() {
        let key = RuntimeBuildKey {
            locator: locator(),
            generation: 1,
            weight_post_process: WeightPostProcess::None,
        };
        let mut inflight = HashMap::new();

        assert!(matches!(
            RuntimeManager::admit_build(&mut inflight, key.clone()),
            BuildAdmission::Leader
        ));
        let follower = match RuntimeManager::admit_build(&mut inflight, key.clone()) {
            BuildAdmission::Follower(receiver) => receiver,
            BuildAdmission::Leader => panic!("second admission should follow"),
        };

        RuntimeManager::finish_build(&mut inflight, &key);
        follower.await.expect("follower should be notified");
        assert!(inflight.is_empty());
    }
}
