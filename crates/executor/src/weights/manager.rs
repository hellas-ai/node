use super::loader::{load_weights_bundle, LoadedWeights};
use super::state::WeightsState;
use super::{has_cached_weights, EnsureDisposition, WeightsBundle, WeightsError, WeightsLocator};
use crate::policy::DownloadPolicy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

#[derive(Clone)]
pub(crate) struct WeightsManager {
    inner: Arc<WeightsManagerInner>,
}

struct WeightsManagerInner {
    download_policy: DownloadPolicy,
    state: Mutex<ManagerState>,
}

#[derive(Default)]
struct ManagerState {
    weights: WeightsState,
    waiters: HashMap<WeightsLocator, Vec<oneshot::Sender<Result<(), WeightsError>>>>,
}

struct EnsureAdmission {
    disposition: EnsureDisposition,
    next_load: Option<WeightsLocator>,
    waiter: Option<oneshot::Receiver<Result<(), WeightsError>>>,
}

impl WeightsManager {
    pub(crate) fn new(download_policy: DownloadPolicy) -> Self {
        Self {
            inner: Arc::new(WeightsManagerInner {
                download_policy,
                state: Mutex::new(ManagerState::default()),
            }),
        }
    }

    pub(crate) async fn ensure_ready(&self, locator: WeightsLocator) -> EnsureDisposition {
        let admission = self.admit(locator, false).await;
        self.spawn_load_if_needed(admission.next_load);
        admission.disposition
    }

    pub(crate) async fn ensure_ready_wait(
        &self,
        locator: WeightsLocator,
        wait_timeout: Duration,
    ) -> Result<(), WeightsError> {
        let admission = self.admit(locator, true).await;
        self.spawn_load_if_needed(admission.next_load);

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

    async fn admit(&self, locator: WeightsLocator, register_waiter: bool) -> EnsureAdmission {
        let denied_error = self.denied_error(&locator);
        let mut state = self.inner.state.lock().await;
        let action = state.weights.ensure(&locator, denied_error);
        let waiter = if register_waiter
            && matches!(
                action.disposition,
                EnsureDisposition::Queued | EnsureDisposition::InFlight
            ) {
            Some(Self::register_waiter(&mut state, locator))
        } else {
            None
        };

        EnsureAdmission {
            disposition: action.disposition,
            next_load: action.next_load,
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

    pub(crate) async fn bundle(
        &self,
        locator: &WeightsLocator,
    ) -> Result<Arc<WeightsBundle>, WeightsError> {
        let state = self.inner.state.lock().await;
        state.weights.bundle(locator)
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

    fn spawn_load_if_needed(&self, locator: Option<WeightsLocator>) {
        if let Some(locator) = locator {
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
        let (waiters, next_load, waiter_result) = {
            let mut state = self.inner.state.lock().await;
            let (next_load, waiter_result) = match load_result {
                Ok(loaded) => {
                    info!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        resolved_revision = %loaded.resolved_revision,
                        "weights ready"
                    );
                    (state.weights.finish_ready(&locator, loaded.bundle), Ok(()))
                }
                Err(error) => {
                    warn!(
                        model = %locator.model_id,
                        requested_revision = %locator.revision,
                        error = %error,
                        "weights failed"
                    );
                    (
                        state.weights.finish_failed(&locator, error.clone()),
                        Err(WeightsError::Failed(error)),
                    )
                }
            };
            let waiters = state.waiters.remove(&locator).unwrap_or_default();
            (waiters, next_load, waiter_result)
        };

        Self::notify_waiters(waiters, &waiter_result);
        self.spawn_load_if_needed(next_load);
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
