use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hellas_core::{ProducerId, PublicKey, canonical_dag_cbor, decode_dag_cbor};
use hellas_rpc::peers::TokenBucket;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::fetch_projection::{FetchRequestView, FetchUsage};

#[derive(Clone, Debug)]
pub struct FetchAccessPolicy {
    callers: HashMap<ProducerId, CallerAccess>,
    rate_buckets: HashMap<ProducerId, TokenBucket>,
    quota_store: FetchQuotaStoreBackend,
}

impl FetchAccessPolicy {
    pub fn new(callers: impl IntoIterator<Item = CallerAccess>) -> Self {
        Self::with_quota_store(callers, FetchQuotaStoreBackend::memory())
    }

    pub fn with_quota_store(
        callers: impl IntoIterator<Item = CallerAccess>,
        quota_store: FetchQuotaStoreBackend,
    ) -> Self {
        Self {
            callers: callers
                .into_iter()
                .map(|access| (ProducerId::from_public_key(&access.public_key), access))
                .collect(),
            rate_buckets: HashMap::new(),
            quota_store,
        }
    }

    pub fn trusted_callers(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self::new(keys.into_iter().map(CallerAccess::allow_all))
    }

    pub fn caller_keys(&self) -> Vec<PublicKey> {
        self.callers
            .values()
            .map(|access| access.public_key)
            .collect()
    }

    pub fn with_store(mut self, quota_store: FetchQuotaStoreBackend) -> Self {
        self.quota_store = quota_store;
        self
    }

    pub fn authorize_admission(
        &mut self,
        caller_key: &PublicKey,
        request: &FetchRequestView,
        now_ms: u64,
        reservation_id: String,
        capabilities: &FetchRoutePolicy,
    ) -> Result<FetchAdmission, FetchAccessError> {
        let caller_id = ProducerId::from_public_key(caller_key);
        let caller = self.callers.get(&caller_id).ok_or_else(|| {
            FetchAccessError::Denied("fetch caller is not authorized".to_string())
        })?;
        if caller.public_key != *caller_key {
            return Err(FetchAccessError::Denied(
                "fetch caller key does not match authorized key".to_string(),
            ));
        }
        let route = FetchRoute::new(request.service.clone(), request.method.clone());
        let route_policy = caller.routes.policy_for(&route).ok_or_else(|| {
            FetchAccessError::Denied(format!(
                "fetch caller is not authorized for {}/{}",
                request.service, request.method
            ))
        })?;
        let effective = capabilities.intersect(route_policy);
        effective.validate(request)?;

        if let Some(rate) = caller.request_rate {
            let bucket = self
                .rate_buckets
                .entry(caller_id)
                .or_insert_with(|| TokenBucket::new(now_ms, rate.capacity));
            bucket
                .try_take(now_ms, rate.capacity, rate.refill_per_sec)
                .map_err(|retry_after_ms| FetchAccessError::QuotaExceeded {
                    retry_after_ms,
                    message: "fetch request rate quota exceeded".to_string(),
                })?;
        }

        let reservation = match caller.spend {
            Some(spend) => {
                let reserved_units = reserved_units(request, &effective)?;
                self.reserve_spend(caller_id, reservation_id, now_ms, reserved_units, spend)?
            }
            None => None,
        };

        Ok(FetchAdmission { reservation })
    }

    pub fn cancel_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        ledger.entries.retain(|entry| entry.id != reservation.id);
        self.quota_store.put(reservation.caller_id, &ledger)?;
        Ok(())
    }

    pub fn reconcile_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        usage: Option<FetchUsage>,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let charged_units = usage_charge_units(usage).unwrap_or(reservation.reserved_units);
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        if let Some(entry) = ledger
            .entries
            .iter_mut()
            .find(|entry| entry.id == reservation.id)
        {
            entry.units = charged_units;
        }
        self.quota_store.put(reservation.caller_id, &ledger)?;
        Ok(())
    }

    fn reserve_spend(
        &mut self,
        caller_id: ProducerId,
        reservation_id: String,
        now_ms: u64,
        reserved_units: u64,
        spend: SpendLimit,
    ) -> Result<Option<FetchQuotaReservation>, FetchAccessError> {
        let mut ledger = self.quota_store.load(caller_id)?;
        prune_ledger(&mut ledger, now_ms, spend.window);
        let used = ledger
            .entries
            .iter()
            .fold(0_u64, |acc, entry| acc.saturating_add(entry.units));
        if used.saturating_add(reserved_units) > spend.max_units {
            return Err(FetchAccessError::QuotaExceeded {
                retry_after_ms: spend_retry_after_ms(&ledger, now_ms, spend.window),
                message: "fetch token spend quota exceeded".to_string(),
            });
        }
        ledger.entries.push(SpendEntry {
            id: reservation_id.clone(),
            at_ms: now_ms,
            units: reserved_units,
        });
        self.quota_store.put(caller_id, &ledger)?;
        Ok(Some(FetchQuotaReservation {
            caller_id,
            id: reservation_id,
            reserved_units,
        }))
    }
}

fn reserved_units(
    request: &FetchRequestView,
    route_policy: &FetchRoutePolicy,
) -> Result<u64, FetchAccessError> {
    let requested = request.max_output_units.ok_or_else(|| {
        FetchAccessError::Denied(
            "fetch request must set max output units for quota-controlled routes".to_string(),
        )
    })?;
    Ok(match route_policy.max_output_units {
        Some(limit) => requested.min(limit),
        None => requested,
    })
}

fn usage_charge_units(usage: Option<FetchUsage>) -> Option<u64> {
    let usage = usage?;
    usage
        .output_units
        .or(usage.total_units)
        .or(usage.input_units)
}

fn prune_ledger(ledger: &mut SpendLedger, now_ms: u64, window: Duration) {
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    ledger
        .entries
        .retain(|entry| now_ms.saturating_sub(entry.at_ms) < window_ms);
}

fn spend_retry_after_ms(ledger: &SpendLedger, now_ms: u64, window: Duration) -> Option<u64> {
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    ledger
        .entries
        .iter()
        .map(|entry| entry.at_ms.saturating_add(window_ms).saturating_sub(now_ms))
        .filter(|retry| *retry > 0)
        .min()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchAdmission {
    pub reservation: Option<FetchQuotaReservation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchQuotaReservation {
    pub caller_id: ProducerId,
    pub id: String,
    pub reserved_units: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallerAccess {
    pub public_key: PublicKey,
    pub routes: RouteSet,
    pub request_rate: Option<RequestRateLimit>,
    pub spend: Option<SpendLimit>,
}

impl CallerAccess {
    pub fn allow_all(public_key: PublicKey) -> Self {
        Self {
            public_key,
            routes: RouteSet::All(FetchRoutePolicy::default()),
            request_rate: None,
            spend: None,
        }
    }

    pub fn explicit(
        public_key: PublicKey,
        routes: impl IntoIterator<Item = FetchRouteGrant>,
    ) -> Self {
        Self {
            public_key,
            routes: RouteSet::explicit(routes),
            request_rate: None,
            spend: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSet {
    All(FetchRoutePolicy),
    Explicit(HashMap<FetchRoute, FetchRoutePolicy>),
}

impl RouteSet {
    pub fn explicit(routes: impl IntoIterator<Item = FetchRouteGrant>) -> Self {
        Self::Explicit(
            routes
                .into_iter()
                .map(|grant| (grant.route, grant.policy))
                .collect(),
        )
    }

    fn policy_for(&self, route: &FetchRoute) -> Option<&FetchRoutePolicy> {
        match self {
            Self::All(policy) => Some(policy),
            Self::Explicit(routes) => routes.get(route),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FetchRoute {
    pub service: String,
    pub method: String,
}

impl FetchRoute {
    pub fn new(service: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRouteGrant {
    pub route: FetchRoute,
    pub policy: FetchRoutePolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchRoutePolicy {
    pub allowed_models: Option<BTreeSet<String>>,
    pub max_output_units: Option<u64>,
}

impl FetchRoutePolicy {
    /// The policy admitting exactly what both `self` and `other` admit:
    /// model allowlists intersect when both are set (otherwise the one that
    /// is set applies), and output limits take the minimum.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            allowed_models: match (&self.allowed_models, &other.allowed_models) {
                (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
                (Some(a), None) => Some(a.clone()),
                (None, b) => b.clone(),
            },
            max_output_units: match (self.max_output_units, other.max_output_units) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
    }

    fn validate(&self, request: &FetchRequestView) -> Result<(), FetchAccessError> {
        if let Some(models) = &self.allowed_models {
            let Some(model) = &request.model else {
                return Err(FetchAccessError::Denied(
                    "fetch request model is required for this route".to_string(),
                ));
            };
            if !models.contains(model) {
                return Err(FetchAccessError::Denied(format!(
                    "fetch model {model} is not authorized for this route"
                )));
            }
        }
        if let Some(max_output_units) = self.max_output_units {
            let requested = request.max_output_units.ok_or_else(|| {
                FetchAccessError::Denied(
                    "fetch request must set max output units for this route".to_string(),
                )
            })?;
            if requested > max_output_units {
                return Err(FetchAccessError::Denied(format!(
                    "fetch request max output units {requested} exceed route limit {max_output_units}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RequestRateLimit {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendLimit {
    pub max_units: u64,
    pub window: Duration,
}

#[derive(Clone, Debug)]
pub enum FetchQuotaStoreBackend {
    Memory(MemoryFetchQuotaStore),
    Fs(FsFetchQuotaStore),
}

impl FetchQuotaStoreBackend {
    pub fn memory() -> Self {
        Self::Memory(MemoryFetchQuotaStore::default())
    }

    pub fn fs(root: impl Into<PathBuf>) -> Self {
        Self::Fs(FsFetchQuotaStore::new(root))
    }

    fn load(&self, caller_id: ProducerId) -> Result<SpendLedger, FetchAccessError> {
        match self {
            Self::Memory(store) => store.load(caller_id),
            Self::Fs(store) => store.load(caller_id),
        }
    }

    fn put(&self, caller_id: ProducerId, ledger: &SpendLedger) -> Result<(), FetchAccessError> {
        match self {
            Self::Memory(store) => store.put(caller_id, ledger),
            Self::Fs(store) => store.put(caller_id, ledger),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryFetchQuotaStore {
    ledgers: std::sync::Arc<std::sync::Mutex<HashMap<ProducerId, SpendLedger>>>,
}

impl MemoryFetchQuotaStore {
    fn load(&self, caller_id: ProducerId) -> Result<SpendLedger, FetchAccessError> {
        let ledgers = self.ledgers.lock().map_err(|_| {
            FetchAccessError::Store("fetch quota memory store lock is poisoned".to_string())
        })?;
        Ok(ledgers.get(&caller_id).cloned().unwrap_or_default())
    }

    fn put(&self, caller_id: ProducerId, ledger: &SpendLedger) -> Result<(), FetchAccessError> {
        let mut ledgers = self.ledgers.lock().map_err(|_| {
            FetchAccessError::Store("fetch quota memory store lock is poisoned".to_string())
        })?;
        ledgers.insert(caller_id, ledger.clone());
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FsFetchQuotaStore {
    root: PathBuf,
}

impl FsFetchQuotaStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, caller_id: ProducerId) -> PathBuf {
        self.root.join(format!("{}.dagcbor", caller_id.digest()))
    }

    fn load(&self, caller_id: ProducerId) -> Result<SpendLedger, FetchAccessError> {
        let path = self.path(caller_id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(SpendLedger::default()),
            Err(err) => return Err(FetchAccessError::Io(err)),
        };
        decode_dag_cbor(&bytes).map_err(|err| {
            FetchAccessError::Store(format!("fetch quota ledger decode failed: {err}"))
        })
    }

    fn put(&self, caller_id: ProducerId, ledger: &SpendLedger) -> Result<(), FetchAccessError> {
        fs::create_dir_all(&self.root).map_err(FetchAccessError::Io)?;
        let bytes = canonical_dag_cbor(ledger).map_err(|err| {
            FetchAccessError::Store(format!("fetch quota ledger encode failed: {err}"))
        })?;
        atomic_replace(&self.path(caller_id), &bytes)
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), FetchAccessError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("quota");
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(FetchAccessError::Io)?;
        file.write_all(bytes).map_err(FetchAccessError::Io)?;
        file.sync_all().map_err(FetchAccessError::Io)?;
        drop(file);
        fs::rename(&tmp, path).map_err(FetchAccessError::Io)?;
        Ok(())
    })();

    let _ = fs::remove_file(&tmp);
    result
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SpendLedger {
    entries: Vec<SpendEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SpendEntry {
    id: String,
    at_ms: u64,
    units: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchAccessError {
    #[error("fetch access denied: {0}")]
    Denied(String),
    #[error("{message}")]
    QuotaExceeded {
        retry_after_ms: Option<u64>,
        message: String,
    },
    #[error("fetch quota store error: {0}")]
    Store(String),
    #[error("fetch quota store I/O error: {0}")]
    Io(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_core::ProducerSigningKey;

    fn key(byte: u8) -> PublicKey {
        ProducerSigningKey::from_secret_bytes([byte; 32])
            .unwrap()
            .public_key()
    }

    fn request(max_output_units: Option<u64>) -> FetchRequestView {
        FetchRequestView {
            service: "codex".to_string(),
            method: "responses".to_string(),
            model: Some("gpt-5.5-codex".to_string()),
            max_output_units,
        }
    }

    fn route_policy() -> FetchRoutePolicy {
        FetchRoutePolicy {
            allowed_models: Some(BTreeSet::from(["gpt-5.5-codex".to_string()])),
            max_output_units: Some(100),
        }
    }

    #[test]
    fn intersect_takes_common_models_and_min_output() {
        let capabilities = FetchRoutePolicy {
            allowed_models: Some(BTreeSet::from(["a".to_string(), "b".to_string()])),
            max_output_units: Some(50),
        };
        let grant = FetchRoutePolicy {
            allowed_models: Some(BTreeSet::from(["b".to_string(), "c".to_string()])),
            max_output_units: Some(100),
        };

        let effective = capabilities.intersect(&grant);

        assert_eq!(
            effective.allowed_models,
            Some(BTreeSet::from(["b".to_string()]))
        );
        assert_eq!(effective.max_output_units, Some(50));
    }

    #[test]
    fn intersect_uses_whichever_side_is_set() {
        let restricted = FetchRoutePolicy {
            allowed_models: Some(BTreeSet::from(["a".to_string()])),
            max_output_units: Some(50),
        };
        let unrestricted = FetchRoutePolicy::default();

        assert_eq!(unrestricted.intersect(&restricted), restricted);
        assert_eq!(restricted.intersect(&unrestricted), restricted);
        assert_eq!(
            unrestricted.intersect(&FetchRoutePolicy::default()),
            FetchRoutePolicy::default()
        );
    }

    #[test]
    fn route_capabilities_cap_caller_grant() {
        let caller = key(1);
        // Caller grant allows the model and 100 output units, but the route
        // capability caps output at 10.
        let mut policy = FetchAccessPolicy::new([CallerAccess::explicit(
            caller,
            [FetchRouteGrant {
                route: FetchRoute::new("codex", "responses"),
                policy: route_policy(),
            }],
        )]);
        let capabilities = FetchRoutePolicy {
            allowed_models: None,
            max_output_units: Some(10),
        };

        let err = policy
            .authorize_admission(
                &caller,
                &request(Some(32)),
                1_000,
                "r1".to_string(),
                &capabilities,
            )
            .unwrap_err();

        assert!(matches!(err, FetchAccessError::Denied(_)));
    }

    #[test]
    fn authorizes_explicit_route_and_model() {
        let caller = key(1);
        let mut policy = FetchAccessPolicy::new([CallerAccess::explicit(
            caller,
            [FetchRouteGrant {
                route: FetchRoute::new("codex", "responses"),
                policy: route_policy(),
            }],
        )]);

        let admission = policy
            .authorize_admission(
                &caller,
                &request(Some(32)),
                1_000,
                "r1".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();

        assert!(admission.reservation.is_none());
    }

    #[test]
    fn denies_unknown_caller_and_route() {
        let caller = key(1);
        let mut policy = FetchAccessPolicy::new([CallerAccess::explicit(
            caller,
            [FetchRouteGrant {
                route: FetchRoute::new("codex", "responses"),
                policy: FetchRoutePolicy::default(),
            }],
        )]);

        assert!(matches!(
            policy
                .authorize_admission(
                    &key(2),
                    &request(Some(1)),
                    1_000,
                    "r1".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::Denied(_)
        ));
        assert!(matches!(
            policy
                .authorize_admission(
                    &caller,
                    &FetchRequestView {
                        service: "openai".to_string(),
                        method: "responses".to_string(),
                        model: Some("gpt-5.5-codex".to_string()),
                        max_output_units: Some(1),
                    },
                    1_000,
                    "r2".to_string(),
                    &FetchRoutePolicy::default(),
                )
                .unwrap_err(),
            FetchAccessError::Denied(_)
        ));
    }

    #[test]
    fn denies_model_and_output_over_limit() {
        let caller = key(1);
        let mut policy = FetchAccessPolicy::new([CallerAccess::explicit(
            caller,
            [FetchRouteGrant {
                route: FetchRoute::new("codex", "responses"),
                policy: route_policy(),
            }],
        )]);

        let mut wrong_model = request(Some(32));
        wrong_model.model = Some("other".to_string());
        assert!(matches!(
            policy
                .authorize_admission(
                    &caller,
                    &wrong_model,
                    1_000,
                    "r1".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::Denied(_)
        ));
        assert!(matches!(
            policy
                .authorize_admission(
                    &caller,
                    &request(Some(101)),
                    1_000,
                    "r2".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::Denied(_)
        ));
    }

    #[test]
    fn rate_limit_refills() {
        let caller = key(1);
        let mut access = CallerAccess::allow_all(caller);
        access.request_rate = Some(RequestRateLimit {
            capacity: 1.0,
            refill_per_sec: 1.0,
        });
        let mut policy = FetchAccessPolicy::new([access]);

        policy
            .authorize_admission(
                &caller,
                &request(None),
                1_000,
                "r1".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();
        assert!(matches!(
            policy
                .authorize_admission(
                    &caller,
                    &request(None),
                    1_000,
                    "r2".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::QuotaExceeded {
                retry_after_ms: Some(1000),
                ..
            }
        ));
        policy
            .authorize_admission(
                &caller,
                &request(None),
                2_000,
                "r3".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();
    }

    #[test]
    fn spend_quota_reserves_and_reconciles() {
        let caller = key(1);
        let mut access = CallerAccess::allow_all(caller);
        access.spend = Some(SpendLimit {
            max_units: 100,
            window: Duration::from_secs(60),
        });
        let mut policy = FetchAccessPolicy::new([access]);

        let admission = policy
            .authorize_admission(
                &caller,
                &request(Some(90)),
                1_000,
                "r1".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();
        assert!(matches!(
            policy
                .authorize_admission(
                    &caller,
                    &request(Some(20)),
                    1_000,
                    "r2".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::QuotaExceeded { .. }
        ));

        policy
            .reconcile_reservation(
                admission.reservation.as_ref(),
                Some(FetchUsage {
                    input_units: None,
                    output_units: Some(40),
                    total_units: None,
                }),
            )
            .unwrap();
        policy
            .authorize_admission(
                &caller,
                &request(Some(60)),
                1_000,
                "r3".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();
    }

    #[test]
    fn missing_usage_keeps_reservation() {
        let caller = key(1);
        let mut access = CallerAccess::allow_all(caller);
        access.spend = Some(SpendLimit {
            max_units: 50,
            window: Duration::from_secs(60),
        });
        let mut policy = FetchAccessPolicy::new([access]);

        let admission = policy
            .authorize_admission(
                &caller,
                &request(Some(50)),
                1_000,
                "r1".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();
        policy
            .reconcile_reservation(admission.reservation.as_ref(), None)
            .unwrap();

        assert!(matches!(
            policy
                .authorize_admission(
                    &caller,
                    &request(Some(1)),
                    1_000,
                    "r2".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::QuotaExceeded { .. }
        ));
    }

    #[test]
    fn spend_persists_across_fs_store_reload() {
        let root = std::env::temp_dir().join(format!(
            "hellas-fetch-quota-test-{}",
            Uuid::new_v4().simple()
        ));
        let caller = key(1);
        let mut access = CallerAccess::allow_all(caller);
        access.spend = Some(SpendLimit {
            max_units: 10,
            window: Duration::from_secs(60),
        });
        let mut policy = FetchAccessPolicy::with_quota_store(
            [access.clone()],
            FetchQuotaStoreBackend::fs(&root),
        );
        policy
            .authorize_admission(
                &caller,
                &request(Some(10)),
                1_000,
                "r1".to_string(),
                &FetchRoutePolicy::default(),
            )
            .unwrap();

        let mut reloaded =
            FetchAccessPolicy::with_quota_store([access], FetchQuotaStoreBackend::fs(&root));
        assert!(matches!(
            reloaded
                .authorize_admission(
                    &caller,
                    &request(Some(1)),
                    1_000,
                    "r2".to_string(),
                    &FetchRoutePolicy::default()
                )
                .unwrap_err(),
            FetchAccessError::QuotaExceeded { .. }
        ));
        let _ = fs::remove_dir_all(root);
    }
}
