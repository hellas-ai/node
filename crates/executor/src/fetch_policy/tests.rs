use super::*;
use hellas_rpc::ProducerSigningKey;

fn fs_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fetch-quota-tests")
        .join(format!("{name}-{}", Uuid::new_v4().simple()))
}

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

fn input(byte: u8) -> InputCommitment {
    InputCommitment::from_digest(Digest::from_bytes([byte; 32]))
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
            input(1),
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
            input(1),
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
                input(1),
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
                input(2),
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
                input(1),
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
                input(2),
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
            input(1),
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
                input(2),
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
            input(3),
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
            input(1),
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
                input(2),
                &FetchRoutePolicy::default()
            )
            .unwrap_err(),
        FetchAccessError::QuotaExceeded { .. }
    ));

    policy
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    policy
        .reconcile_reservation(admission.reservation.as_ref(), 40, 1_500)
        .unwrap();
    policy
        .authorize_admission(
            &caller,
            &request(Some(60)),
            1_000,
            "r3".to_string(),
            input(3),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
}

#[test]
fn queued_pending_spend_cannot_age_out_before_dispatch() {
    let caller = key(1);
    let caller_id = ProducerId::from_public_key(&caller);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 100,
        window: Duration::from_secs(1),
    });
    let store = MemoryFetchQuotaStore::default();
    let mut policy = FetchAccessPolicy::with_quota_store(
        [access],
        FetchQuotaStoreBackend::Memory(store.clone()),
    );
    let admission = policy
        .authorize_admission(
            &caller,
            &request(Some(90)),
            1_000,
            "long-running".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();

    let pending = store.load(caller_id).unwrap();
    assert_eq!(pending.entries.len(), 1);
    assert_eq!(pending.entries[0].lifecycle(), SpendLifecycle::Pending);
    assert_eq!(pending.entries[0].at_ms, u64::MAX);

    assert!(matches!(
        policy
            .authorize_admission(
                &caller,
                &request(Some(11)),
                3_000,
                "would-overbook".to_string(),
                input(2),
                &FetchRoutePolicy::default(),
            )
            .unwrap_err(),
        FetchAccessError::QuotaExceeded { .. }
    ));

    policy
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    policy
        .reconcile_reservation(admission.reservation.as_ref(), 40, 3_000)
        .unwrap();
    let ledger = store.load(caller_id).unwrap();
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].units, 40);
    assert_eq!(ledger.entries[0].at_ms, 3_000);
    assert!(!ledger.entries[0].reserved);

    policy
        .authorize_admission(
            &caller,
            &request(Some(60)),
            3_000,
            "after-reconcile".to_string(),
            input(3),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
}

#[test]
fn worst_case_failure_spend_denies_immediately_then_expires_after_its_window() {
    const ADMITTED_AT_MS: u64 = 1_000;
    const FAILED_AT_MS: u64 = 2_000;
    const WINDOW_MS: u64 = 60_000;

    let caller = key(1);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 100,
        window: Duration::from_millis(WINDOW_MS),
    });
    let store = MemoryFetchQuotaStore::default();
    let mut policy = FetchAccessPolicy::with_quota_store(
        [access],
        FetchQuotaStoreBackend::Memory(store.clone()),
    );
    let admission = policy
        .authorize_admission(
            &caller,
            &request(Some(90)),
            ADMITTED_AT_MS,
            "failed-dispatch".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    let reservation = admission.reservation.as_ref().unwrap();

    policy.activate_reservation(Some(reservation)).unwrap();
    policy
        .reconcile_reservation(Some(reservation), reservation.reserved_units, FAILED_AT_MS)
        .unwrap();

    assert!(matches!(
        policy
            .authorize_admission(
                &caller,
                &request(Some(11)),
                FAILED_AT_MS,
                "immediate-retry".to_string(),
                input(2),
                &FetchRoutePolicy::default(),
            )
            .unwrap_err(),
        FetchAccessError::QuotaExceeded { .. }
    ));
    policy
        .authorize_admission(
            &caller,
            &request(Some(100)),
            FAILED_AT_MS + WINDOW_MS,
            "after-window".to_string(),
            input(3),
            &FetchRoutePolicy::default(),
        )
        .unwrap();

    let caller_id = ProducerId::from_public_key(&caller);
    let ledger = store.load(caller_id).unwrap();
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].id, "after-window");
    assert!(ledger.entries[0].reserved);
}

#[test]
fn zero_billable_completion_removes_ledger_entry() {
    let caller = key(1);
    let caller_id = ProducerId::from_public_key(&caller);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 100,
        window: Duration::from_secs(60),
    });
    let store = MemoryFetchQuotaStore::default();
    let mut policy = FetchAccessPolicy::with_quota_store(
        [access],
        FetchQuotaStoreBackend::Memory(store.clone()),
    );
    let admission = policy
        .authorize_admission(
            &caller,
            &request(Some(90)),
            1_000,
            "r1".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();

    policy
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    policy
        .reconcile_reservation(admission.reservation.as_ref(), 0, 1_500)
        .unwrap();

    assert!(store.load(caller_id).unwrap().entries.is_empty());
}

#[test]
fn queued_cancellation_releases_reserved_spend() {
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
            "queued".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();

    policy
        .cancel_reservation(admission.reservation.as_ref())
        .unwrap();
    policy
        .authorize_admission(
            &caller,
            &request(Some(100)),
            1_000,
            "replacement".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
}

#[test]
fn spend_ledger_entry_count_is_bounded() {
    let caller = key(1);
    let caller_id = ProducerId::from_public_key(&caller);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: u64::MAX,
        window: Duration::from_secs(60),
    });
    let store = MemoryFetchQuotaStore::default();
    store
        .put(
            caller_id,
            &SpendLedger {
                entries: (0..MAX_FETCH_SPEND_LEDGER_ENTRIES)
                    .map(|index| SpendEntry {
                        id: format!("r{index}"),
                        at_ms: 1_000,
                        units: 1,
                        reserved: false,
                        lifecycle: Some(SpendLifecycle::Spent),
                        input_commitment: None,
                    })
                    .collect(),
            },
        )
        .unwrap();
    let mut policy =
        FetchAccessPolicy::with_quota_store([access], FetchQuotaStoreBackend::Memory(store));

    let error = policy
        .authorize_admission(
            &caller,
            &request(Some(1)),
            1_000,
            "overflow".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap_err();

    assert!(matches!(error, FetchAccessError::QuotaExceeded { .. }));
    assert!(error.to_string().contains("4096-entry limit"));
}

#[test]
fn spend_quota_rejects_billable_units_above_the_reservation() {
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
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();

    policy
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    assert!(matches!(
        policy
            .reconcile_reservation(admission.reservation.as_ref(), 91, 1_500)
            .unwrap_err(),
        FetchAccessError::BillableUnitsExceedReservation {
            billable_units: 91,
            reserved_units: 90,
        }
    ));
    policy
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "r2".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
}

#[test]
fn pending_restart_is_reclaimed_from_memory_store() {
    let caller = key(1);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 10,
        window: Duration::from_secs(60),
    });
    let store = MemoryFetchQuotaStore::default();
    let mut policy = FetchAccessPolicy::with_quota_store(
        [access.clone()],
        FetchQuotaStoreBackend::Memory(store.clone()),
    );
    policy
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "previous-process".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    drop(policy);

    let mut removed = Vec::new();
    let mut restarted =
        FetchAccessPolicy::with_quota_store([access], FetchQuotaStoreBackend::Memory(store));
    assert_eq!(
        restarted
            .recover_reservations(2_000, |input| {
                removed.push(input);
                Ok(())
            })
            .unwrap(),
        1
    );
    assert_eq!(removed, [input(1)]);
    restarted
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "new-process".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
}

#[test]
fn pending_restart_is_reclaimed_from_filesystem_store() {
    let root = fs_root("pending-recovery");
    let caller = key(1);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 10,
        window: Duration::from_secs(60),
    });
    let mut policy =
        FetchAccessPolicy::with_quota_store([access.clone()], FetchQuotaStoreBackend::fs(&root));
    policy
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "previous-process".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    drop(policy);

    let mut restarted =
        FetchAccessPolicy::with_quota_store([access], FetchQuotaStoreBackend::fs(&root));
    let mut removed = Vec::new();
    assert_eq!(
        restarted
            .recover_reservations(2_000, |input| {
                removed.push(input);
                Ok(())
            })
            .unwrap(),
        1
    );
    assert_eq!(removed, [input(1)]);
    restarted
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "new-process".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn dispatched_reservation_becomes_worst_case_spend_for_one_fresh_window() {
    let root = fs_root("dispatched-recovery");
    let caller = key(1);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 10,
        window: Duration::from_millis(100),
    });
    let mut policy =
        FetchAccessPolicy::with_quota_store([access.clone()], FetchQuotaStoreBackend::fs(&root));
    let admission = policy
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "possibly-dispatched".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    policy
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    drop(policy);

    let mut marker_removals = 0;
    let restarted_store = FsFetchQuotaStore::new(&root);
    let mut restarted = FetchAccessPolicy::with_quota_store(
        [access],
        FetchQuotaStoreBackend::Fs(restarted_store.clone()),
    );
    assert_eq!(
        restarted
            .recover_reservations(10_000, |_| {
                marker_removals += 1;
                Ok(())
            })
            .unwrap(),
        1
    );
    assert_eq!(marker_removals, 0);
    let caller_id = ProducerId::from_public_key(&caller);
    let loaded = restarted_store.load(caller_id).unwrap();
    assert_eq!(loaded.entries[0].lifecycle(), SpendLifecycle::Spent);
    assert_eq!(loaded.entries[0].at_ms, 10_000);
    let error = restarted
        .authorize_admission(
            &caller,
            &request(Some(1)),
            10_099,
            "within-recovery-window".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        FetchAccessError::QuotaExceeded {
            retry_after_ms: Some(1),
            ..
        }
    ));
    restarted
        .authorize_admission(
            &caller,
            &request(Some(10)),
            10_100,
            "after-recovery-window".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cancelling_restart_reclaims_marker_and_reservation_without_charge() {
    let caller = key(1);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 10,
        window: Duration::from_secs(60),
    });
    let store = MemoryFetchQuotaStore::default();
    let mut policy = FetchAccessPolicy::with_quota_store(
        [access.clone()],
        FetchQuotaStoreBackend::Memory(store.clone()),
    );
    let admission = policy
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "cancel-at-crash".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    policy
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    policy
        .begin_reservation_cancellation(admission.reservation.as_ref())
        .unwrap();
    drop(policy);

    let mut removed = Vec::new();
    let mut restarted =
        FetchAccessPolicy::with_quota_store([access], FetchQuotaStoreBackend::Memory(store));
    assert_eq!(
        restarted
            .recover_reservations(2_000, |commitment| {
                removed.push(commitment);
                Ok(())
            })
            .unwrap(),
        1
    );
    assert_eq!(removed, [input(1)]);
    restarted
        .authorize_admission(
            &caller,
            &request(Some(10)),
            2_000,
            "replacement".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
}

#[test]
fn actual_legacy_entry_is_charged_for_one_fresh_window_on_upgrade() {
    #[derive(Serialize)]
    struct LegacySpendLedger {
        entries: Vec<LegacySpendEntry>,
    }

    #[derive(Serialize)]
    struct LegacySpendEntry {
        id: String,
        at_ms: u64,
        units: u64,
    }

    let root = fs_root("legacy-actual");
    let caller = key(1);
    let caller_id = ProducerId::from_public_key(&caller);
    let store = FsFetchQuotaStore::new(&root);
    fs::create_dir_all(&root).unwrap();
    let legacy = LegacySpendLedger {
        entries: vec![LegacySpendEntry {
            id: "legacy-ambiguous".to_string(),
            at_ms: 1_000,
            units: 10,
        }],
    };
    atomic_replace(
        &store.path(caller_id),
        &canonical_dag_cbor(&legacy).unwrap(),
    )
    .unwrap();

    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 10,
        window: Duration::from_millis(100),
    });
    let mut restarted =
        FetchAccessPolicy::with_quota_store([access], FetchQuotaStoreBackend::Fs(store.clone()));
    assert_eq!(
        restarted
            .recover_reservations(10_000, |_| {
                panic!("actual legacy entries have no trustworthy marker commitment")
            })
            .unwrap(),
        1
    );
    let loaded = store.load(caller_id).unwrap();
    assert_eq!(loaded.entries[0].lifecycle(), SpendLifecycle::Spent);
    assert_eq!(loaded.entries[0].at_ms, 10_000);
    assert!(matches!(
        restarted
            .authorize_admission(
                &caller,
                &request(Some(1)),
                10_099,
                "still-charged".to_string(),
                input(2),
                &FetchRoutePolicy::default(),
            )
            .unwrap_err(),
        FetchAccessError::QuotaExceeded { .. }
    ));
    restarted
        .authorize_admission(
            &caller,
            &request(Some(10)),
            10_100,
            "fresh-window-ended".to_string(),
            input(2),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn filesystem_quota_root_has_one_process_lifetime_owner() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};

    let root = fs_root("exclusive-owner");
    fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fetch_policy::tests::hold_filesystem_quota_root",
            "--ignored",
            "--nocapture",
        ])
        .env("HELLAS_FETCH_QUOTA_LOCK_TEST_ROOT", &root)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "lock holder exited"
        );
        if line == "locked\n" {
            break;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    // Replacing the child used by the old implementation must not replace
    // the ownership claim: the live lock belongs to the directory inode.
    let obsolete_child = root.join(".hellas-fetch-quota.lock");
    match fs::remove_file(&obsolete_child) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove obsolete child: {error}"),
    }
    fs::write(&obsolete_child, b"replacement").unwrap();
    let competitor = FsFetchQuotaStore::new(&root);
    let error = competitor.init().unwrap_err();
    assert!(
        matches!(&error, FetchAccessError::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(
        error
            .to_string()
            .contains("already open by another executor")
    );

    child.kill().unwrap();
    child.wait().unwrap();
    competitor
        .init()
        .expect("the released root can be reopened");
    drop(competitor);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn filesystem_quota_ledger_rejects_a_fifo_without_blocking() {
    let root = fs_root("fifo-ledger");
    let store = FsFetchQuotaStore::new(&root);
    store.init().unwrap();
    assert!(!root.join(".hellas-fetch-quota.lock").exists());
    let caller_id = ProducerId::from_public_key(&key(91));
    let status = std::process::Command::new("mkfifo")
        .arg(store.path(caller_id))
        .status()
        .unwrap();
    assert!(status.success(), "the fixture needs a FIFO");

    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = store.clone();
    std::thread::spawn(move || {
        let _ = sender.send(reader.load(caller_id));
    });
    let error = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("quota ledger open blocked on a FIFO")
        .expect_err("quota ledger must be a regular file");
    assert!(
        matches!(error, FetchAccessError::Io(error) if error.kind() == io::ErrorKind::InvalidInput)
    );
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "started by filesystem_quota_root_has_one_process_lifetime_owner"]
fn hold_filesystem_quota_root() {
    let root = std::env::var_os("HELLAS_FETCH_QUOTA_LOCK_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap();
    let store = FsFetchQuotaStore::new(root);
    store.init().unwrap();
    store
        .clone()
        .init()
        .expect("clones share the same ownership claim");
    println!("locked");
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn old_reader_cannot_age_new_pending_or_dispatched_entries() {
    #[derive(Deserialize)]
    struct LegacySpendLedger {
        entries: Vec<LegacySpendEntry>,
    }

    #[derive(Deserialize)]
    struct LegacySpendEntry {
        #[allow(dead_code)]
        id: String,
        at_ms: u64,
        #[allow(dead_code)]
        units: u64,
    }

    let caller = key(1);
    let caller_id = ProducerId::from_public_key(&caller);
    let mut access = CallerAccess::allow_all(caller);
    access.spend = Some(SpendLimit {
        max_units: 10,
        window: Duration::from_millis(100),
    });
    let store = MemoryFetchQuotaStore::default();
    let mut policy = FetchAccessPolicy::with_quota_store(
        [access],
        FetchQuotaStoreBackend::Memory(store.clone()),
    );
    let admission = policy
        .authorize_admission(
            &caller,
            &request(Some(10)),
            1_000,
            "new-entry".to_string(),
            input(1),
            &FetchRoutePolicy::default(),
        )
        .unwrap();

    for activate in [false, true] {
        if activate {
            policy
                .activate_reservation(admission.reservation.as_ref())
                .unwrap();
        }
        let bytes = canonical_dag_cbor(&store.load(caller_id).unwrap()).unwrap();
        let old: LegacySpendLedger = decode_dag_cbor(&bytes).unwrap();
        assert_eq!(old.entries[0].at_ms, u64::MAX);
        assert!(u64::MAX.saturating_sub(old.entries[0].at_ms) < 100);
    }
}
