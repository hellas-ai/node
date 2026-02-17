use super::FinalizationDiffs;
use commonware_cryptography::sha256::Digest;
use indexmap::IndexSet;
use std::collections::HashMap;

/// Tracks finalized payload ordering and pending persistence diffs.
pub(crate) struct FinalizationTracker {
    pending_diffs: HashMap<Digest, FinalizationDiffs>,
    finalized_payloads: IndexSet<Digest>,
    latest_finalized: Option<Digest>,
    max_finalized_payloads: usize,
}

impl FinalizationTracker {
    pub(crate) fn new(max_finalized_payloads: usize) -> Self {
        Self {
            pending_diffs: HashMap::new(),
            finalized_payloads: IndexSet::new(),
            latest_finalized: None,
            max_finalized_payloads,
        }
    }

    #[cfg(test)]
    pub(crate) fn latest_finalized(&self) -> Option<Digest> {
        self.latest_finalized
    }

    pub(crate) fn observe_finalized(&mut self, payload: Digest, diffs: Option<FinalizationDiffs>) {
        self.latest_finalized = Some(payload);
        let first_observation = self.finalized_payloads.insert(payload);
        debug_assert!(
            first_observation || diffs.is_none(),
            "duplicate finalization should not provide replacement diffs"
        );
        if first_observation && let Some(diffs) = diffs {
            self.pending_diffs.insert(payload, diffs);
        }
        self.trim_finalized_history();
    }

    pub(crate) fn is_finalized(&self, payload: Digest) -> bool {
        self.finalized_payloads.contains(&payload)
    }

    pub(crate) fn finalized_digests(&self) -> &IndexSet<Digest> {
        &self.finalized_payloads
    }

    pub(crate) fn next_unpersisted_finalization(&self) -> Option<(Digest, &FinalizationDiffs)> {
        self.finalized_payloads
            .iter()
            .find_map(|digest| self.pending_diffs.get(digest).map(|diffs| (*digest, diffs)))
    }

    pub(crate) fn unpersisted_finalization_count(&self) -> usize {
        self.pending_diffs.len()
    }

    pub(crate) fn mark_persisted(&mut self, payload: Digest) -> bool {
        let removed = self.pending_diffs.remove(&payload).is_some();
        if removed {
            self.trim_finalized_history();
        }
        removed
    }

    fn trim_finalized_history(&mut self) {
        while self.finalized_payloads.len() > self.max_finalized_payloads {
            let Some(oldest) = self.finalized_payloads.get_index(0).copied() else {
                break;
            };
            if self.pending_diffs.contains_key(&oldest) {
                // Keep oldest unpersisted finalizations so they can be retried later.
                break;
            }
            self.finalized_payloads.shift_remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_types::Coin;
    use commonware_cryptography::Signer;
    use commonware_cryptography::sha256::Digest;
    use hellas_types::PrivateKey;

    fn sample_diffs(seed: u8) -> FinalizationDiffs {
        FinalizationDiffs {
            created: vec![(
                Digest::from([seed; 32]),
                Coin {
                    owner: hellas_types::Address::from(PrivateKey::from_seed(u64::from(seed)).public_key()),
                    value: u64::from(seed),
                },
            )],
            deleted: vec![Digest::from([seed.wrapping_add(1); 32])],
        }
    }

    #[test_log::test]
    fn finalized_diffs_require_explicit_ack() {
        let mut tracker = FinalizationTracker::new(16);
        let canonical = Digest::from([2; 32]);

        tracker.observe_finalized(canonical, Some(sample_diffs(1)));
        assert_eq!(
            tracker
                .next_unpersisted_finalization()
                .map(|(digest, _)| digest),
            Some(canonical)
        );

        tracker.observe_finalized(canonical, None);
        assert_eq!(
            tracker
                .next_unpersisted_finalization()
                .map(|(digest, _)| digest),
            Some(canonical)
        );

        assert!(tracker.mark_persisted(canonical));
        assert!(tracker.next_unpersisted_finalization().is_none());

        tracker.observe_finalized(canonical, None);
        assert!(tracker.next_unpersisted_finalization().is_none());
    }

    #[test_log::test]
    fn unpersisted_diffs_are_retried_in_order() {
        let mut tracker = FinalizationTracker::new(16);
        let a = Digest::from([2; 32]);
        let b = Digest::from([3; 32]);

        tracker.observe_finalized(a, Some(sample_diffs(1)));
        tracker.observe_finalized(b, Some(sample_diffs(2)));
        assert_eq!(
            tracker
                .next_unpersisted_finalization()
                .map(|(digest, _)| digest),
            Some(a)
        );

        assert!(tracker.mark_persisted(a));
        assert_eq!(
            tracker
                .next_unpersisted_finalization()
                .map(|(digest, _)| digest),
            Some(b)
        );
    }

    #[test_log::test]
    fn trim_keeps_unpersisted_oldest_until_acked() {
        let mut tracker = FinalizationTracker::new(2);
        let a = Digest::from([1; 32]);
        let b = Digest::from([2; 32]);
        let c = Digest::from([3; 32]);

        tracker.observe_finalized(a, Some(sample_diffs(1)));
        tracker.observe_finalized(b, Some(sample_diffs(2)));
        tracker.observe_finalized(c, Some(sample_diffs(3)));

        assert!(tracker.is_finalized(a));
        assert!(tracker.is_finalized(b));
        assert!(tracker.is_finalized(c));

        assert!(tracker.mark_persisted(a));
        assert!(!tracker.is_finalized(a));
        assert!(tracker.is_finalized(b));
        assert!(tracker.is_finalized(c));
    }
}
