use super::{EnsureDisposition, WeightsBundle, WeightsError, WeightsLocator};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[derive(Clone, Debug)]
enum EntryStatus {
    Queued,
    Loading,
    Ready,
    Failed(String),
}

struct Entry {
    status: EntryStatus,
    bundle: Option<Arc<WeightsBundle>>,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            status: EntryStatus::Queued,
            bundle: None,
        }
    }
}

pub(crate) struct EnsureTransition {
    pub disposition: EnsureDisposition,
    pub next_load: Option<WeightsLocator>,
}

#[derive(Default)]
pub(crate) struct WeightsState {
    entries: HashMap<WeightsLocator, Entry>,
    active: Option<WeightsLocator>,
    queue: VecDeque<WeightsLocator>,
}

impl WeightsState {
    pub(crate) fn ensure(
        &mut self,
        locator: WeightsLocator,
        denied_error: Option<String>,
    ) -> EnsureTransition {
        let disposition = match self.entries.get(&locator).map(|entry| &entry.status) {
            Some(EntryStatus::Ready) => EnsureDisposition::Ready,
            Some(EntryStatus::Failed(_)) => {
                if let Some(error) = denied_error {
                    EnsureDisposition::Failed(error)
                } else {
                    self.requeue(locator.clone());
                    EnsureDisposition::Queued
                }
            }
            Some(EntryStatus::Queued | EntryStatus::Loading) => {
                if self.is_pending(&locator) {
                    EnsureDisposition::InFlight
                } else {
                    self.requeue(locator.clone());
                    EnsureDisposition::Queued
                }
            }
            None => {
                if let Some(error) = denied_error {
                    EnsureDisposition::Failed(error)
                } else {
                    self.entries.insert(locator.clone(), Entry::default());
                    self.queue.push_back(locator.clone());
                    EnsureDisposition::Queued
                }
            }
        };

        let next_load = matches!(disposition, EnsureDisposition::Queued)
            .then(|| self.start_next())
            .flatten();

        EnsureTransition {
            disposition,
            next_load,
        }
    }

    pub(crate) fn bundle(
        &self,
        locator: &WeightsLocator,
    ) -> Result<Arc<WeightsBundle>, WeightsError> {
        match self
            .entries
            .get(locator)
            .map(|entry| (&entry.status, &entry.bundle))
        {
            Some((EntryStatus::Ready, Some(bundle))) => Ok(bundle.clone()),
            Some((EntryStatus::Ready, None)) => Err(WeightsError::UnknownKey),
            Some((EntryStatus::Failed(error), _)) => Err(WeightsError::Failed(error.clone())),
            Some((EntryStatus::Queued | EntryStatus::Loading, _)) => Err(WeightsError::NotReady),
            None => Err(WeightsError::UnknownKey),
        }
    }

    pub(crate) fn finish_ready(
        &mut self,
        locator: &WeightsLocator,
        bundle: Arc<WeightsBundle>,
    ) -> Option<WeightsLocator> {
        let entry = self.entries.entry(locator.clone()).or_default();
        entry.status = EntryStatus::Ready;
        entry.bundle = Some(bundle);
        if self.active.as_ref() == Some(locator) {
            self.active = None;
        }
        self.start_next()
    }

    pub(crate) fn finish_failed(
        &mut self,
        locator: &WeightsLocator,
        error: String,
    ) -> Option<WeightsLocator> {
        let entry = self.entries.entry(locator.clone()).or_default();
        entry.status = EntryStatus::Failed(error);
        entry.bundle = None;
        if self.active.as_ref() == Some(locator) {
            self.active = None;
        }
        self.start_next()
    }

    fn requeue(&mut self, locator: WeightsLocator) {
        if let Some(entry) = self.entries.get_mut(&locator) {
            entry.status = EntryStatus::Queued;
        }
        if !self.is_pending(&locator) {
            self.queue.push_back(locator);
        }
    }

    fn start_next(&mut self) -> Option<WeightsLocator> {
        if self.active.is_some() {
            return None;
        }

        let locator = self.queue.pop_front()?;
        self.active = Some(locator.clone());
        if let Some(entry) = self.entries.get_mut(&locator) {
            entry.status = EntryStatus::Loading;
        }
        Some(locator)
    }

    fn is_pending(&self, locator: &WeightsLocator) -> bool {
        self.active.as_ref() == Some(locator) || self.queue.iter().any(|queued| queued == locator)
    }

    #[cfg(test)]
    fn pending_occurrences(&self, locator: &WeightsLocator) -> usize {
        usize::from(self.active.as_ref() == Some(locator))
            + self
                .queue
                .iter()
                .filter(|queued| *queued == locator)
                .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn locator(index: u8) -> WeightsLocator {
        WeightsLocator {
            model_id: format!("model-{index}"),
            revision: "deadbeef".to_string(),
        }
    }

    fn dummy_bundle() -> Arc<WeightsBundle> {
        Arc::new(WeightsBundle {
            parameter_values: Default::default(),
            parameter_types: Default::default(),
        })
    }

    #[test]
    fn ensure_starts_loading_immediately_when_idle() {
        let mut state = WeightsState::default();
        let action = state.ensure(locator(0), None);
        assert_eq!(action.disposition, EnsureDisposition::Queued);
        assert_eq!(action.next_load, Some(locator(0)));
    }

    #[test]
    fn failed_locator_can_requeue_when_admission_is_allowed() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        state.ensure(locator.clone(), None);
        state.finish_failed(&locator, "boom".to_string());

        let action = state.ensure(locator.clone(), None);
        assert_eq!(action.disposition, EnsureDisposition::Queued);
        assert_eq!(action.next_load, Some(locator));
    }

    #[test]
    fn failed_locator_stays_failed_when_admission_is_denied() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        state.ensure(locator.clone(), None);
        state.finish_failed(&locator, "boom".to_string());

        let action = state.ensure(locator, Some("denied".to_string()));
        assert_eq!(
            action.disposition,
            EnsureDisposition::Failed("denied".to_string())
        );
        assert!(action.next_load.is_none());
    }

    #[test]
    fn ready_bundle_is_returned_after_completion() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        state.ensure(locator.clone(), None);
        state.finish_ready(&locator, dummy_bundle());

        assert!(state.bundle(&locator).is_ok());
    }

    proptest! {
        #[test]
        fn ensure_never_duplicates_pending_locators(sequence in vec(0u8..4, 0..64)) {
            let mut state = WeightsState::default();
            let locators: Vec<_> = (0..4).map(locator).collect();

            for index in sequence {
                let locator = locators[index as usize].clone();
                state.ensure(locator, None);

                for locator in &locators {
                    prop_assert!(state.pending_occurrences(locator) <= 1);
                }
            }
        }
    }
}
