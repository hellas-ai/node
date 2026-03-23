use super::{ExecutionContext, WeightsBundle, WeightsError, WeightsLocator};
use crate::backend::ExecBackend;
use catgrad_llm::Runtime;
use catgrad_llm::helpers::WeightPostProcess;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
enum EntryStatus {
    Queued,
    Loading,
    Ready,
    Failed(String),
}

struct RuntimeEntry {
    runtime: Arc<Runtime<ExecBackend>>,
    programs: HashMap<String, Arc<ExecutionContext>>,
}

struct Entry {
    status: EntryStatus,
    bundle: Option<Arc<WeightsBundle>>,
    runtimes: HashMap<WeightPostProcess, RuntimeEntry>,
    generation: u64,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            status: EntryStatus::Queued,
            bundle: None,
            runtimes: HashMap::new(),
            generation: 0,
        }
    }
}

pub(crate) struct ProgramLookup {
    pub generation: u64,
    pub bundle: Arc<WeightsBundle>,
    pub runtime: Option<Arc<Runtime<ExecBackend>>>,
    pub program: Option<Arc<ExecutionContext>>,
}

pub(crate) enum CacheProgramOutcome {
    Cached(Arc<ExecutionContext>),
    Stale,
}

pub(crate) enum CacheRuntimeOutcome {
    Cached,
    Stale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntryStatusSnapshot {
    Queued,
    Loading,
    Ready,
    Failed(String),
}

#[derive(Default)]
pub(crate) struct WeightsState {
    entries: HashMap<WeightsLocator, Entry>,
}

impl WeightsState {
    pub(crate) fn status(&self, locator: &WeightsLocator) -> Option<EntryStatusSnapshot> {
        self.entries.get(locator).map(|entry| match &entry.status {
            EntryStatus::Queued => EntryStatusSnapshot::Queued,
            EntryStatus::Loading => EntryStatusSnapshot::Loading,
            EntryStatus::Ready => EntryStatusSnapshot::Ready,
            EntryStatus::Failed(error) => EntryStatusSnapshot::Failed(error.clone()),
        })
    }

    pub(crate) fn mark_queued(&mut self, locator: WeightsLocator) {
        let entry = self.entries.entry(locator).or_default();
        entry.status = EntryStatus::Queued;
    }

    pub(crate) fn mark_loading(&mut self, locator: &WeightsLocator) -> Result<(), WeightsError> {
        let entry = self
            .entries
            .get_mut(locator)
            .ok_or(WeightsError::UnknownKey)?;
        match &entry.status {
            EntryStatus::Failed(error) => Err(WeightsError::Failed(error.clone())),
            _ => {
                entry.status = EntryStatus::Loading;
                Ok(())
            }
        }
    }

    pub(crate) fn finish_ready(&mut self, locator: &WeightsLocator, bundle: Arc<WeightsBundle>) {
        let entry = self.entries.entry(locator.clone()).or_default();
        entry.status = EntryStatus::Ready;
        entry.bundle = Some(bundle);
        entry.runtimes.clear();
        entry.generation = entry.generation.wrapping_add(1);
    }

    pub(crate) fn finish_failed(&mut self, locator: &WeightsLocator, error: String) {
        let entry = self.entries.entry(locator.clone()).or_default();
        entry.status = EntryStatus::Failed(error);
        entry.bundle = None;
        entry.runtimes.clear();
        entry.generation = entry.generation.wrapping_add(1);
    }

    pub(crate) fn lookup_program(
        &self,
        locator: &WeightsLocator,
        weight_post_process: WeightPostProcess,
        program_id: &str,
    ) -> Result<ProgramLookup, WeightsError> {
        let entry = self.entries.get(locator).ok_or(WeightsError::UnknownKey)?;
        match &entry.status {
            EntryStatus::Ready => {
                let runtime_entry = entry.runtimes.get(&weight_post_process);
                Ok(ProgramLookup {
                    generation: entry.generation,
                    bundle: entry.bundle.clone().ok_or(WeightsError::UnknownKey)?,
                    runtime: runtime_entry.map(|runtime| runtime.runtime.clone()),
                    program: runtime_entry
                        .and_then(|runtime| runtime.programs.get(program_id))
                        .cloned(),
                })
            }
            EntryStatus::Failed(error) => Err(WeightsError::Failed(error.clone())),
            EntryStatus::Queued | EntryStatus::Loading => Err(WeightsError::NotReady),
        }
    }

    pub(crate) fn cache_runtime(
        &mut self,
        locator: &WeightsLocator,
        generation: u64,
        weight_post_process: WeightPostProcess,
        runtime: Arc<Runtime<ExecBackend>>,
    ) -> Result<CacheRuntimeOutcome, WeightsError> {
        let entry = self
            .entries
            .get_mut(locator)
            .ok_or(WeightsError::UnknownKey)?;
        match &entry.status {
            EntryStatus::Ready => {
                if entry.generation != generation {
                    return Ok(CacheRuntimeOutcome::Stale);
                }

                let cached = entry
                    .runtimes
                    .entry(weight_post_process)
                    .or_insert_with(|| RuntimeEntry {
                        runtime,
                        programs: HashMap::new(),
                    });
                let _ = cached;
                Ok(CacheRuntimeOutcome::Cached)
            }
            EntryStatus::Failed(error) => Err(WeightsError::Failed(error.clone())),
            EntryStatus::Queued | EntryStatus::Loading => Err(WeightsError::NotReady),
        }
    }

    pub(crate) fn cache_program(
        &mut self,
        locator: &WeightsLocator,
        generation: u64,
        weight_post_process: WeightPostProcess,
        program_id: String,
        program: Arc<ExecutionContext>,
    ) -> Result<CacheProgramOutcome, WeightsError> {
        let entry = self
            .entries
            .get_mut(locator)
            .ok_or(WeightsError::UnknownKey)?;
        match &entry.status {
            EntryStatus::Ready => {
                if entry.generation != generation {
                    return Ok(CacheProgramOutcome::Stale);
                }

                let runtime = entry
                    .runtimes
                    .get_mut(&weight_post_process)
                    .ok_or(WeightsError::UnknownKey)?;
                let cached = runtime.programs.entry(program_id).or_insert(program);
                Ok(CacheProgramOutcome::Cached(cached.clone()))
            }
            EntryStatus::Failed(error) => Err(WeightsError::Failed(error.clone())),
            EntryStatus::Queued | EntryStatus::Loading => Err(WeightsError::NotReady),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catgrad::category::lang::{Term, TypedTerm};
    use catgrad::path::Path;
    use catgrad_llm::helpers::WeightPostProcess;
    use catgrad_llm::{Program, ProgramSpec};

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

    fn dummy_runtime() -> Arc<Runtime<ExecBackend>> {
        Arc::new(
            Runtime::new(
                crate::backend::create_backend().unwrap(),
                WeightPostProcess::None,
                Default::default(),
                Default::default(),
            )
            .unwrap(),
        )
    }

    fn dummy_program() -> Program {
        Program::from_spec(ProgramSpec::from_typed_term(
            TypedTerm {
                term: Term::empty(),
                source_type: vec![],
                target_type: vec![],
            },
            Path::empty(),
            vec![],
            1,
            WeightPostProcess::None,
        ))
        .unwrap()
    }

    fn dummy_execution_context() -> Arc<ExecutionContext> {
        Arc::new(ExecutionContext::new(Arc::new(
            dummy_runtime().bind(dummy_program()).unwrap(),
        )))
    }

    #[test]
    fn mark_queued_inserts_missing_entry() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        state.mark_queued(locator.clone());

        assert_eq!(state.status(&locator), Some(EntryStatusSnapshot::Queued));
    }

    #[test]
    fn mark_loading_updates_existing_entry() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        state.mark_queued(locator.clone());

        state.mark_loading(&locator).unwrap();
        assert_eq!(state.status(&locator), Some(EntryStatusSnapshot::Loading));
    }

    #[test]
    fn ready_lookup_returns_bundle_after_completion() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        let bundle = dummy_bundle();
        state.mark_queued(locator.clone());
        state.finish_ready(&locator, bundle.clone());

        let lookup = state
            .lookup_program(&locator, WeightPostProcess::None, "missing")
            .unwrap();
        assert!(Arc::ptr_eq(&lookup.bundle, &bundle));
    }

    #[test]
    fn cache_runtime_returns_stale_after_generation_changes() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        let bundle = dummy_bundle();
        state.mark_queued(locator.clone());
        state.finish_ready(&locator, bundle.clone());

        let generation = state
            .lookup_program(&locator, WeightPostProcess::None, "missing")
            .unwrap()
            .generation;

        state.finish_ready(&locator, bundle);

        let runtime = dummy_runtime();

        assert!(matches!(
            state
                .cache_runtime(&locator, generation, WeightPostProcess::None, runtime)
                .unwrap(),
            CacheRuntimeOutcome::Stale
        ));
    }

    #[test]
    fn cache_program_returns_stale_after_generation_changes() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        let bundle = dummy_bundle();
        state.mark_queued(locator.clone());
        state.finish_ready(&locator, bundle.clone());

        let generation = state
            .lookup_program(&locator, WeightPostProcess::None, "missing")
            .unwrap()
            .generation;

        let runtime = dummy_runtime();
        let _ = state
            .cache_runtime(&locator, generation, WeightPostProcess::None, runtime)
            .unwrap();

        state.finish_ready(&locator, bundle);

        let bound_program = dummy_execution_context();

        assert!(matches!(
            state
                .cache_program(
                    &locator,
                    generation,
                    WeightPostProcess::None,
                    "program".to_string(),
                    bound_program,
                )
                .unwrap(),
            CacheProgramOutcome::Stale
        ));
    }

    #[test]
    fn finish_failed_marks_entry_failed() {
        let mut state = WeightsState::default();
        let locator = locator(0);
        state.mark_queued(locator.clone());

        state.finish_failed(&locator, "boom".to_string());
        assert_eq!(
            state.status(&locator),
            Some(EntryStatusSnapshot::Failed("boom".to_string()))
        );
    }
}
