use super::{Bundle, Error, HuggingFaceLocator};
use crate::programs::ExecutionContext;
use hellas_runtime::cid::Cid;
use hellas_runtime::graph::Program;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Queued,
    Loading,
    Ready,
    Failed(String),
}

struct Entry {
    status: Status,
    bundle: Option<Arc<Bundle>>,
    /// Programs bound against this entry's [`Bundle::inputs`], keyed by
    /// canonical [`Cid<Program>`]. Lives here (not on
    /// [`crate::programs::Cache`]) because it's always scoped to a single
    /// `ParameterBundle` and a single `(model, revision, dtype)` cache generation —
    /// when the bundle reloads we need the program map to be invalidated
    /// atomically with it.
    programs: HashMap<Cid<Program>, Arc<ExecutionContext>>,
    generation: u64,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            status: Status::Queued,
            bundle: None,
            programs: HashMap::new(),
            generation: 0,
        }
    }
}

pub(crate) struct ProgramLookup {
    pub generation: u64,
    pub bundle: Arc<Bundle>,
    pub program: Option<Arc<ExecutionContext>>,
}

pub(crate) enum CacheProgramOutcome {
    Cached(Arc<ExecutionContext>),
    Stale,
}

/// Shared status check for callsites that only operate on `Ready` entries.
/// Maps the non-ready statuses to the canonical [`Error`], stamping the
/// caller's locator into each variant so the resulting message is useful.
fn require_ready(locator: &HuggingFaceLocator, status: &Status) -> Result<(), Error> {
    match status {
        Status::Ready => Ok(()),
        Status::Failed(error) => Err(Error::Failed {
            locator: locator.clone(),
            message: error.clone(),
        }),
        Status::Queued | Status::Loading => Err(Error::NotReady {
            locator: locator.clone(),
        }),
    }
}

#[derive(Default)]
pub(crate) struct State {
    entries: HashMap<HuggingFaceLocator, Entry>,
}

impl State {
    pub(crate) fn list_models(&self) -> Vec<(HuggingFaceLocator, Status)> {
        self.entries
            .iter()
            .map(|(locator, entry)| (locator.clone(), entry.status.clone()))
            .collect()
    }

    pub(crate) fn status(&self, locator: &HuggingFaceLocator) -> Option<Status> {
        self.entries.get(locator).map(|entry| entry.status.clone())
    }

    pub(crate) fn mark_queued(&mut self, locator: HuggingFaceLocator) {
        let entry = self.entries.entry(locator).or_default();
        entry.status = Status::Queued;
    }

    pub(crate) fn mark_loading(&mut self, locator: &HuggingFaceLocator) -> Result<(), Error> {
        let entry = self
            .entries
            .get_mut(locator)
            .ok_or_else(|| Error::UnknownKey {
                locator: locator.clone(),
            })?;
        if let Status::Failed(error) = &entry.status {
            return Err(Error::Failed {
                locator: locator.clone(),
                message: error.clone(),
            });
        }
        entry.status = Status::Loading;
        Ok(())
    }

    pub(crate) fn finish_ready(&mut self, locator: &HuggingFaceLocator, bundle: Arc<Bundle>) {
        let entry = self.entries.entry(locator.clone()).or_default();
        entry.status = Status::Ready;
        entry.bundle = Some(bundle);
        entry.programs.clear();
        entry.generation = entry.generation.wrapping_add(1);
    }

    pub(crate) fn finish_failed(&mut self, locator: &HuggingFaceLocator, error: String) {
        let entry = self.entries.entry(locator.clone()).or_default();
        entry.status = Status::Failed(error);
        entry.bundle = None;
        entry.programs.clear();
        entry.generation = entry.generation.wrapping_add(1);
    }

    pub(crate) fn lookup_program(
        &self,
        locator: &HuggingFaceLocator,
        program_id: Cid<Program>,
    ) -> Result<ProgramLookup, Error> {
        let entry = self.entries.get(locator).ok_or_else(|| Error::UnknownKey {
            locator: locator.clone(),
        })?;
        require_ready(locator, &entry.status)?;
        Ok(ProgramLookup {
            generation: entry.generation,
            bundle: entry.bundle.clone().ok_or_else(|| Error::UnknownKey {
                locator: locator.clone(),
            })?,
            program: entry.programs.get(&program_id).cloned(),
        })
    }

    pub(crate) fn cache_program(
        &mut self,
        locator: &HuggingFaceLocator,
        generation: u64,
        program: Arc<ExecutionContext>,
    ) -> Result<CacheProgramOutcome, Error> {
        let entry = self
            .entries
            .get_mut(locator)
            .ok_or_else(|| Error::UnknownKey {
                locator: locator.clone(),
            })?;
        require_ready(locator, &entry.status)?;
        if entry.generation != generation {
            return Ok(CacheProgramOutcome::Stale);
        }
        let program_id = program.bound_program().program().id();
        let cached = entry.programs.entry(program_id).or_insert(program);
        Ok(CacheProgramOutcome::Cached(cached.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catgrad::category::lang::{Term, TypedTerm};
    use catgrad::interpreter;
    use catgrad::path::Path;
    use hellas_runtime::graph::{BoundProgram, Program};

    fn locator(index: u8) -> HuggingFaceLocator {
        HuggingFaceLocator::new(
            format!("model-{index}"),
            "deadbeef".to_string(),
            catgrad::prelude::Dtype::F32,
        )
    }

    fn empty_bundle() -> Arc<Bundle> {
        let inputs = interpreter::Parameters::default();
        Arc::new(Bundle { inputs })
    }

    fn dummy_spec() -> Program {
        hellas_runtime::graph::ProgramSpec {
            typed_term: TypedTerm {
                term: Term::empty(),
                source_type: vec![],
                target_type: vec![],
            },
            module_path: Path::empty(),
            empty_state_type: vec![],
            max_sequence_length: 1,
            extra_nat_chunk_size: None,
        }
        .into()
    }

    fn dummy_execution_context(bundle: &Arc<Bundle>) -> Arc<ExecutionContext> {
        let backend = crate::backend::create_backend().unwrap();
        Arc::new(
            ExecutionContext::new(Arc::new(
                BoundProgram::bind(&bundle.inputs, &backend, dummy_spec())
                    .map_err(hellas_runtime::LLMError::from)
                    .unwrap(),
            ))
            .unwrap(),
        )
    }

    #[test]
    fn mark_queued_inserts_missing_entry() {
        let mut state = State::default();
        let locator = locator(0);
        state.mark_queued(locator.clone());

        assert_eq!(state.status(&locator), Some(Status::Queued));
    }

    #[test]
    fn mark_loading_updates_existing_entry() {
        let mut state = State::default();
        let locator = locator(0);
        state.mark_queued(locator.clone());

        state.mark_loading(&locator).unwrap();
        assert_eq!(state.status(&locator), Some(Status::Loading));
    }

    #[test]
    fn ready_lookup_returns_bundle_after_completion() {
        let mut state = State::default();
        let locator = locator(0);
        let bundle = empty_bundle();
        state.mark_queued(locator.clone());
        state.finish_ready(&locator, bundle.clone());

        let lookup = state
            .lookup_program(&locator, Cid::<Program>::from_bytes([0; 32]))
            .unwrap();
        assert!(Arc::ptr_eq(&lookup.bundle, &bundle));
    }

    #[test]
    fn cache_program_returns_stale_after_generation_changes() {
        let mut state = State::default();
        let locator = locator(0);
        let bundle = empty_bundle();
        state.mark_queued(locator.clone());
        state.finish_ready(&locator, bundle.clone());

        let generation = state
            .lookup_program(&locator, Cid::<Program>::from_bytes([0; 32]))
            .unwrap()
            .generation;

        state.finish_ready(&locator, bundle.clone());

        let bound_program = dummy_execution_context(&bundle);

        assert!(matches!(
            state
                .cache_program(&locator, generation, bound_program)
                .unwrap(),
            CacheProgramOutcome::Stale
        ));
    }

    #[test]
    fn finish_failed_marks_entry_failed() {
        let mut state = State::default();
        let locator = locator(0);
        state.mark_queued(locator.clone());

        state.finish_failed(&locator, "boom".to_string());
        assert_eq!(
            state.status(&locator),
            Some(Status::Failed("boom".to_string()))
        );
    }
}
