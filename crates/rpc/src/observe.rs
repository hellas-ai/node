//! The places a measured budget is sampled, and the one way a sample
//! leaves them.
//!
//! # What this is for
//!
//! The mount's two waits are arithmetic over quantities nothing in this
//! tree emitted:
//!
//! ```text
//! Wresp  = 3×fsync_tail_ms + rotation_tail_ms + response_build_ms
//!          + one_block_fetch_ms + max6(rpc_ms + response_worker_ms + validation_ms)
//! Wstart = fresh_tip_ms + close_prepared_fsync_ms + rotation_tail_ms
//!          + max6(rpc_ms + general_worker_ms + validation_ms)
//! ```
//!
//! Every name in those two lines is the name of an event emitted under
//! [`TARGET`], at the one place that already performs the work it
//! measures. A reader mapping a sample to the addend it belongs to has
//! nothing to translate: the event's name *is* the term.
//!
//! # A sample, and not a summary
//!
//! Each seam emits one event per piece of work, carrying `ms` and enough
//! identity to say which piece of work it was — which journal, which
//! block, which contest. Nothing here averages, counts, or keeps a
//! running anything: a mean cannot be turned back into a lower tail, and
//! a lower tail and a confidence bound are what the budgets are made of.
//!
//! # Observation, and not decision
//!
//! [`Timing::ms`] is the only thing that reads a clock back, and its
//! result is only ever a field of an event. No branch anywhere in this
//! crate is taken on a duration, no work is refused because of one, and
//! a journal writes the same bytes in the same order whether or not
//! anybody is listening.
//!
//! # What a node that is not measuring pays
//!
//! One relaxed atomic load per seam. [`Timing::start`] asks `tracing`
//! whether a DEBUG event under [`TARGET`] could reach anyone; with no
//! subscriber installed the process-wide maximum level is `OFF`, the
//! answer is no before any callsite is consulted, and no clock is read,
//! nothing is formatted, and nothing is allocated. The event macros
//! below are guarded by the same question, so their fields — the hex
//! keys especially — are never built either.

use web_time::Instant;

/// The target every sample in this crate is emitted under.
///
/// One target for all of them, so a reader turns the whole measurement
/// surface on with one directive and a node that does not want it pays
/// for none of it.
pub const TARGET: &str = "hellas.mount.measure";

/// The level every sample is emitted at.
pub const LEVEL: tracing::Level = tracing::Level::DEBUG;

/// A measurement that has started — or has not, because nobody asked.
///
/// The `None` case is the whole point: an unobserved node builds one of
/// these, reads no clock, and hands it back to a seam that emits
/// nothing.
#[derive(Clone, Copy, Debug)]
pub struct Timing(Option<Instant>);

impl Timing {
    /// Starts timing one piece of work, if a sample of it could reach
    /// anyone.
    #[must_use]
    pub fn start() -> Self {
        Self(tracing::enabled!(target: TARGET, LEVEL).then(Instant::now))
    }

    /// Returns how long the work took in milliseconds, or `None` when
    /// this measurement never started.
    ///
    /// The only reader of a duration in this crate, and every caller of
    /// it puts the answer straight into an event field.
    #[must_use]
    pub fn ms(self) -> Option<f64> {
        self.0
            .map(|started| started.elapsed().as_secs_f64() * 1_000.0)
    }
}

/// One observation a seam emitted.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    /// The term this is one observation of, spelled as §4 spells it.
    pub quantity: &'static str,
    /// How long the work took.
    pub ms: f64,
    /// The identity fields the seam carried, in emission order.
    pub fields: Vec<(&'static str, String)>,
}

impl Sample {
    /// Returns what the seam recorded under `name`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find_map(|(field, value)| (*field == name).then_some(value.as_str()))
    }
}

/// The reading half of the seam: a subscriber that keeps every sample
/// and does nothing else with it.
///
/// Deliberately not an aggregate. It computes no mean, no quantile and
/// no bound — it hands back the individual observations and leaves every
/// judgement about them to whoever asked.
#[derive(Debug, Default)]
pub struct Samples(std::sync::Mutex<Vec<Sample>>);

impl Samples {
    /// Returns a collector holding nothing.
    #[must_use]
    pub fn new() -> Self {
        hold_the_seams_open();
        Self::default()
    }

    /// Returns every sample collected so far, in emission order.
    #[must_use]
    pub fn all(&self) -> Vec<Sample> {
        self.lock().clone()
    }

    /// Returns every sample of one quantity, in emission order.
    #[must_use]
    pub fn of(&self, quantity: &str) -> Vec<Sample> {
        self.lock()
            .iter()
            .filter(|sample| sample.quantity == quantity)
            .cloned()
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Sample>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl tracing::Subscriber for Samples {
    /// Deliberately `sometimes` rather than `always`: `tracing` caches a
    /// callsite's interest for the whole process, and an `always` cached
    /// by one thread would make every other thread build the event's
    /// fields whether or not it has a subscriber of its own.
    fn register_callsite(
        &self,
        metadata: &tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == TARGET {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == TARGET
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = SampleVisitor::default();
        event.record(&mut visitor);
        let Some(ms) = visitor.ms else {
            return;
        };
        self.lock().push(Sample {
            quantity: event.metadata().name(),
            ms,
            fields: visitor.fields,
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Keeps one dispatcher alive for the rest of the process, so that a
/// seam's callsite is never left cached as one nobody could ever be
/// interested in.
///
/// `tracing` caches a callsite's interest process-wide and recomputes it
/// only when a dispatcher is added. A callsite first reached while no
/// dispatcher exists is cached as "never", and a collector installed on
/// another thread a moment later can miss the rebuild — so a seam goes
/// quiet for a reader that is plainly listening. This dispatcher
/// collects nothing and answers nothing; it exists only to say that a
/// sample under [`TARGET`] is *sometimes* interesting, which sends every
/// such callsite to whichever collector the emitting thread has.
///
/// It is installed by [`Samples::new`] and nowhere else. A node that
/// never builds a collector never builds this either, and goes on paying
/// one atomic load per seam.
fn hold_the_seams_open() {
    static OPEN: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    let _ = OPEN.get_or_init(|| tracing::Dispatch::new(Listening));
}

/// The dispatcher [`hold_the_seams_open`] keeps: interested in the
/// seams, and useless for anything else.
struct Listening;

impl tracing::Subscriber for Listening {
    fn register_callsite(
        &self,
        metadata: &tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == TARGET {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::from_level(LEVEL))
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[derive(Default)]
struct SampleVisitor {
    ms: Option<f64>,
    fields: Vec<(&'static str, String)>,
}

impl SampleVisitor {
    fn push(&mut self, field: &tracing::field::Field, value: String) {
        self.fields.push((field.name(), value));
    }
}

impl tracing::field::Visit for SampleVisitor {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if field.name() == "ms" {
            self.ms = Some(value);
        } else {
            self.push(field, value.to_string());
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push(field, value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push(field, value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push(field, value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }
}
