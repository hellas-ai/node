//! Thin wrappers around standard collections that keep a Prometheus gauge
//! in sync with the collection length after every mutation.
//!
//! Read access is provided via [`Deref`] — all non-mutating methods on the
//! inner collection are available directly.  Only mutating operations are
//! wrapped so the gauge is synced after each one.

use indexmap::IndexMap;
use prometheus_client::metrics::gauge::Gauge;
use std::collections::VecDeque;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::atomic::AtomicI64;

fn set_gauge(gauge: &Gauge<i64, AtomicI64>, len: usize) {
    gauge.set(i64::try_from(len).unwrap_or(i64::MAX));
}

// ---------------------------------------------------------------------------
// GaugedIndexMap
// ---------------------------------------------------------------------------

pub(crate) struct GaugedIndexMap<K, V> {
    inner: IndexMap<K, V>,
    gauge: Gauge<i64, AtomicI64>,
}

impl<K, V> Default for GaugedIndexMap<K, V> {
    fn default() -> Self {
        Self {
            inner: IndexMap::new(),
            gauge: Gauge::default(),
        }
    }
}

impl<K, V> Deref for GaugedIndexMap<K, V> {
    type Target = IndexMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<K, V> GaugedIndexMap<K, V>
where
    K: Hash + Eq,
{
    pub(crate) fn new(gauge: Gauge<i64, AtomicI64>) -> Self {
        gauge.set(0);
        Self {
            inner: IndexMap::new(),
            gauge,
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        let prev = self.inner.insert(key, value);
        set_gauge(&self.gauge, self.inner.len());
        prev
    }

    /// Evict the oldest entries until `len() <= max`. Returns evicted pairs.
    pub(crate) fn enforce_capacity(&mut self, max: usize) -> Vec<(K, V)> {
        let mut evicted = Vec::new();
        while self.inner.len() > max {
            let Some(oldest) = self.inner.shift_remove_index(0) else {
                break;
            };
            evicted.push(oldest);
        }
        if !evicted.is_empty() {
            set_gauge(&self.gauge, self.inner.len());
        }
        evicted
    }
}

// ---------------------------------------------------------------------------
// GaugedVecDeque
// ---------------------------------------------------------------------------

pub(crate) struct GaugedVecDeque<T> {
    inner: VecDeque<T>,
    gauge: Gauge<i64, AtomicI64>,
}

impl<T> Default for GaugedVecDeque<T> {
    fn default() -> Self {
        Self {
            inner: VecDeque::new(),
            gauge: Gauge::default(),
        }
    }
}

impl<T> Deref for GaugedVecDeque<T> {
    type Target = VecDeque<T>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> GaugedVecDeque<T> {
    pub(crate) fn new(gauge: Gauge<i64, AtomicI64>) -> Self {
        gauge.set(0);
        Self {
            inner: VecDeque::new(),
            gauge,
        }
    }

    pub(crate) fn push_back(&mut self, value: T) {
        self.inner.push_back(value);
        set_gauge(&self.gauge, self.inner.len());
    }

    pub(crate) fn pop_front(&mut self) -> Option<T> {
        let value = self.inner.pop_front();
        if value.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        value
    }

    pub(crate) fn replace(&mut self, new: VecDeque<T>) {
        self.inner = new;
        set_gauge(&self.gauge, self.inner.len());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn gauge() -> Gauge<i64, AtomicI64> {
        Gauge::default()
    }

    // -- GaugedIndexMap --

    #[test]
    fn map_insert() {
        let g = gauge();
        let mut m = GaugedIndexMap::<&str, i32>::new(g.clone());
        assert_eq!(g.get(), 0);

        m.insert("a", 1);
        assert_eq!(g.get(), 1);
        m.insert("b", 2);
        assert_eq!(g.get(), 2);

        // Overwrite — length unchanged.
        m.insert("a", 10);
        assert_eq!(g.get(), 2);
    }

    #[test]
    fn map_deref_reads() {
        let g = gauge();
        let mut m = GaugedIndexMap::<&str, i32>::new(g.clone());
        m.insert("a", 1);

        // All via Deref — no gauge writes.
        assert!(m.contains_key(&"a"));
        assert_eq!(m.get(&"a"), Some(&1));
        assert_eq!(m.len(), 1);
        assert!(!m.is_empty());
        assert_eq!(m.keys().count(), 1);
        assert_eq!(m.values().count(), 1);
        assert_eq!(m.iter().count(), 1);
        assert_eq!(g.get(), 1);
    }

    // -- GaugedVecDeque --

    #[test]
    fn deque_push_pop() {
        let g = gauge();
        let mut d = GaugedVecDeque::<&str>::new(g.clone());
        assert_eq!(g.get(), 0);

        d.push_back("a");
        assert_eq!(g.get(), 1);
        assert_eq!(d.pop_front(), Some("a"));
        assert_eq!(g.get(), 0);
        assert_eq!(d.pop_front(), None); // empty
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn deque_deref_reads() {
        let g = gauge();
        let mut d = GaugedVecDeque::<i32>::new(g.clone());
        d.push_back(10);

        assert_eq!(d.len(), 1);
        assert!(!d.is_empty());
        assert_eq!(d.iter().count(), 1);
        assert_eq!(g.get(), 1);
    }

    #[test]
    fn map_enforce_capacity() {
        let g = gauge();
        let mut m = GaugedIndexMap::<&str, i32>::new(g.clone());
        m.insert("a", 1);
        m.insert("b", 2);
        m.insert("c", 3);
        m.insert("d", 4);
        assert_eq!(g.get(), 4);

        let evicted = m.enforce_capacity(2);
        assert_eq!(evicted, vec![("a", 1), ("b", 2)]);
        assert_eq!(g.get(), 2);
        assert!(m.contains_key(&"c"));
        assert!(m.contains_key(&"d"));

        // Already within capacity — no-op.
        let evicted = m.enforce_capacity(5);
        assert!(evicted.is_empty());
        assert_eq!(g.get(), 2);
    }
}
