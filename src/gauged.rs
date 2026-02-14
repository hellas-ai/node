//! Thin wrappers around standard collections that keep a Prometheus gauge
//! in sync with the collection length after every mutation.
//!
//! Read access is provided via [`Deref`] — all non-mutating methods on the
//! inner collection are available directly.  Only mutating operations are
//! wrapped so the gauge is synced after each one.

use indexmap::{IndexMap, IndexSet, map::Entry as IndexMapEntry};
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

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        let prev = self.inner.insert(key, value);
        set_gauge(&self.gauge, self.inner.len());
        prev
    }

    pub(crate) fn shift_remove(&mut self, key: &K) -> Option<V> {
        let removed = self.inner.shift_remove(key);
        if removed.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        removed
    }

    pub(crate) fn shift_remove_index(&mut self, index: usize) -> Option<(K, V)> {
        let removed = self.inner.shift_remove_index(index);
        if removed.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        removed
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

    /// Provides entry access. The gauge is synced when the returned
    /// [`GaugedEntry`] is consumed via `or_default` / `or_insert`.
    pub(crate) fn entry(&mut self, key: K) -> GaugedEntry<'_, K, V> {
        let prev_len = self.inner.len();
        GaugedEntry {
            entry: self.inner.entry(key),
            gauge: &self.gauge,
            prev_len,
        }
    }
}

/// Wrapper around [`IndexMapEntry`] that syncs the gauge on insert.
pub(crate) struct GaugedEntry<'a, K, V> {
    entry: IndexMapEntry<'a, K, V>,
    gauge: &'a Gauge<i64, AtomicI64>,
    prev_len: usize,
}

impl<'a, K, V> GaugedEntry<'a, K, V>
where
    K: Hash + Eq,
{
    pub(crate) fn or_insert(self, default: V) -> &'a mut V {
        let was_vacant = matches!(self.entry, IndexMapEntry::Vacant(_));
        let value = self.entry.or_insert(default);
        if was_vacant {
            set_gauge(self.gauge, self.prev_len + 1);
        }
        value
    }
}

impl<'a, K, V> GaugedEntry<'a, K, V>
where
    K: Hash + Eq,
    V: Default,
{
    pub(crate) fn or_default(self) -> &'a mut V {
        let was_vacant = matches!(self.entry, IndexMapEntry::Vacant(_));
        let value = self.entry.or_default();
        if was_vacant {
            set_gauge(self.gauge, self.prev_len + 1);
        }
        value
    }
}

// ---------------------------------------------------------------------------
// GaugedIndexSet
// ---------------------------------------------------------------------------

pub(crate) struct GaugedIndexSet<T> {
    inner: IndexSet<T>,
    gauge: Gauge<i64, AtomicI64>,
}

impl<T> Default for GaugedIndexSet<T> {
    fn default() -> Self {
        Self {
            inner: IndexSet::new(),
            gauge: Gauge::default(),
        }
    }
}

impl<T> Deref for GaugedIndexSet<T> {
    type Target = IndexSet<T>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> GaugedIndexSet<T>
where
    T: Hash + Eq,
{
    pub(crate) fn new(gauge: Gauge<i64, AtomicI64>) -> Self {
        gauge.set(0);
        Self {
            inner: IndexSet::new(),
            gauge,
        }
    }

    pub(crate) fn insert(&mut self, value: T) -> bool {
        let new = self.inner.insert(value);
        if new {
            set_gauge(&self.gauge, self.inner.len());
        }
        new
    }

    pub(crate) fn shift_remove(&mut self, value: &T) -> bool {
        let removed = self.inner.shift_remove(value);
        if removed {
            set_gauge(&self.gauge, self.inner.len());
        }
        removed
    }

    pub(crate) fn shift_remove_index(&mut self, index: usize) -> Option<T> {
        let removed = self.inner.shift_remove_index(index);
        if removed.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        removed
    }

    /// Evict the oldest entries until `len() <= max`. Returns evicted values.
    pub(crate) fn enforce_capacity(&mut self, max: usize) -> Vec<T> {
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

    pub(crate) fn push_front(&mut self, value: T) {
        self.inner.push_front(value);
        set_gauge(&self.gauge, self.inner.len());
    }

    pub(crate) fn pop_front(&mut self) -> Option<T> {
        let value = self.inner.pop_front();
        if value.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        value
    }

    pub(crate) fn pop_back(&mut self) -> Option<T> {
        let value = self.inner.pop_back();
        if value.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        value
    }

    pub(crate) fn drain(&mut self) -> std::collections::vec_deque::Drain<'_, T> {
        set_gauge(&self.gauge, 0);
        self.inner.drain(..)
    }

    pub(crate) fn replace(&mut self, new: VecDeque<T>) {
        self.inner = new;
        set_gauge(&self.gauge, self.inner.len());
    }

    /// Evict the oldest entries until `len() <= max`. Returns evicted values.
    pub(crate) fn enforce_capacity(&mut self, max: usize) -> Vec<T> {
        let mut evicted = Vec::new();
        while self.inner.len() > max {
            let Some(oldest) = self.inner.pop_front() else {
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
// GaugedBinaryHeap
// ---------------------------------------------------------------------------

pub(crate) struct GaugedBinaryHeap<T: Ord> {
    inner: std::collections::BinaryHeap<T>,
    gauge: Gauge<i64, AtomicI64>,
}

impl<T: Ord> Default for GaugedBinaryHeap<T> {
    fn default() -> Self {
        Self {
            inner: std::collections::BinaryHeap::new(),
            gauge: Gauge::default(),
        }
    }
}

impl<T: Ord> Deref for GaugedBinaryHeap<T> {
    type Target = std::collections::BinaryHeap<T>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Ord> GaugedBinaryHeap<T> {
    pub(crate) fn new(gauge: Gauge<i64, AtomicI64>) -> Self {
        gauge.set(0);
        Self {
            inner: std::collections::BinaryHeap::new(),
            gauge,
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        self.inner.push(item);
        set_gauge(&self.gauge, self.inner.len());
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        let item = self.inner.pop();
        if item.is_some() {
            set_gauge(&self.gauge, self.inner.len());
        }
        item
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
    fn map_insert_remove() {
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

        m.shift_remove(&"a");
        assert_eq!(g.get(), 1);
        m.shift_remove(&"z"); // nonexistent
        assert_eq!(g.get(), 1);
        m.shift_remove_index(0);
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn map_entry() {
        let g = gauge();
        let mut m = GaugedIndexMap::<String, Vec<u8>>::new(g.clone());

        m.entry("x".into()).or_default().push(42);
        assert_eq!(g.get(), 1);
        m.entry("x".into()).or_default().push(43); // existing
        assert_eq!(g.get(), 1);
        m.entry("y".into()).or_default();
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

    // -- GaugedIndexSet --

    #[test]
    fn set_insert_remove() {
        let g = gauge();
        let mut s = GaugedIndexSet::<i32>::new(g.clone());
        assert_eq!(g.get(), 0);

        assert!(s.insert(1));
        assert_eq!(g.get(), 1);
        assert!(!s.insert(1)); // duplicate
        assert_eq!(g.get(), 1);
        assert!(s.insert(2));
        assert_eq!(g.get(), 2);

        assert!(s.shift_remove(&1));
        assert_eq!(g.get(), 1);
        assert!(!s.shift_remove(&99)); // nonexistent
        assert_eq!(g.get(), 1);
        assert_eq!(s.shift_remove_index(0), Some(2));
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn set_deref_reads() {
        let g = gauge();
        let mut s = GaugedIndexSet::<i32>::new(g.clone());
        s.insert(10);

        assert!(s.contains(&10));
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
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
        d.push_front("b");
        assert_eq!(g.get(), 2);
        assert_eq!(d.pop_front(), Some("b"));
        assert_eq!(g.get(), 1);
        assert_eq!(d.pop_back(), Some("a"));
        assert_eq!(g.get(), 0);
        assert_eq!(d.pop_front(), None); // empty
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn deque_drain() {
        let g = gauge();
        let mut d = GaugedVecDeque::<i32>::new(g.clone());
        d.push_back(1);
        d.push_back(2);
        d.push_back(3);
        assert_eq!(g.get(), 3);

        let drained: Vec<_> = d.drain().collect();
        assert_eq!(drained, vec![1, 2, 3]);
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

    // -- enforce_capacity --

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

    #[test]
    fn set_enforce_capacity() {
        let g = gauge();
        let mut s = GaugedIndexSet::<i32>::new(g.clone());
        s.insert(10);
        s.insert(20);
        s.insert(30);
        s.insert(40);
        assert_eq!(g.get(), 4);

        let evicted = s.enforce_capacity(2);
        assert_eq!(evicted, vec![10, 20]);
        assert_eq!(g.get(), 2);
        assert!(s.contains(&30));
        assert!(s.contains(&40));

        let evicted = s.enforce_capacity(5);
        assert!(evicted.is_empty());
        assert_eq!(g.get(), 2);
    }

    #[test]
    fn deque_enforce_capacity() {
        let g = gauge();
        let mut d = GaugedVecDeque::<i32>::new(g.clone());
        d.push_back(1);
        d.push_back(2);
        d.push_back(3);
        d.push_back(4);
        assert_eq!(g.get(), 4);

        let evicted = d.enforce_capacity(2);
        assert_eq!(evicted, vec![1, 2]);
        assert_eq!(g.get(), 2);
        assert_eq!(d.pop_front(), Some(3));
        assert_eq!(d.pop_front(), Some(4));

        let evicted = d.enforce_capacity(5);
        assert!(evicted.is_empty());
        assert_eq!(g.get(), 0); // already empty from pops
    }
}
