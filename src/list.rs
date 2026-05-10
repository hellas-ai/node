//! Bounded no-allocation lists.

use core::fmt;
use core::hash::{Hash, Hasher};

/// Bounded no-allocation list backed by a fixed array.
///
/// `Debug` prints only the live entries; the inactive tail is implementation
/// detail and would otherwise flood error messages and example output.
///
/// Intentionally not `Copy`: ownership transitions of operation payloads,
/// blocks, events, and effects must be explicit. The kernel passes these
/// by reference whenever possible; explicit `.clone()` marks the few sites
/// that genuinely need a separate owned copy.
#[derive(Clone)]
pub struct List<T, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for List<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl<T, const N: usize> List<T, N> {
    /// Creates a bounded list using every array entry.
    #[must_use]
    pub const fn all(items: [T; N]) -> Self {
        Self { items, len: N }
    }

    /// Returns the number of live entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the list has no live entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrows the live entries.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items[..self.len]
    }
}

impl<T, const N: usize> List<T, N> {
    /// Borrows the live entries.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<T, const N: usize> IntoIterator for List<T, N> {
    type Item = T;
    type IntoIter = core::iter::Take<core::array::IntoIter<T, N>>;

    fn into_iter(self) -> Self::IntoIter {
        let len = self.len;
        self.items.into_iter().take(len)
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a List<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: Copy, const N: usize> List<T, N> {
    /// Creates an empty bounded list using `fill` for inactive slots.
    #[must_use]
    pub const fn empty(fill: T) -> Self {
        Self {
            items: [fill; N],
            len: 0,
        }
    }

    /// Creates a bounded list from a backing array and live length.
    #[must_use]
    pub const fn new(items: [T; N], len: usize) -> Option<Self> {
        if len > N {
            return None;
        }

        Some(Self { items, len })
    }

    /// Creates a bounded list from a backing array and live length,
    /// saturating at the array capacity. Use this when the caller can
    /// statically prove `len <= N` (typically because `len` came from
    /// another `List<_, N>`); the saturation is a no-op in that case
    /// and avoids a fallible-but-impossible `List::new` call.
    #[must_use]
    pub const fn take(items: [T; N], len: usize) -> Self {
        let live = if len > N { N } else { len };
        Self { items, len: live }
    }

    /// Maps live entries into another bounded list.
    #[must_use]
    pub fn map<U: Copy>(self, fill: U, mut f: impl FnMut(T) -> U) -> List<U, N> {
        let mut items = [fill; N];
        for (index, item) in self.as_slice().iter().enumerate() {
            items[index] = f(*item);
        }

        List {
            items,
            len: self.len,
        }
    }
}

impl<T: PartialEq, const N: usize> PartialEq for List<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for List<T, N> {}

impl<T: Hash, const N: usize> Hash for List<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}
