//! Bounded no-allocation lists.

use core::hash::{Hash, Hasher};

/// Bounded no-allocation list backed by a fixed array.
#[derive(Debug, Clone, Copy)]
pub struct List<T, const N: usize> {
    items: [T; N],
    len: usize,
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

impl<T: Copy, const N: usize> List<T, N> {
    /// Creates a bounded list from a backing array and live length.
    #[must_use]
    pub const fn new(items: [T; N], len: usize) -> Option<Self> {
        if len > N {
            return None;
        }

        Some(Self { items, len })
    }

    /// Maps live entries into another bounded list.
    #[must_use]
    pub fn map<U: Copy>(self, fill: U, mut f: impl FnMut(T) -> U) -> List<U, N> {
        let mut items = [fill; N];
        for (index, item) in self.iter().enumerate() {
            items[index] = f(item);
        }

        List {
            items,
            len: self.len,
        }
    }

    /// Iterates over copied live entries.
    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.as_slice().iter().copied()
    }

    pub(crate) fn resize<const M: usize>(self, fill: T) -> Option<List<T, M>> {
        if self.len > M {
            return None;
        }

        let mut items = [fill; M];
        for (index, item) in self.iter().enumerate() {
            items[index] = item;
        }

        Some(List {
            items,
            len: self.len,
        })
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
