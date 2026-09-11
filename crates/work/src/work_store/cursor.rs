//! A byte cursor for the durable records.
//!
//! Exact by construction: every read either takes the bytes it asked
//! for or returns `None`, and each record's decoder finishes by
//! requiring the cursor to be empty. A record with a trailing byte is
//! not a record with something harmless after it — it is a spelling the
//! encoder cannot produce, and the journal's digests are over exactly
//! these bytes.

/// A cursor over one record's canonical bytes.
#[derive(Debug)]
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Starts a cursor at the beginning of `bytes`.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns whether every byte has been read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Takes one byte.
    pub(crate) fn byte(&mut self) -> Option<u8> {
        let (head, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(*head)
    }

    /// Takes exactly `len` bytes.
    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(head)
    }

    /// Takes a fixed-width array.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let head = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(head);
        Some(out)
    }

    /// Takes one big-endian `u64`.
    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array::<8>().map(u64::from_be_bytes)
    }

    /// Takes every remaining byte.
    ///
    /// Only legal as a record's last field, where "the rest" and "a
    /// length-prefixed body" are the same bytes and the prefix would be
    /// a second, disagreeable spelling of the record's own length.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let all = self.bytes;
        self.bytes = &[];
        all
    }
}
