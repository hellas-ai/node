//! Concrete edge terms and their deterministic commitment.
//!
//! No direct abstract counterpart — the L1 model treats terms as opaque
//! constants (`TimeoutHeight`, `MakerPayout`, `TakerPayout` in
//! `models/types.qnt`). The Rust kernel commits to a structured [`Terms`]
//! body and binds it via [`TermsHash`] so closes can carry only the
//! commitment, not the full payload.
//!
//! [`Terms`] computes its [`TermsHash`] at construction and stores it
//! alongside the body. Callers that need the hash get a field load; no
//! type that contains a `Terms` ever needs to cache `terms_hash`
//! separately.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::MAX_EDGE_OUTPUTS,
    context::BlockHeight,
    list::List,
    object::Parties,
    primitive::{ProtocolCode, TermsHash},
    tx::Payout,
};

/// Concrete open terms committed by an edge.
///
/// `Terms` is the *body* + a precomputed [`TermsHash`] that binds it.
/// The two cannot drift because the only constructor computes the hash
/// once and stores it, and the body is immutable thereafter.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Terms {
    body: TermsBody,
    hash: TermsHash,
}

/// Body of a [`Terms`] commitment. Variants enumerate the supported
/// protocol-mode shapes; the wrapping [`Terms`] adds the canonical
/// commitment over the body.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
enum TermsBody {
    /// Degenerate bilateral terms used until protocol-specific terms land.
    Basic {
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    },
}

const BASIC_TAG: u8 = 0;

impl Terms {
    /// Creates basic terms.
    #[must_use]
    pub fn basic(
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> Self {
        let body = TermsBody::Basic {
            protocol,
            parties,
            timeout,
            timeout_outputs,
        };
        let hash = body.compute_hash();
        Self { body, hash }
    }

    /// Returns the canonical BLAKE3 commitment for these terms.
    ///
    /// Computed once at construction; this is a field load.
    #[must_use]
    pub const fn hash(&self) -> TermsHash {
        self.hash
    }

    /// Returns the chain-version-local protocol code.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolCode {
        match &self.body {
            TermsBody::Basic { protocol, .. } => *protocol,
        }
    }

    /// Returns the committed parties.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        match &self.body {
            TermsBody::Basic { parties, .. } => *parties,
        }
    }

    /// Returns the earliest valid timeout height.
    #[must_use]
    pub const fn timeout(&self) -> BlockHeight {
        match &self.body {
            TermsBody::Basic { timeout, .. } => *timeout,
        }
    }

    /// Returns the deterministic timeout payout shape, including any reserve
    /// surplus left after the open-time committed timeout close fee.
    #[must_use]
    pub const fn timeout_outputs(&self) -> &List<Payout, MAX_EDGE_OUTPUTS> {
        match &self.body {
            TermsBody::Basic {
                timeout_outputs, ..
            } => timeout_outputs,
        }
    }
}

impl TermsBody {
    fn compute_hash(&self) -> TermsHash {
        // The hash domain is the structural tag for this body shape. If a
        // second terms body shape is introduced, it must use a distinct domain
        // separator or a chain-versioned tagged encoding, so different
        // semantics cannot share the same canonical bytes.
        TermsHash::from_bytes(crate::canonical::hash(crate::consts::TERMS_BASIC, self))
    }
}

impl Encode for Terms {
    const MAX_ENCODED_SIZE: usize = TermsBody::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        self.body.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.body.encode_to(writer);
    }
}

impl Decode for Terms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (body, consumed) = TermsBody::decode(buf)?;
        let hash = body.compute_hash();
        Ok((Self { body, hash }, consumed))
    }
}

impl Encode for TermsBody {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + u8::MAX_ENCODED_SIZE
        + ProtocolCode::MAX_ENCODED_SIZE
        + Parties::MAX_ENCODED_SIZE
        + BlockHeight::MAX_ENCODED_SIZE
        + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                ENVELOPE_SIZE
                    + u8::MAX_ENCODED_SIZE
                    + protocol.encoded_size()
                    + parties.encoded_size()
                    + timeout.encoded_size()
                    + timeout_outputs.encoded_size()
            }
        }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                encode_envelope(writer, tag::TERMS);
                BASIC_TAG.encode_to(writer);
                protocol.encode_to(writer);
                parties.encode_to(writer);
                timeout.encode_to(writer);
                timeout_outputs.encode_to(writer);
            }
        }
    }
}

impl Decode for TermsBody {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::TERMS)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            BASIC_TAG => {
                let protocol = decode_field(buf, &mut consumed)?;
                let parties = decode_field(buf, &mut consumed)?;
                let timeout = decode_field(buf, &mut consumed)?;
                let timeout_outputs = decode_field(buf, &mut consumed)?;
                Ok((
                    Self::Basic {
                        protocol,
                        parties,
                        timeout,
                        timeout_outputs,
                    },
                    consumed,
                ))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test constants are in-bounds")]
mod tests {
    use super::*;
    use crate::{
        canonical::{BufferWriter, hash},
        consts::TERMS_BASIC,
        primitive::Key,
    };

    #[test]
    fn basic_terms_hash_is_bound_to_basic_terms_domain() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(maker, 7);
        outputs[1] = Payout::new(taker, 8);
        let outputs = List::take(outputs, 2);
        let terms = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            outputs,
        );

        let expected = TermsHash::from_bytes(hash(TERMS_BASIC, &terms.body));
        assert_eq!(terms.hash(), expected);
    }

    #[test]
    fn basic_terms_body_size_matches_canonical_encoding() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let outputs = List::all([Payout::new(maker, 7); MAX_EDGE_OUTPUTS]);
        let body = TermsBody::Basic {
            protocol: ProtocolCode::new(1),
            parties: Parties::new(maker, taker),
            timeout: BlockHeight::new(99),
            timeout_outputs: outputs,
        };
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let mut writer = BufferWriter::new(&mut buf);

        body.encode_to(&mut writer);

        assert_eq!(
            TermsBody::MAX_ENCODED_SIZE,
            ENVELOPE_SIZE
                + u8::MAX_ENCODED_SIZE
                + ProtocolCode::MAX_ENCODED_SIZE
                + Parties::MAX_ENCODED_SIZE
                + BlockHeight::MAX_ENCODED_SIZE
                + <usize as Encode>::MAX_ENCODED_SIZE
                + MAX_EDGE_OUTPUTS * Payout::MAX_ENCODED_SIZE,
        );
        assert_eq!(body.encoded_size(), writer.position());
        assert_eq!(body.encoded_size(), TermsBody::MAX_ENCODED_SIZE);
        let maker_start =
            ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + ProtocolCode::MAX_ENCODED_SIZE + ENVELOPE_SIZE;
        let taker_start = maker_start + Key::LENGTH;
        let parties_end = taker_start + Key::LENGTH;

        assert_eq!(&buf[..4], &[1, tag::TERMS, BASIC_TAG, 1]);
        assert_eq!(&buf[4..maker_start], &[1, tag::PARTIES]);
        assert_eq!(&buf[maker_start..taker_start], maker.as_bytes());
        assert_eq!(&buf[taker_start..parties_end], taker.as_bytes());
    }
}
