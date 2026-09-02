//! Byte-level canonical encoding tests.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

use hellas_kernel::{
    Auth, BOND_LEASE_CHUNKS, BlockHeight, BondLease, BufferWriter, CoinId, Decode, DecodeError,
    EarnedCertificate, EdgeId, Encode, Fees, Funding, Key, List, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, MAX_WEBAUTHN_DATA_LENGTH, Move, Parties, Party, PayloadHash,
    PaymentCloseResponse, PaymentCloseStart, PaymentContestCommitment, Payout, PendingPaymentClose,
    Proof, ProtocolCode, Sig, StartId, Terms, TermsHash, Tx, WebAuthnAssertion, WebAuthnData,
    WorkPaymentTerms, WorkStakeBondTerms, Writer, freeze_digest, no_earned_digest, response_digest,
    settlement_commitment, start_digest, start_id,
};

const NETWORK: hellas_kernel::NetworkId = match hellas_kernel::NetworkId::new("hellas-kernel-test")
{
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

const fn key(byte: u8) -> Key {
    Key::from_bytes([byte; Key::LENGTH])
}

const fn funding() -> Funding {
    let maker = List::take(
        [CoinId::from_bytes([0x11; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        2,
    );
    let taker = List::take(
        [CoinId::from_bytes([0x22; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        1,
    );
    Funding::new(maker, taker)
}

fn payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    let mut payouts = [Payout::default(); MAX_EDGE_OUTPUTS];
    payouts[0] = Payout::new(key(0x31), 41);
    payouts[1] = Payout::new(key(0x32), 59);
    List::take(payouts, 2)
}

fn terms() -> Terms {
    Terms::basic(
        ProtocolCode::new(7),
        Parties::new(key(0x31), key(0x32)),
        BlockHeight::new(101),
        payouts(),
    )
}

const fn native_auth(byte: u8) -> Auth {
    Auth::native(Sig::from_bytes([byte; Sig::LENGTH]))
}

const fn webauthn_assertion() -> WebAuthnAssertion {
    let data: WebAuthnData = List::take([0x55; MAX_WEBAUTHN_DATA_LENGTH], 5);
    WebAuthnAssertion::new([1; 32], [2; 32], [3; 32], [4; 32], data)
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    const fn next_u8(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf {
            *byte = self.next_u8();
        }
    }
}

fn assert_canonical_round_trip<T>(value: &T, buf: &mut [u8])
where
    T: Clone + core::fmt::Debug + Decode + Encode + PartialEq,
{
    let written = value.write_to(buf);
    assert_eq!(written, value.encoded_size());
    assert!(written <= T::MAX_ENCODED_SIZE);
    assert!(written < buf.len());

    let (decoded, consumed) = T::decode(&buf[..written]).expect("canonical value decodes");
    assert_eq!(decoded, value.clone());
    assert_eq!(consumed, written);
    assert_eq!(T::decode_exact(&buf[..written]), Ok(value.clone()));

    for end in 0..written {
        assert!(
            T::decode_exact(&buf[..end]).is_err(),
            "truncated value unexpectedly decoded at {end} bytes",
        );
    }

    buf[written] = 0xa5;
    assert_eq!(
        T::decode_exact(&buf[..=written]),
        Err(DecodeError::TrailingBytes { remaining: 1 }),
    );
}

#[test]
fn buffer_writer_appends_and_tracks_position() {
    let mut buf = [0xff; 8];
    let mut writer = BufferWriter::new(&mut buf);

    writer.write(&[1, 2]);
    assert_eq!(writer.position(), 2);
    writer.write(&[3, 4, 5]);
    assert_eq!(writer.position(), 5);

    assert_eq!(&buf[..5], &[1, 2, 3, 4, 5]);
    assert_eq!(&buf[5..], &[0xff, 0xff, 0xff]);
}

#[test]
fn primitive_numbers_encode_big_endian_and_decode_exact_sizes() {
    let mut buf = [0; 8];

    assert_eq!(7_u8.encoded_size(), 1);
    assert_eq!(7_u8.write_to(&mut buf), 1);
    assert_eq!(buf[0], 7);
    assert_eq!(u8::decode(&buf[..1]), Ok((7, 1)));
    assert_eq!(
        u8::decode(&[]),
        Err(DecodeError::InsufficientBytes { needed: 1, got: 0 }),
    );

    assert_eq!(0x0102_u16.encoded_size(), 2);
    assert_eq!(0x0102_u16.write_to(&mut buf), 2);
    assert_eq!(&buf[..2], &[1, 2]);
    assert_eq!(u16::decode(&buf[..2]), Ok((0x0102, 2)));
    assert_eq!(
        u16::decode(&buf[..1]),
        Err(DecodeError::InsufficientBytes { needed: 2, got: 1 }),
    );

    assert_eq!(0x0102_0304_u32.encoded_size(), 4);
    assert_eq!(0x0102_0304_u32.write_to(&mut buf), 4);
    assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    assert_eq!(u32::decode(&buf[..4]), Ok((0x0102_0304, 4)));
    assert_eq!(
        u32::decode(&buf[..3]),
        Err(DecodeError::InsufficientBytes { needed: 4, got: 3 }),
    );

    assert_eq!(0x0102_0304_0506_0708_u64.encoded_size(), 8);
    assert_eq!(0x0102_0304_0506_0708_u64.write_to(&mut buf), 8);
    assert_eq!(&buf, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(u64::decode(&buf), Ok((0x0102_0304_0506_0708, 8)));
    assert_eq!(
        u64::decode(&buf[..7]),
        Err(DecodeError::InsufficientBytes { needed: 8, got: 7 }),
    );

    assert_eq!(2_usize.encoded_size(), 8);
    assert_eq!(2_usize.write_to(&mut buf), 8);
    assert_eq!(&buf, &[0, 0, 0, 0, 0, 0, 0, 2]);
    assert_eq!(usize::decode(&buf), Ok((2, 8)));
}

#[test]
fn u16_round_trips_across_byte_boundaries() {
    // 255→256 is where the low byte carries into the high one, and 65535
    // is where the type itself runs out. A fixed-width big-endian codec
    // must be indifferent to both.
    for value in [0_u16, 1, 255, 256, 65535] {
        let mut buf = [0; <u16 as Encode>::MAX_ENCODED_SIZE + 1];
        assert_canonical_round_trip(&value, &mut buf);
    }

    let mut buf = [0; 2];
    assert_eq!(256_u16.write_to(&mut buf), 2);
    assert_eq!(&buf, &[1, 0]);
    assert_eq!(u16::MAX.write_to(&mut buf), 2);
    assert_eq!(&buf, &[0xff, 0xff]);
}

#[test]
fn list_encoding_round_trips_length_prefix_and_live_entries() {
    let list: List<u32, 4> = List::new([0x0102_0304, 0x0506_0708, 0, 0], 2).unwrap();
    let mut buf = [0; <List<u32, 4> as Encode>::MAX_ENCODED_SIZE];

    let written = list.write_to(&mut buf);

    assert_eq!(list.encoded_size(), 8 + 2 * 4);
    assert_eq!(written, list.encoded_size());
    assert_eq!(&buf[..8], &[0, 0, 0, 0, 0, 0, 0, 2]);
    assert_eq!(&buf[8..12], &[1, 2, 3, 4]);
    assert_eq!(&buf[12..16], &[5, 6, 7, 8]);

    let (decoded, consumed) = List::<u32, 4>::decode(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    assert_eq!(decoded.as_slice(), &[0x0102_0304, 0x0506_0708]);

    assert_eq!(
        List::<u32, 1>::decode(&buf[..written]),
        Err(DecodeError::InvalidLength { got: 2, max: 1 }),
    );
    assert_eq!(
        List::<u32, 4>::decode(&buf[..written - 1]),
        Err(DecodeError::InsufficientBytes { needed: 4, got: 3 }),
    );
}

#[test]
fn empty_list_encodes_as_only_the_zero_length_and_decodes_exactly() {
    let list: List<CoinId, MAX_PARTY_INPUTS> = List::empty(CoinId::from_bytes([0; CoinId::LENGTH]));
    let mut buf = [0xff; <List<CoinId, MAX_PARTY_INPUTS> as Encode>::MAX_ENCODED_SIZE];

    let written = list.write_to(&mut buf);

    assert_eq!(written, <usize as Encode>::MAX_ENCODED_SIZE);
    assert_eq!(&buf[..written], &[0; <usize as Encode>::MAX_ENCODED_SIZE]);
    assert!(buf[written..].iter().all(|byte| *byte == 0xff));
    let encoded = &buf[..written];
    let (decoded, consumed) = List::<CoinId, MAX_PARTY_INPUTS>::decode(encoded).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(consumed, <usize as Encode>::MAX_ENCODED_SIZE);
    assert_eq!(
        List::<CoinId, MAX_PARTY_INPUTS>::decode_exact(encoded),
        Ok(list),
    );
}

#[test]
fn payout_encoding_round_trips_owner_value_and_consumed_size() {
    let owner = Key::from_bytes([0xab; Key::LENGTH]);
    let payout = Payout::new(owner, 0x0102_0304_0506_0708);
    let mut buf = [0; Payout::MAX_ENCODED_SIZE];

    let written = payout.write_to(&mut buf);

    assert_eq!(payout.encoded_size(), 2 + Key::LENGTH + 8);
    assert_eq!(written, 2 + Key::LENGTH + 8);
    assert_eq!(&buf[..2], &[1, 7]);
    assert_eq!(&buf[2..2 + Key::LENGTH], owner.as_bytes());
    assert_eq!(&buf[2 + Key::LENGTH..], &[1, 2, 3, 4, 5, 6, 7, 8]);

    let (decoded, consumed) = Payout::decode(&buf).expect("canonical payout decodes");
    assert_eq!(decoded, payout);
    assert_eq!(consumed, 2 + Key::LENGTH + 8);

    assert_eq!(
        Payout::decode(&buf[..2 + Key::LENGTH + 7]),
        Err(DecodeError::InsufficientBytes { needed: 8, got: 7 }),
    );
}

#[test]
fn bounded_list_of_payouts_uses_actual_live_encoded_size() {
    let owner = Key::from_bytes([0xcd; Key::LENGTH]);
    let outputs: List<Payout, MAX_EDGE_OUTPUTS> =
        List::new([Payout::new(owner, 1); MAX_EDGE_OUTPUTS], 3).unwrap();

    assert_eq!(
        outputs.encoded_size(),
        <usize as Encode>::MAX_ENCODED_SIZE + 3 * Payout::MAX_ENCODED_SIZE,
    );
}

#[test]
fn full_transaction_graph_and_persistence_values_round_trip_exactly() {
    let fees = Fees::new(1, 2, 3, 4);
    let mut fees_buf = [0; Fees::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&fees, &mut fees_buf);

    let height = BlockHeight::new(123);
    let mut height_buf = [0; BlockHeight::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&height, &mut height_buf);

    let parties = Parties::new(key(1), key(2));
    let mut parties_buf = [0; Parties::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&parties, &mut parties_buf);

    let funding = funding();
    let mut funding_buf = [0; Funding::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&funding, &mut funding_buf);

    let payout = Payout::new(key(3), 99);
    let mut payout_buf = [0; Payout::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&payout, &mut payout_buf);

    let assertion = webauthn_assertion();
    let mut assertion_buf = [0; WebAuthnAssertion::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&assertion, &mut assertion_buf);

    let native = native_auth(5);
    let mut native_buf = [0; Auth::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&native, &mut native_buf);

    let webauthn = Auth::webauthn(assertion);
    let mut webauthn_buf = [0; Auth::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&webauthn, &mut webauthn_buf);

    let terms = terms();
    let mut terms_buf = [0; Terms::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&terms, &mut terms_buf);

    let mutual = Proof::mutual(native_auth(7), native_auth(8));
    let mut mutual_buf = [0; Proof::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&mutual, &mut mutual_buf);

    let timeout = Proof::timeout(terms.clone());
    let mut timeout_buf = [0; Proof::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&timeout, &mut timeout_buf);

    let adjudicated = Proof::adjudicated(PaymentContestCommitment::from_bytes(
        [6; PaymentContestCommitment::LENGTH],
    ));
    let mut adjudicated_buf = [0; Proof::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&adjudicated, &mut adjudicated_buf);

    let open = Tx::open(funding, terms.clone(), native_auth(9), webauthn.clone());
    let mut open_buf = [0; Tx::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&open, &mut open_buf);

    let close = Tx::close(
        EdgeId::from_bytes([0x71; EdgeId::LENGTH]),
        Proof::timeout(terms),
        payouts(),
    );
    let mut close_buf = [0; Tx::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&close, &mut close_buf);
}

#[test]
fn plain_tx_decode_accepts_trailing_bytes_but_exact_decode_rejects_them() {
    let tx = Tx::close(
        EdgeId::from_bytes([0x91; EdgeId::LENGTH]),
        Proof::timeout(terms()),
        payouts(),
    );
    let mut buf = [0; Tx::MAX_ENCODED_SIZE + 1];
    let value_length = tx.write_to(&mut buf);
    buf[value_length] = 0xa5;
    let with_trailing = &buf[..=value_length];

    let (decoded, consumed) =
        Tx::decode(with_trailing).expect("plain decode accepts trailing data");
    assert_eq!(decoded, tx);
    assert_eq!(consumed, value_length);
    assert_eq!(
        Tx::decode_exact(with_trailing),
        Err(DecodeError::TrailingBytes { remaining: 1 }),
    );
}

#[test]
fn id_and_hash_newtypes_decode_through_their_canonical_bytes() {
    let coin = CoinId::from_bytes([0x81; CoinId::LENGTH]);
    let mut coin_buf = [0; CoinId::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&coin, &mut coin_buf);

    let edge = EdgeId::from_bytes([0x82; EdgeId::LENGTH]);
    let mut edge_buf = [0; EdgeId::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&edge, &mut edge_buf);

    let terms = terms();
    let terms_hash: TermsHash = terms.hash();
    let mut terms_hash_buf = [0; TermsHash::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&terms_hash, &mut terms_hash_buf);

    let payload_hash: PayloadHash = Tx::open_hash(NETWORK, &funding(), &terms);
    let mut payload_hash_buf = [0; PayloadHash::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&payload_hash, &mut payload_hash_buf);
}

#[test]
fn composite_types_have_distinct_versioned_domain_tags() {
    macro_rules! assert_tag {
        ($value:expr, $type:ty, $tag:expr) => {{
            let mut buf = [0; <$type as Encode>::MAX_ENCODED_SIZE];
            let written = $value.write_to(&mut buf);
            assert!(written >= 2);
            assert_eq!(&buf[..2], &[1, $tag]);
        }};
    }

    assert_tag!(BlockHeight::new(1), BlockHeight, 1);
    assert_tag!(Fees::ZERO, Fees, 2);
    assert_tag!(Parties::new(key(1), key(2)), Parties, 3);
    assert_tag!(funding(), Funding, 6);
    assert_tag!(Payout::new(key(3), 4), Payout, 7);
    assert_tag!(webauthn_assertion(), WebAuthnAssertion, 9);
    assert_tag!(native_auth(6), Auth, 10);
    assert_tag!(terms(), Terms, 11);
    assert_tag!(Proof::timeout(terms()), Proof, 12);
    assert_tag!(
        Tx::close(
            EdgeId::from_bytes([7; EdgeId::LENGTH]),
            Proof::timeout(terms()),
            payouts(),
        ),
        Tx,
        13
    );
}

#[test]
fn malformed_envelopes_variants_and_bounded_lengths_are_rejected() {
    let payout = Payout::new(key(1), 2);
    let mut payout_buf = [0; Payout::MAX_ENCODED_SIZE];
    payout.write_to(&mut payout_buf);
    payout_buf[0] = 2;
    assert_eq!(
        Payout::decode_exact(&payout_buf),
        Err(DecodeError::InvalidTag { tag: 2 }),
    );
    payout_buf[0] = 1;
    payout_buf[1] = 6;
    assert_eq!(
        Payout::decode_exact(&payout_buf),
        Err(DecodeError::InvalidTag { tag: 6 }),
    );

    let mut auth_buf = [0; Auth::MAX_ENCODED_SIZE];
    let auth_len = native_auth(2).write_to(&mut auth_buf);
    auth_buf[2] = 0xff;
    assert_eq!(
        Auth::decode_exact(&auth_buf[..auth_len]),
        Err(DecodeError::InvalidTag { tag: 0xff }),
    );

    let mut terms_buf = [0; Terms::MAX_ENCODED_SIZE];
    let terms_len = terms().write_to(&mut terms_buf);
    terms_buf[2] = 0xff;
    assert_eq!(
        Terms::decode_exact(&terms_buf[..terms_len]),
        Err(DecodeError::InvalidTag { tag: 0xff }),
    );

    let mut proof_buf = [0; Proof::MAX_ENCODED_SIZE];
    let proof_len = Proof::timeout(terms()).write_to(&mut proof_buf);
    proof_buf[2] = 0xff;
    assert_eq!(
        Proof::decode_exact(&proof_buf[..proof_len]),
        Err(DecodeError::InvalidTag { tag: 0xff }),
    );

    let mut tx_buf = [0; Tx::MAX_ENCODED_SIZE];
    let tx_len = Tx::close(
        EdgeId::from_bytes([3; EdgeId::LENGTH]),
        Proof::timeout(terms()),
        payouts(),
    )
    .write_to(&mut tx_buf);
    tx_buf[2] = 0xff;
    assert_eq!(
        Tx::decode_exact(&tx_buf[..tx_len]),
        Err(DecodeError::InvalidTag { tag: 0xff }),
    );

    let mut funding_buf = [0; Funding::MAX_ENCODED_SIZE];
    let funding_len = funding().write_to(&mut funding_buf);
    let too_many = u64::try_from(MAX_PARTY_INPUTS + 1)
        .expect("the compile-time funding bound fits in u64")
        .to_be_bytes();
    funding_buf[2..10].copy_from_slice(&too_many);
    assert_eq!(
        Funding::decode_exact(&funding_buf[..funding_len]),
        Err(DecodeError::InvalidLength {
            got: MAX_PARTY_INPUTS + 1,
            max: MAX_PARTY_INPUTS,
        }),
    );

    let mut assertion_buf = [0; WebAuthnAssertion::MAX_ENCODED_SIZE];
    let assertion = webauthn_assertion();
    let assertion_len = assertion.write_to(&mut assertion_buf);
    let data_len_offset = 2 + 4 * assertion.r().len();
    let too_much_data = u64::try_from(MAX_WEBAUTHN_DATA_LENGTH + 1)
        .expect("the compile-time WebAuthn bound fits in u64")
        .to_be_bytes();
    assertion_buf[data_len_offset..data_len_offset + 8].copy_from_slice(&too_much_data);
    assert_eq!(
        WebAuthnAssertion::decode_exact(&assertion_buf[..assertion_len]),
        Err(DecodeError::InvalidLength {
            got: MAX_WEBAUTHN_DATA_LENGTH + 1,
            max: MAX_WEBAUTHN_DATA_LENGTH,
        }),
    );
}

/// The two proof variants the cutover removed, named one at a time.
///
/// Byte 2 was `Violation` and byte 5 was `WorkStakeMutual`. Both sit
/// inside the assigned run rather than far outside it, so the `0xff`
/// case above does not cover them: a decoder that grew an arm back for
/// either of its old neighbours would still reject `0xff` and pass that
/// test. Neither byte is reserved for anything. Both are simply
/// invalid, and a later slice that wants one has to re-assign it in the
/// open.
#[test]
fn the_removed_proof_variants_decode_as_nothing() {
    let mut proof_buf = [0; Proof::MAX_ENCODED_SIZE];
    let proof_len = Proof::timeout(terms()).write_to(&mut proof_buf);
    for variant in [2, 5] {
        proof_buf[2] = variant;
        assert_eq!(
            Proof::decode_exact(&proof_buf[..proof_len]),
            Err(DecodeError::InvalidTag { tag: variant }),
            "proof variant {variant}",
        );
    }
}

#[test]
fn maximum_bounded_lists_reach_their_declared_codec_bounds() {
    let maker = List::all([CoinId::from_bytes([1; CoinId::LENGTH]); MAX_PARTY_INPUTS]);
    let taker = List::all([CoinId::from_bytes([2; CoinId::LENGTH]); MAX_PARTY_INPUTS]);
    let funding = Funding::new(maker, taker);
    assert_eq!(funding.encoded_size(), Funding::MAX_ENCODED_SIZE);

    let assertion = WebAuthnAssertion::new(
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        List::all([7; MAX_WEBAUTHN_DATA_LENGTH]),
    );
    assert_eq!(
        assertion.encoded_size(),
        WebAuthnAssertion::MAX_ENCODED_SIZE,
    );
    let auth = Auth::webauthn(assertion);
    assert_eq!(auth.encoded_size(), Auth::MAX_ENCODED_SIZE);

    // WorkPayment is the widest terms shape, so it defines the codec
    // bound: it carries a complete bond body inside its own.
    let max_terms = Terms::work_payment(widest_work_payment());
    assert_eq!(max_terms.encoded_size(), Terms::MAX_ENCODED_SIZE);

    let tx = Tx::open(funding, max_terms, auth.clone(), auth);
    assert_eq!(tx.encoded_size(), Tx::MAX_ENCODED_SIZE);
    let mut buf = [0; Tx::MAX_ENCODED_SIZE];
    assert_eq!(tx.write_to(&mut buf), Tx::MAX_ENCODED_SIZE);
    assert_eq!(Tx::decode_exact(&buf), Ok(tx));
}

#[test]
fn arbitrary_transaction_bytes_never_panic_the_decoder() {
    const CASES: usize = 4_096;

    let mut rng = XorShift64::new(0x6a09_e667_f3bc_c909);
    let mut buf = [0_u8; Tx::MAX_ENCODED_SIZE];

    for case in 0..CASES {
        let random = rng.next_u64().to_le_bytes();
        let sampled_length =
            usize::from(u16::from_le_bytes([random[0], random[1]])) % (Tx::MAX_ENCODED_SIZE + 1);
        let length = match case {
            0 => 0,
            1 => Tx::MAX_ENCODED_SIZE,
            _ => sampled_length,
        };
        rng.fill(&mut buf[..length]);

        if case % 4 == 0 && length >= 2 {
            buf[0] = 1;
            buf[1] = 13;
        }

        let result = Tx::decode(&buf[..length]);
        if let Ok((_, consumed)) = result {
            assert!(consumed <= length);
        }
    }
}

/// Widest possible terms: a work payment whose embedded bond carries a
/// full timeout payout list.
const fn widest_work_payment() -> WorkPaymentTerms {
    let provider = key(0x51);
    let client = key(0x52);
    let bond = WorkStakeBondTerms {
        parties: Parties::new(provider, client),
        timeout: BlockHeight::new(200),
        timeout_outputs: List::all([Payout::new(provider, 10); MAX_EDGE_OUTPUTS]),
        max_job_price: 6,
    };
    WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([0x54; EdgeId::LENGTH]),
        bond_terms: bond,
        private_policy_commitment: [0x55; 32],
        omit_response_blocks: 4096,
        start_validity_blocks: 64,
        omission_bond: 11,
    }
}

/// The owned maxima every stack buffer and chain payload bound is sized
/// from. They have moved twice: up when the work profiles landed, which
/// took `Terms` from 335 to 555 bytes, and back down when the cutover
/// reduced the stake surface to one body, which took it to 360. A silent
/// third move would resize chain transaction buffers.
#[test]
fn owned_terms_and_transaction_maxima_are_pinned() {
    assert_eq!(Terms::MAX_ENCODED_SIZE, TERMS_MAX);
    assert_eq!(Tx::MAX_ENCODED_SIZE, TX_MAX);
    assert_eq!(terms().encoded_size(), 176);
}

/// The widest owned bodies. Every stack buffer and chain payload bound
/// is sized from these two numbers.
const TERMS_MAX: usize = 360;
const TX_MAX: usize = 5_015;

/// `Terms::decode` recomputes the terms commitment, and a work payment
/// recomputes its embedded bond's commitment too. `SingleChunkHasher`
/// asserts at `MIN_CHUNK_SIZE`, and the kernel cannot unwind, so the
/// widest preimage a remote peer can hand the decoder has to stay
/// strictly below it.
#[test]
fn the_widest_terms_preimage_stays_inside_one_xet_chunk() {
    let terms = Terms::work_payment(widest_work_payment());
    assert_eq!(terms.encoded_size(), Terms::MAX_ENCODED_SIZE);

    // Longest domain separator any terms body is hashed under.
    let longest_domain = b"hellas.terms.work-stake-bond.v3".len();
    assert!(longest_domain + Terms::MAX_ENCODED_SIZE < hellas_xet::MIN_CHUNK_SIZE);

    let mut buf = [0; Terms::MAX_ENCODED_SIZE];
    let written = terms.write_to(&mut buf);
    assert_eq!(written, Terms::MAX_ENCODED_SIZE);
    assert_eq!(Terms::decode_exact(&buf), Ok(terms));
}

/// Basic-terms goldens. Every `Basic` edge is bound to these bytes, so
/// an edit that moves either one is a consensus break, not a refactor.
#[test]
fn basic_terms_encoding_is_byte_identical() {
    const BASIC_BYTES: &str = "010b00070103313131313131313131313131313131313131313131313131313131313131313131323232323232323232323232323232323232323232323232323232323232323232010100000000000000650000000000000002010731313131313131313131313131313131313131313131313131313131313131313100000000000000290107323232323232323232323232323232323232323232323232323232323232323232000000000000003b";
    const BASIC_HASH: &str = "f868ca23d33933194d51959382aafa5786d6b41020b113880d4bdec094214f3b";
    let basic = Terms::basic(
        ProtocolCode::new(7),
        Parties::new(key(0x31), key(0x32)),
        BlockHeight::new(101),
        payouts(),
    );
    let mut buf = [0; Terms::MAX_ENCODED_SIZE];
    let written = basic.write_to(&mut buf);
    assert_hex(&buf[..written], BASIC_BYTES);
    assert_hex(&basic.hash().to_bytes(), BASIC_HASH);
    assert_eq!(Terms::decode_exact(&buf[..written]), Ok(basic));
}

/// Reads a hex golden into `bytes`, the inverse of [`assert_hex`].
///
/// A golden a test only compares against proves the encoder; a golden a
/// test reads back into a value proves the decoder too, which is the
/// half that a field order changed on both sides cannot fake.
fn from_hex(expected: &str, bytes: &mut [u8]) {
    assert_eq!(bytes.len() * 2, expected.len(), "golden length");
    for (index, byte) in bytes.iter_mut().enumerate() {
        let Ok(value) = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16) else {
            panic!("golden byte {index} is not hex");
        };
        *byte = value;
    }
}

/// Compares canonical bytes against a hex golden. Spelled out here
/// rather than through a hex crate so the goldens stay readable and the
/// comparison allocates nothing.
fn assert_hex(bytes: &[u8], expected: &str) {
    assert_eq!(bytes.len() * 2, expected.len(), "golden length");
    for (index, byte) in bytes.iter().enumerate() {
        let Ok(value) = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16) else {
            panic!("golden byte {index} is not hex");
        };
        assert_eq!(*byte, value, "golden byte {index}");
    }
}

// ── Work-payment close wire ───────────────────────────────────────────

const fn golden_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

fn golden_terms_hash() -> TermsHash {
    Terms::work_payment(widest_work_payment()).hash()
}

fn golden_certificate() -> EarnedCertificate {
    EarnedCertificate::new(golden_edge(), golden_terms_hash(), 4_242)
}

fn golden_start(certificate: Option<(EarnedCertificate, Sig)>) -> PaymentCloseStart {
    PaymentCloseStart::new(
        golden_edge(),
        Terms::work_payment(widest_work_payment()),
        Party::Taker,
        (900, 907),
        certificate,
        Sig::from_bytes([0x77; Sig::LENGTH]),
    )
}

fn golden_response() -> PaymentCloseResponse {
    PaymentCloseResponse::new(
        golden_edge(),
        StartId::from_bytes([0x33; StartId::LENGTH]),
        Party::Taker,
        (golden_certificate(), Sig::from_bytes([0x66; Sig::LENGTH])),
        Sig::from_bytes([0x77; Sig::LENGTH]),
    )
}

/// The stored contest record every record and seal golden is taken from.
///
/// Its three u64s are pairwise distinct — deadline 907, start 4,242,
/// final 4,243 — and its two flags disagree, so any pair of neighbouring
/// fields exchanged in the layout or in the seal preimage moves a value
/// some assertion below names.
const GOLDEN_PENDING_RECORD: &str = "0117021111111111111111111111111111111111111111111111111111111111111111013333333333333333333333333333333333333333333333333333333333333333000000000000038b0000000000001092000000000000109301000000000000000011";

/// The record those bytes spell.
///
/// Decoded rather than constructed because decoding is the only way any
/// code outside the kernel ever obtains one: the kernel alone writes the
/// pending slot, and every reader — host, indexer, this test — reads it
/// back out of stored bytes.
fn golden_record() -> PendingPaymentClose {
    let mut bytes = [0; PendingPaymentClose::ENCODED_SIZE];
    from_hex(GOLDEN_PENDING_RECORD, &mut bytes);
    let Ok(record) = PendingPaymentClose::decode_exact(&bytes) else {
        panic!("the golden record decodes");
    };
    record
}

/// The stored contest record, pinned byte for byte and field for field.
///
/// This is consensus state under the authenticated registry root, and
/// the seal a later close recomputes is derived from these fields: two
/// node versions that disagreed about which eight bytes are the deadline
/// would fork rather than merely disagree.
///
/// The field assertions carry the weight here, not the round trip. A
/// field order changed in the encoder *and* the decoder together round
/// trips perfectly and moves no byte; it is caught only by reading fixed
/// bytes back out and finding each value where that value belongs.
#[test]
fn payment_close_pending_record_bytes_are_pinned() {
    let record = golden_record();

    assert_eq!(record.payment_edge(), golden_edge());
    assert_eq!(record.opener_role(), Party::Taker);
    assert_eq!(
        record.start_id(),
        StartId::from_bytes([0x33; StartId::LENGTH]),
    );
    assert_eq!(record.response_deadline(), 907);
    assert_eq!(record.start_cumulative(), 4_242);
    assert_eq!(record.final_cumulative(), 4_243);
    assert!(record.responded());
    assert!(!record.penalty_due());
    assert_eq!(record.penalty_amount(), 17);

    // And the encoder puts them back exactly where they were found.
    let mut buf = [0; PendingPaymentClose::ENCODED_SIZE];
    let written = record.write_to(&mut buf);
    assert_eq!(written, PendingPaymentClose::ENCODED_SIZE);
    assert_hex(&buf[..written], GOLDEN_PENDING_RECORD);
}

/// Every encoded width the design fixes for the payment close, measured
/// at the widest body each shape admits.
///
/// These are the numbers every stack buffer, block budget, and quoted
/// protocol cost is derived from. A body that grew by one field would
/// move one of them, which is the point.
#[test]
fn payment_close_wire_widths_are_pinned() {
    let certificate = golden_certificate();
    assert_eq!(certificate.encoded_size(), 75);
    assert_eq!(EarnedCertificate::MAX_ENCODED_SIZE, 75);

    // A start carries the complete revealed payment terms, so its
    // maximum is the widest terms plus its own fields.
    let present = golden_start(Some((certificate, Sig::from_bytes([0x66; Sig::LENGTH]))));
    assert_eq!(present.encoded_size(), 616);
    assert_eq!(PaymentCloseStart::MAX_ENCODED_SIZE, 616);
    // Absence encodes neither conditional field: 75 + 64 bytes shorter.
    assert_eq!(golden_start(None).encoded_size(), 616 - 75 - 64);

    let response = golden_response();
    assert_eq!(response.encoded_size(), 271);
    assert_eq!(PaymentCloseResponse::MAX_ENCODED_SIZE, 271);

    // The nested dispatch adds the outer `Tx` envelope and its variant
    // byte, and nothing else: the action's own tag is what selects it.
    let start_tx = Tx::move_action(Move::StartPaymentClose(present));
    let response_tx = Tx::move_action(Move::RespondPaymentClose(response));
    assert_eq!(start_tx.encoded_size(), 619);
    assert_eq!(response_tx.encoded_size(), 274);

    let freeze = Proof::freeze(
        7,
        (900, 907),
        Sig::from_bytes([0x66; Sig::LENGTH]),
        Sig::from_bytes([0x77; Sig::LENGTH]),
    );
    let adjudicated = Proof::adjudicated(PaymentContestCommitment::from_bytes([0x88; 32]));
    assert_eq!(freeze.encoded_size(), 155);
    assert_eq!(adjudicated.encoded_size(), 35);

    let mut split = [Payout::default(); MAX_EDGE_OUTPUTS];
    split[0] = Payout::new(key(0x31), 7);
    split[1] = Payout::new(key(0x32), 3);
    let split = List::take(split, 2);
    assert_eq!(
        Tx::close(golden_edge(), freeze, split.clone()).encoded_size(),
        284,
    );
    assert_eq!(
        Tx::close(golden_edge(), adjudicated, split).encoded_size(),
        164,
    );

    // The owned maxima are unchanged by the move arm: a start is 619
    // bytes against the ceiling the open arm sets.
    assert_eq!(Terms::MAX_ENCODED_SIZE, TERMS_MAX);
    assert_eq!(Tx::MAX_ENCODED_SIZE, TX_MAX);
}

/// Round trips through the exact wire, including the nested dispatch.
#[test]
fn payment_close_bodies_round_trip_through_the_move_envelope() {
    let certificate = (golden_certificate(), Sig::from_bytes([0x66; Sig::LENGTH]));
    let cases = [
        Tx::move_action(Move::StartPaymentClose(golden_start(Some(certificate)))),
        Tx::move_action(Move::StartPaymentClose(golden_start(None))),
        Tx::move_action(Move::RespondPaymentClose(golden_response())),
    ];

    for tx in cases {
        let mut buf = [0; Tx::MAX_ENCODED_SIZE];
        let written = tx.write_to(&mut buf);
        assert_eq!(written, tx.encoded_size());
        assert_eq!(Tx::decode_exact(&buf[..written]), Ok(tx));
    }
}

/// The certificate presence byte is exactly zero or one. Any other value
/// would be a third reading of a two-state field.
#[test]
fn the_certificate_presence_byte_admits_only_its_two_values() {
    let tx = Tx::move_action(Move::StartPaymentClose(golden_start(None)));
    let mut buf = [0; Tx::MAX_ENCODED_SIZE];
    let written = tx.write_to(&mut buf);

    // Envelope + Tx variant + start envelope + version + edge + terms +
    // role + two heights.
    let presence = 2 + 1 + 2 + 1 + 32 + Terms::MAX_ENCODED_SIZE + 1 + 8 + 8;
    assert_eq!(buf[presence], 0);
    buf[presence] = 2;
    assert_eq!(
        Tx::decode_exact(&buf[..written]),
        Err(DecodeError::InvalidTag { tag: 2 }),
    );
}

/// A move dispatches on the nested envelope tag. An unassigned tag is a
/// rejection, not a body the decoder can skip.
#[test]
fn an_unassigned_move_tag_is_rejected() {
    // Envelope + Tx variant byte, then the nested envelope's type tag.
    const NESTED_TAG: usize = 2 + 1 + 1;

    let tx = Tx::move_action(Move::RespondPaymentClose(golden_response()));
    let mut buf = [0; Tx::MAX_ENCODED_SIZE];
    let written = tx.write_to(&mut buf);
    assert_eq!(buf[NESTED_TAG], 22);
    buf[NESTED_TAG] = 28;

    assert_eq!(
        Tx::decode_exact(&buf[..written]),
        Err(DecodeError::InvalidTag { tag: 28 }),
    );
}

/// Consensus digests, pinned. Every one of these is a preimage a party
/// signs or a seal the kernel recomputes, so a reordered field or a
/// changed domain is a consensus break rather than a refactor.
#[test]
fn payment_close_digests_are_pinned() {
    const EARNED: &str = "efaebccb3b8dae5bb2ebdc3aed9cc62f77fc2807593597ca9ec028783c30d4f8";
    const NO_EARNED: &str = "bf9a0a3fd7bcf8ded8c6df3a99611faaa24fb4baa8d2d8380fd8225c06c19e96";
    const SETTLEMENT: &str = "a8e6e24c24e14eb6ca4b179431b64520c5da833e85db20f6659689383d6e7634";
    const START: &str = "aa5542a8a429fa7e2c847579c88255a5ec41b251bd722fc10c3a7835ddefd6c5";
    const START_ID: &str = "ed37dee622a84ec77220ca81122978023451fde519e6b0ce97b903dcdf7a615e";
    const RESPONSE: &str = "7cf8b8d0296d911b2addbe3c9e968230644e78d443ce4e40467f2658e46ded76";
    const FREEZE: &str = "e872443259af9e87915ab5aa87b08400d52d65592c6c4ea9d830f6d2c6bcc437";
    const CONTEST: &str = "ef33b7b7fb8c96c08bd35781060203fbe91d405eaa6f8ee29ccb83364ae7c986";

    let edge = golden_edge();
    let terms = golden_terms_hash();
    let certificate = golden_certificate();
    let earned = certificate.digest(NETWORK);

    assert_hex(&earned.to_bytes(), EARNED);
    assert_hex(&no_earned_digest(edge, terms).to_bytes(), NO_EARNED);
    assert_hex(
        &settlement_commitment(NETWORK, edge, terms, 4_242),
        SETTLEMENT,
    );

    let start = start_digest(NETWORK, edge, terms, Party::Taker, (900, 907), earned);
    assert_hex(&start.to_bytes(), START);
    assert_hex(&start_id(start, 903).to_bytes(), START_ID);
    assert_hex(
        &response_digest(
            NETWORK,
            edge,
            terms,
            StartId::from_bytes([0x33; StartId::LENGTH]),
            Party::Taker,
            earned,
        )
        .to_bytes(),
        RESPONSE,
    );
    assert_hex(
        &freeze_digest(NETWORK, edge, terms, 4_242, (900, 907)).to_bytes(),
        FREEZE,
    );

    // The contest commitment is the one digest here that crosses the
    // wire as consensus data rather than as a signature:
    // `Proof::Adjudicated` carries it, and the kernel admits the close
    // only if it recomputes the same bytes from the stored record. The golden record's deadline, start
    // and final amounts are all distinct, so a preimage whose fields
    // changed places moves these bytes.
    assert_hex(
        &golden_record()
            .contest_commitment(NETWORK, edge, terms)
            .to_bytes(),
        CONTEST,
    );
}

// ── The bond lease ────────────────────────────────────────────────────

/// The stored lease, byte for byte.
///
/// Every field is a distinct repeated byte and the horizon is a value
/// no other field could be mistaken for, so a layout whose fields
/// changed places moves an assertion below. The round trip alone could
/// not: an encoder and a decoder that swapped the same two fields agree
/// with each other perfectly and disagree with every node that did not.
const GOLDEN_BOND_LEASE: &str = "011f0211111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440000000000001092";

/// The lease those bytes spell.
///
/// Decoded rather than constructed, because decoding is the only way
/// anything outside the kernel obtains one: the kernel alone writes the
/// lease slots, and every reader takes it back out of stored bytes.
fn golden_lease() -> BondLease {
    let mut bytes = [0; BondLease::ENCODED_SIZE];
    from_hex(GOLDEN_BOND_LEASE, &mut bytes);
    let Ok(lease) = BondLease::decode_exact(&bytes) else {
        panic!("the golden lease decodes");
    };
    lease
}

/// The lease is consensus state under the authenticated registry root,
/// and it is what decides whether a bond may be timed out at once or
/// must wait for its horizon. Two nodes disagreeing about which eight
/// bytes are that horizon would fork.
#[test]
fn bond_lease_record_bytes_are_pinned() {
    let lease = golden_lease();

    assert_eq!(
        lease.bond_edge(),
        EdgeId::from_bytes([0x11; EdgeId::LENGTH])
    );
    assert_eq!(
        lease.payment_edge(),
        EdgeId::from_bytes([0x22; EdgeId::LENGTH]),
    );
    assert_eq!(
        lease.payment_terms_hash(),
        TermsHash::from_bytes([0x33; TermsHash::LENGTH]),
    );
    assert_eq!(lease.private_policy_commitment(), [0x44; 32]);
    assert_eq!(lease.admission_horizon(), 4_242);

    // And the encoder puts them back exactly where they were found.
    let mut buf = [0; BondLease::ENCODED_SIZE];
    let written = lease.write_to(&mut buf);
    assert_eq!(written, BondLease::ENCODED_SIZE);
    assert_hex(&buf[..written], GOLDEN_BOND_LEASE);
}

/// The widths the design fixes for the lease: 139 canonical bytes over
/// two registry chunks. Both numbers are consensus — the first decides
/// what a reassembled value must measure, the second how many slots
/// every reader consults before it may answer "unleased".
#[test]
fn bond_lease_wire_width_is_pinned() {
    assert_eq!(BondLease::ENCODED_SIZE, 139);
    assert_eq!(BondLease::MAX_ENCODED_SIZE, 139);
    assert_eq!(golden_lease().encoded_size(), 139);
    assert_eq!(BOND_LEASE_CHUNKS, 2);
}

/// A record's own version byte and envelope tag are what stop a future
/// shape from being read as this one.
#[test]
fn a_lease_decodes_only_under_its_own_tag_and_version() {
    let mut bytes = [0; BondLease::ENCODED_SIZE];
    from_hex(GOLDEN_BOND_LEASE, &mut bytes);

    let mut wrong_tag = bytes;
    wrong_tag[1] = 24;
    assert_eq!(
        BondLease::decode_exact(&wrong_tag),
        Err(DecodeError::InvalidTag { tag: 24 }),
    );

    let mut wrong_version = bytes;
    wrong_version[2] = 3;
    assert_eq!(
        BondLease::decode_exact(&wrong_version),
        Err(DecodeError::InvalidTag { tag: 3 }),
    );

    assert_eq!(
        BondLease::decode_exact(&bytes[..BondLease::ENCODED_SIZE - 1]),
        Err(DecodeError::InsufficientBytes { needed: 8, got: 7 }),
    );
}
