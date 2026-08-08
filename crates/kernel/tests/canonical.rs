//! Byte-level canonical encoding tests.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

use hellas_kernel::{
    Auth, BlockHeight, BufferWriter, CoinId, Decode, DecodeError, EdgeId, Encode, Fees, Funding,
    Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, MAX_WEBAUTHN_DATA_LENGTH, Parties, PayloadHash,
    Payout, Proof, ProtocolCode, Seal, Sig, StakeBondTerms, Terms, TermsHash, Tx,
    WebAuthnAssertion, WebAuthnData, Writer,
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

    let seal = Seal::from_bytes([6; Seal::LENGTH]);
    let mut seal_buf = [0; Seal::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&seal, &mut seal_buf);

    let terms = terms();
    let mut terms_buf = [0; Terms::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&terms, &mut terms_buf);

    let mutual = Proof::mutual(native_auth(7), native_auth(8));
    let mut mutual_buf = [0; Proof::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&mutual, &mut mutual_buf);

    let timeout = Proof::timeout(terms.clone());
    let mut timeout_buf = [0; Proof::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&timeout, &mut timeout_buf);

    let violation = Proof::violation(terms.clone(), seal);
    let mut violation_buf = [0; Proof::MAX_ENCODED_SIZE + 1];
    assert_canonical_round_trip(&violation, &mut violation_buf);

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
    assert_tag!(Seal::from_bytes([5; Seal::LENGTH]), Seal, 8);
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

    // StakeBond is the widest terms shape, so it defines the codec bound.
    let max_terms = Terms::stake_bond(StakeBondTerms {
        protocol: ProtocolCode::new(8),
        parties: Parties::new(key(8), key(9)),
        timeout: BlockHeight::new(200),
        timeout_outputs: List::all([Payout::new(key(8), 10); MAX_EDGE_OUTPUTS]),
        treasury: key(10),
        award: 10,
        stake: 10,
        max_job_price: 6,
        max_dispute_cost: 4,
        challenge_margin: 8,
    });
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
