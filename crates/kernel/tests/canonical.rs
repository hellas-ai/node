//! Byte-level canonical encoding tests.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

use hellas_kernel::{
    BufferWriter, Decode, DecodeError, Encode, Key, List, MAX_EDGE_OUTPUTS, Payout, Writer,
};

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
fn payout_encoding_round_trips_owner_value_and_consumed_size() {
    let owner = Key::from_bytes([0xab; Key::LENGTH]);
    let payout = Payout::new(owner, 0x0102_0304_0506_0708);
    let mut buf = [0; Payout::MAX_ENCODED_SIZE];

    let written = payout.write_to(&mut buf);

    assert_eq!(payout.encoded_size(), Key::LENGTH + 8);
    assert_eq!(written, Key::LENGTH + 8);
    assert_eq!(&buf[..Key::LENGTH], owner.as_bytes());
    assert_eq!(&buf[Key::LENGTH..], &[1, 2, 3, 4, 5, 6, 7, 8]);

    let (decoded, consumed) = Payout::decode(&buf).expect("canonical payout decodes");
    assert_eq!(decoded, payout);
    assert_eq!(consumed, Key::LENGTH + 8);

    assert_eq!(
        Payout::decode(&buf[..Key::LENGTH + 7]),
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
