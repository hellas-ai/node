//! Registry chunk codec, id derivation, and store-slot tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    BOND_LEASE_CHUNKS, Batch, Decode, DecodeError, EdgeId, Encode, InsertError,
    MAX_NETWORK_ID_LENGTH, MAX_REGISTRY_CHUNKS, MAX_REGISTRY_VALUE_LEN, NetworkId,
    REGISTRY_CHUNK_DATA_CAPACITY, RegistryChunk, RegistryChunkId, RegistryNamespace,
    RegistryRecordTag, Store, bond_lease_slot, bond_lease_slots,
};

use support::{FixedStore, NETWORK};

const CAPACITY: usize = REGISTRY_CHUNK_DATA_CAPACITY;

const NAMESPACES: [RegistryNamespace; 2] = [
    RegistryNamespace::PaymentClose,
    RegistryNamespace::BondLease,
];

const RECORD_TAGS: [RegistryRecordTag; 2] = [
    RegistryRecordTag::PaymentPending,
    RegistryRecordTag::BondLease,
];

/// A deterministic value of `len` bytes, distinct at every position so a
/// chunk that copies the wrong window is visible.
fn value(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap().wrapping_add(1))
        .collect()
}

fn chunk_id(namespace: RegistryNamespace, key_byte: u8, index: u8) -> RegistryChunkId {
    RegistryChunkId::derive(NETWORK, namespace, [key_byte; 32], index)
}

fn split(value: &[u8], index: u8) -> RegistryChunk {
    RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        value,
        index,
    )
    .expect("value splits at this index")
}

#[test]
fn chunk_is_the_spec_size_and_round_trips() {
    // 128 body bytes under the two-byte canonical envelope.
    assert_eq!(RegistryChunk::MAX_ENCODED_SIZE, 130);

    let body = value(CAPACITY + 7);
    let chunk = split(&body, 1);
    let mut buf = [0_u8; RegistryChunk::MAX_ENCODED_SIZE + 1];
    let written = chunk.write_to(&mut buf);

    assert_eq!(written, RegistryChunk::MAX_ENCODED_SIZE);
    assert_eq!(chunk.encoded_size(), written);
    // Envelope, then the body's fixed header, then the padded data.
    assert_eq!(&buf[..3], &[1, 24, 2]);
    assert_eq!(RegistryChunk::decode_exact(&buf[..written]), Ok(chunk));

    for end in 0..written {
        assert!(RegistryChunk::decode_exact(&buf[..end]).is_err());
    }
    buf[written] = 0xa5;
    assert_eq!(
        RegistryChunk::decode_exact(&buf[..=written]),
        Err(DecodeError::TrailingBytes { remaining: 1 }),
    );
}

#[test]
fn split_covers_every_value_byte_exactly_once() {
    for len in [
        1,
        2,
        CAPACITY - 1,
        CAPACITY,
        CAPACITY + 1,
        3 * CAPACITY,
        3 * CAPACITY + 1,
    ] {
        let body = value(len);
        let count = RegistryChunk::chunk_count_for(len).expect("splittable length");
        let mut rejoined = Vec::new();
        for index in 0..count {
            let chunk = split(&body, index);
            assert_eq!(chunk.chunk_index(), index);
            assert_eq!(chunk.chunk_count(), count);
            assert_eq!(usize::from(chunk.value_len()), len);
            // Every chunk but the last is full.
            let expected = if index + 1 == count {
                len - usize::from(index) * CAPACITY
            } else {
                CAPACITY
            };
            assert_eq!(chunk.data().len(), expected);
            rejoined.extend_from_slice(chunk.data());
        }
        assert_eq!(rejoined, body);
        assert_eq!(
            RegistryChunk::split(NAMESPACES[0], RECORD_TAGS[0], &body, count),
            None
        );
    }
}

#[test]
fn split_refuses_the_lengths_that_have_no_canonical_chunking() {
    // Zero would make "absent" and "present but empty" the same state.
    assert_eq!(RegistryChunk::chunk_count_for(0), None);
    assert_eq!(
        RegistryChunk::split(NAMESPACES[0], RECORD_TAGS[0], &[], 0),
        None
    );

    assert_eq!(MAX_REGISTRY_VALUE_LEN, MAX_REGISTRY_CHUNKS * CAPACITY);
    assert_eq!(
        RegistryChunk::chunk_count_for(MAX_REGISTRY_VALUE_LEN),
        Some(255)
    );
    assert_eq!(
        RegistryChunk::chunk_count_for(MAX_REGISTRY_VALUE_LEN + 1),
        None
    );

    let oversized = value(MAX_REGISTRY_VALUE_LEN + 1);
    assert_eq!(
        RegistryChunk::split(NAMESPACES[0], RECORD_TAGS[0], &oversized, 0),
        None
    );
}

#[test]
fn every_namespace_and_record_tag_survives_the_chunk_codec() {
    let body = value(5);
    let mut buf = [0_u8; RegistryChunk::MAX_ENCODED_SIZE];
    for namespace in NAMESPACES {
        for record_tag in RECORD_TAGS {
            let chunk = RegistryChunk::split(namespace, record_tag, &body, 0).expect("one chunk");
            let written = chunk.write_to(&mut buf);
            let decoded = RegistryChunk::decode_exact(&buf[..written]).expect("round trip");
            assert_eq!(decoded.namespace(), namespace);
            assert_eq!(decoded.record_tag(), record_tag);
            assert_eq!(decoded.data(), &body);
        }
    }
    // The assigned wire numbers, not merely some stable permutation.
    // Tags 2 and 3 held the game and winner records; both were deleted
    // with the unbuilt game, and both are ordinary rejections now.
    assert_eq!(NAMESPACES.map(RegistryNamespace::tag), [0, 1]);
    assert_eq!(RECORD_TAGS.map(RegistryRecordTag::tag), [0, 1]);
    assert_eq!(RegistryNamespace::from_tag(2), None);
    assert_eq!(RegistryRecordTag::from_tag(2), None);
    assert_eq!(RegistryRecordTag::from_tag(3), None);
}

/// Encodes `chunk`, hands the bytes to `mutate`, and returns the decode
/// verdict. Every canonical rule is a rule about stored bytes, so it has
/// to be checked by corrupting stored bytes.
fn decode_mutated(
    chunk: RegistryChunk,
    mutate: impl FnOnce(&mut [u8]),
) -> Result<RegistryChunk, DecodeError> {
    let mut buf = [0_u8; RegistryChunk::MAX_ENCODED_SIZE];
    let written = chunk.write_to(&mut buf);
    mutate(&mut buf[..written]);
    RegistryChunk::decode_exact(&buf[..written])
}

#[test]
fn decode_rejects_a_chunk_that_disagrees_with_itself() {
    // Field offsets past the two-byte envelope.
    const VERSION: usize = 2;
    const NAMESPACE: usize = 3;
    const RECORD_TAG: usize = 4;
    const CHUNK_INDEX: usize = 5;
    const CHUNK_COUNT: usize = 6;
    const VALUE_LEN: usize = 7;
    const DATA_LEN: usize = 9;
    const DATA: usize = 10;

    let body = value(CAPACITY + 7);
    let first = split(&body, 0);
    let last = split(&body, 1);

    assert_eq!(
        decode_mutated(first, |bytes| bytes[VERSION] = 1),
        Err(DecodeError::InvalidTag { tag: 1 }),
    );
    assert_eq!(
        decode_mutated(first, |bytes| bytes[NAMESPACE] = 3),
        Err(DecodeError::InvalidTag { tag: 3 }),
    );
    assert_eq!(
        decode_mutated(first, |bytes| bytes[RECORD_TAG] = 4),
        Err(DecodeError::InvalidTag { tag: 4 }),
    );

    // A count that does not equal ceil(value_len / 120).
    assert_eq!(
        decode_mutated(first, |bytes| bytes[CHUNK_COUNT] = 3),
        Err(DecodeError::NonCanonical {
            field: "RegistryChunk.chunk_count"
        }),
    );
    // An index at or past the count.
    assert_eq!(
        decode_mutated(first, |bytes| bytes[CHUNK_INDEX] = 2),
        Err(DecodeError::NonCanonical {
            field: "RegistryChunk.chunk_index"
        }),
    );
    // A full-length declaration on the chunk that holds the remainder.
    assert_eq!(
        decode_mutated(last, |bytes| bytes[DATA_LEN] = 120),
        Err(DecodeError::NonCanonical {
            field: "RegistryChunk.data_len"
        }),
    );
    // A short declaration on a chunk that is not the last.
    assert_eq!(
        decode_mutated(first, |bytes| bytes[DATA_LEN] = 119),
        Err(DecodeError::NonCanonical {
            field: "RegistryChunk.data_len"
        }),
    );
    // A value length whose chunking no longer matches the stored count.
    assert_eq!(
        decode_mutated(first, |bytes| {
            bytes[VALUE_LEN] = 0;
            bytes[VALUE_LEN + 1] = 0;
        }),
        Err(DecodeError::NonCanonical {
            field: "RegistryChunk.chunk_count"
        }),
    );
    // A nonzero byte in the dead tail of the last chunk's data array.
    assert_eq!(
        decode_mutated(last, |bytes| bytes[DATA + 7] = 1),
        Err(DecodeError::NonCanonical {
            field: "RegistryChunk.data"
        }),
    );
    // The same byte inside the live prefix is ordinary data.
    assert_eq!(
        decode_mutated(last, |bytes| bytes[DATA + 6] = 1)
            .expect("live data accepts any byte")
            .data()[6],
        1,
    );
}

#[test]
fn chunk_ids_separate_namespace_key_index_and_network() {
    let other_network = NetworkId::new("hellas-kernel-other").expect("legal id");
    let base = chunk_id(RegistryNamespace::BondLease, 0x11, 0);

    // The namespace is what keeps one raw 32-byte key from naming two
    // records: without it, a lease and a payment record on the same edge
    // would derive the same slot.
    assert_ne!(base, chunk_id(RegistryNamespace::PaymentClose, 0x11, 0));
    assert_ne!(base, chunk_id(RegistryNamespace::BondLease, 0x12, 0));
    assert_ne!(base, chunk_id(RegistryNamespace::BondLease, 0x11, 1));
    assert_ne!(
        base,
        RegistryChunkId::derive(other_network, RegistryNamespace::BondLease, [0x11; 32], 0),
    );

    // Derivation is a pure function of its four inputs.
    assert_eq!(base, chunk_id(RegistryNamespace::BondLease, 0x11, 0));
    assert_eq!(
        RegistryChunkId::from_bytes(base.to_bytes()),
        base,
        "id bytes round trip",
    );
}

#[test]
fn chunk_id_hashes_exactly_the_specified_preimage() {
    // Separation tests alone cannot see a reordered preimage: permuting
    // the fields still gives distinct ids for distinct inputs, while
    // silently moving every stored chunk. So rebuild the preimage here
    // from literal bytes and hash it independently of `derive`.
    let mut preimage: Vec<u8> = Vec::new();
    preimage.extend_from_slice(b"hellas.registry.chunk-id.v2");
    // NetworkId encodes as a one-byte length followed by its bytes.
    let network = NETWORK.as_bytes();
    preimage.push(u8::try_from(network.len()).unwrap());
    preimage.extend_from_slice(network);
    preimage.push(RegistryNamespace::BondLease.tag());
    preimage.extend_from_slice(&[0x77; 32]);
    preimage.push(9);

    let mut hasher = hellas_xet::SingleChunkHasher::new();
    hasher.update(&preimage);

    assert_eq!(
        RegistryChunkId::derive(NETWORK, RegistryNamespace::BondLease, [0x77; 32], 9).to_bytes(),
        hasher.finalize().into_bytes(),
    );
}

#[test]
fn chunk_id_preimage_stays_inside_one_xet_chunk() {
    // `SingleChunkHasher::update` asserts rather than errors at
    // `MIN_CHUNK_SIZE`, and this derivation runs on the apply path, so
    // the widest preimage the type system permits has to be provably
    // under that bound. Every term is a compile-time maximum: the domain
    // string, the longest legal network id with its length prefix, the
    // namespace byte, the 32-byte logical key, and the index byte.
    const DOMAIN_LEN: usize = "hellas.registry.chunk-id.v2".len();
    let widest = DOMAIN_LEN + (1 + MAX_NETWORK_ID_LENGTH) + 1 + 32 + 1;

    assert_eq!(widest, 125);
    assert!(widest < hellas_xet::MIN_CHUNK_SIZE);

    // And the widest inputs really do hash without panicking.
    let filled = [b'z'; MAX_NETWORK_ID_LENGTH];
    let longest = NetworkId::new(core::str::from_utf8(&filled).expect("ascii")).expect("legal id");
    assert_eq!(longest.encoded_size(), 1 + MAX_NETWORK_ID_LENGTH);
    let _ = RegistryChunkId::derive(longest, RegistryNamespace::BondLease, [0xff; 32], u8::MAX);
}

#[test]
fn store_slots_hold_chunks_only_where_the_host_declared_them() {
    let declared = chunk_id(RegistryNamespace::BondLease, 0x11, 0);
    let undeclared = chunk_id(RegistryNamespace::BondLease, 0x11, 1);
    let body = value(9);
    let chunk = split(&body, 0);

    let mut store: FixedStore<0, 0, 1> = FixedStore::empty_with_registry([], [], [declared]);
    let mut batch = store.begin();

    assert_eq!(batch.registry_chunk(declared), None);
    assert_eq!(
        batch.insert_registry_chunk(undeclared, chunk),
        Err(InsertError::Unavailable),
        "a write to an id the host never surfaced must fail",
    );
    assert_eq!(batch.insert_registry_chunk(declared, chunk), Ok(()));
    assert_eq!(batch.registry_chunk(declared), Some(chunk));
    assert_eq!(
        batch.insert_registry_chunk(declared, chunk),
        Err(InsertError::Exists),
    );
    assert_eq!(batch.remove_registry_chunk(declared), Some(chunk));
    assert_eq!(batch.registry_chunk(declared), None);
    assert_eq!(batch.insert_registry_chunk(declared, chunk), Ok(()));
    batch.commit();

    assert_eq!(store.registry_chunk(declared), Some(chunk));

    // A dropped batch rolls the slot back, exactly as coins and edges do.
    {
        let mut batch = store.begin();
        assert_eq!(batch.remove_registry_chunk(declared), Some(chunk));
    }
    assert_eq!(store.registry_chunk(declared), Some(chunk));
}

/// The lease's slots are derived from the bond edge under the bond-lease
/// namespace, at index 0 and 1.
///
/// Rebuilt from the literal preimage rather than compared against
/// `derive` with the same arguments: that comparison would restate the
/// implementation, and would still pass if the derivation moved to
/// another namespace, another logical key, or another index — all three
/// of which silently relocate every stored lease.
#[test]
fn lease_slots_derive_from_the_bond_edge_under_the_lease_namespace() {
    let bond = EdgeId::from_bytes([0x5a; EdgeId::LENGTH]);

    for index in 0..BOND_LEASE_CHUNKS {
        let mut preimage: Vec<u8> = Vec::new();
        preimage.extend_from_slice(b"hellas.registry.chunk-id.v2");
        let network = NETWORK.as_bytes();
        preimage.push(u8::try_from(network.len()).unwrap());
        preimage.extend_from_slice(network);
        preimage.push(RegistryNamespace::BondLease.tag());
        preimage.extend_from_slice(&bond.to_bytes());
        preimage.push(index);

        let mut hasher = hellas_xet::SingleChunkHasher::new();
        hasher.update(&preimage);
        assert_eq!(
            bond_lease_slot(NETWORK, bond, index).to_bytes(),
            hasher.finalize().into_bytes(),
            "lease chunk {index}",
        );
    }

    // And the pair a caller preloads is those two slots in that order.
    assert_eq!(
        bond_lease_slots(NETWORK, bond),
        [
            bond_lease_slot(NETWORK, bond, 0),
            bond_lease_slot(NETWORK, bond, 1),
        ],
    );
}
