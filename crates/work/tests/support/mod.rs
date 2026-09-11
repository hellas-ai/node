use hellas_kernel::{EdgeId, Secp256k1Signer};

mod basic;
pub use basic::{network, temp};

pub fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

pub fn client() -> Secp256k1Signer {
    signer(0x21)
}

pub fn provider() -> Secp256k1Signer {
    signer(0x22)
}

pub fn bond_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

pub fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0x22; EdgeId::LENGTH])
}

pub fn payload_at(height: u64) -> [u8; 32] {
    let mut payload = [0xc0; 32];
    for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
        *slot = byte;
    }
    payload
}

pub fn advance(store: &mut hellas_work::work_store::ChannelStore, height: u64) {
    let mut next = store.state().cursor().0.saturating_add(1);
    while next <= height {
        let block = hellas_work::work_close::FinalizedWork {
            height: next,
            parent: payload_at(next.saturating_sub(1)),
            payload: payload_at(next),
            txs: Vec::new(),
        };
        if let Err(error) = hellas_work::work_close::observe(
            store,
            &block,
            &hellas_kernel::Secp256k1Verifier::new(),
        ) {
            panic!("the fixture block applies: {error}");
        }
        next = next.saturating_add(1);
    }
}

pub fn lease_over(
    bond: EdgeId,
    payment: EdgeId,
    terms_hash: &[u8; 32],
    private_policy_commitment: &[u8; 32],
    horizon: u64,
    format_version: u8,
    bond_lease_tag: u8,
) -> hellas_kernel::LeaseSlots {
    use hellas_kernel::{RegistryChunk, RegistryNamespace, RegistryRecordTag};

    let mut value = vec![format_version, bond_lease_tag, 2];
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(terms_hash);
    value.extend_from_slice(private_policy_commitment);
    value.extend_from_slice(&horizon.to_be_bytes());
    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, hellas_kernel::LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}
