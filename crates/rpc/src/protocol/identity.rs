use crate::{ContentId, DagCborEncoder, PublicKey, Signature};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RootKind {
    SecureEnclave = 1,
    Tpm20 = 2,
    Software = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformCredential {
    Absent,
    Registered(ContentId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderGenesisStatement {
    pub root_kind: RootKind,
    pub root_public_key: PublicKey,
    pub producer_public_key: PublicKey,
    pub transport_public_key: PublicKey,
    pub platform_credential: PlatformCredential,
    pub installation_nonce: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootProof {
    AppleAppAttest(Vec<u8>),
    Tpm20(Signature),
    Software(Signature),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedProviderGenesis {
    pub statement: ProviderGenesisStatement,
    pub root_proof: RootProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderIdentityV1 {
    pub genesis: SignedProviderGenesis,
    history: Vec<ContentId>,
}

impl ProviderGenesisStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        encode_statement(&mut e, self);
        e.into_bytes()
    }
}

impl SignedProviderGenesis {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        encode_signed(&mut e, self);
        e.into_bytes()
    }

    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }
}

impl ProviderIdentityV1 {
    pub fn new(genesis: SignedProviderGenesis) -> Self {
        Self {
            genesis,
            history: Vec::new(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        e.array(3);
        e.str("hellas.provider.identity.v1");
        encode_signed(&mut e, &self.genesis);
        e.array(self.history.len() as u64);
        for id in &self.history {
            e.bytes(id.as_bytes());
        }
        e.into_bytes()
    }
}

fn encode_statement(e: &mut DagCborEncoder, s: &ProviderGenesisStatement) {
    e.array(7);
    e.str("hellas.provider.genesis.statement.v2");
    e.u64(s.root_kind as u64);
    encode_public_key(e, &s.root_public_key);
    encode_public_key(e, &s.producer_public_key);
    encode_public_key(e, &s.transport_public_key);
    match s.platform_credential {
        PlatformCredential::Absent => {
            e.array(1);
            e.u64(0);
        }
        PlatformCredential::Registered(id) => {
            e.array(2);
            e.u64(1);
            e.bytes(id.as_bytes());
        }
    }
    e.bytes(&s.installation_nonce);
}

fn encode_signed(e: &mut DagCborEncoder, genesis: &SignedProviderGenesis) {
    e.array(3);
    e.str("hellas.provider.genesis.signed.v2");
    encode_statement(e, &genesis.statement);
    match &genesis.root_proof {
        RootProof::AppleAppAttest(proof) => encode_proof(e, 1, proof),
        RootProof::Tpm20(signature) => {
            e.array(2);
            e.u64(2);
            encode_signature(e, signature);
        }
        RootProof::Software(signature) => {
            e.array(2);
            e.u64(3);
            encode_signature(e, signature);
        }
    }
}

fn encode_proof(e: &mut DagCborEncoder, tag: u64, proof: &[u8]) {
    e.array(2);
    e.u64(tag);
    e.bytes(proof);
}

fn encode_public_key(e: &mut DagCborEncoder, key: &PublicKey) {
    e.array(2);
    e.u64(key.kind().to_byte() as u64);
    e.bytes(key.bytes());
}

fn encode_signature(e: &mut DagCborEncoder, signature: &Signature) {
    e.array(2);
    e.u64(signature.kind().to_byte() as u64);
    e.bytes(signature.bytes());
}
