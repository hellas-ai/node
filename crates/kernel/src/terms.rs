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
//!
//! # Shapes and the shared bond base
//!
//! Two of the four shapes are stake bonds: the legacy tag-1
//! [`StakeBondTerms`] and the tag-4 [`WorkStakeBondTerms`], whose first
//! fields *are* a complete legacy body. Every rule that exists because
//! an edge locks slashable stake reads that shared body through
//! [`Terms::stake_bond_base`], never through a per-variant accessor: a
//! bond profile that could answer "not a bond" would silently switch
//! off the open-time slash arithmetic and the violation payout routing.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::{HASH_LENGTH, MAX_EDGE_OUTPUTS},
    context::BlockHeight,
    list::List,
    object::Parties,
    primitive::{EdgeId, Key, ProtocolCode, TermsHash},
    tx::{CloseKindSet, Payout},
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

    /// Stake bond backing a fraud game: the maker (provider) locks stake
    /// that a proven violation slashes.
    StakeBond(StakeBondTerms),

    /// Work-payment channel: the client (maker) funds capacity the
    /// provider (taker) earns against off-chain.
    WorkPayment(WorkPaymentTerms),

    /// Work-stake bond: a [`StakeBondTerms`] base plus the dispute-game
    /// policy the work channel leases.
    WorkStakeBond(WorkStakeBondTerms),
}

// Variant numbers are consensus assignments, not positions in this
// enum. 3 is deliberately unassigned and its decode is a rejection.
const BASIC_TAG: u8 = 0;
const STAKE_BOND_TAG: u8 = 1;
const WORK_PAYMENT_TAG: u8 = 2;
const WORK_STAKE_BOND_TAG: u8 = 4;

/// Version byte carried by a work-payment body. Every other value is
/// rejected at decode, so one body shape has exactly one meaning.
const WORK_PAYMENT_VERSION: u8 = 2;

/// Epoch policy committed by a stake-bond edge.
///
/// The maker is the provider funding the stake; the taker is the client,
/// who co-signs the open and is the committed beneficiary of a
/// `Violation` close. The bond admits only `Timeout` (stake returned via
/// `timeout_outputs`) and `Violation` (stake slashed into exactly
/// `[(taker, award + surplus), (treasury, stake − award)]` — enforced
/// structurally by the kernel, so no seal verifier can redirect the
/// payout). There is deliberately no `Mutual` exit: the provider must
/// never be able to co-sign its way out from under a pending fraud
/// proof.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct StakeBondTerms {
    /// Chain-version-local protocol code selecting the seal circuit.
    pub protocol: ProtocolCode,
    /// Maker = provider (stake funder), taker = client (beneficiary).
    pub parties: Parties,
    /// Bond expiry; `Timeout` returns the stake at or after this height.
    pub timeout: BlockHeight,
    /// Committed timeout payout shape (the provider's stake return).
    pub timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    /// Settlement key receiving the non-award remainder of a slash.
    pub treasury: Key,
    /// Exact challenger award `A` paid to the client on a proven
    /// violation, `0 < A ≤ stake`.
    pub award: u64,
    /// Net stake `S`; must equal the bond edge's locked value at open.
    pub stake: u64,
    /// Largest job price this bond may cover; with `max_dispute_cost`
    /// it floors the award so a slash always makes the client whole.
    /// At least 1 — a bond that can cover no job is not a bond.
    pub max_job_price: u64,
    /// Largest dispute cost this bond may cover.
    pub max_dispute_cost: u64,
    /// Challenge margin in blocks: the challenge window plus inclusion
    /// and finality margins. A job is only covered when its terminal
    /// deadline leaves at least this margin before `timeout`, otherwise
    /// a stalling provider could push the challenge past the bond's
    /// expiry and escape into a stake refund.
    pub challenge_margin: u64,
}

/// Bond backing the correctness game of a work channel.
///
/// The base is a complete [`StakeBondTerms`], byte-for-byte in the same
/// field order a tag-1 body uses, so every stake rule applies unchanged
/// and only the dispute-game policy is new. `base.timeout` is the
/// admission horizon: a job is admissible only while its whole game
/// envelope fits below it.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct WorkStakeBondTerms {
    /// Stake policy shared with the legacy bond.
    pub base: StakeBondTerms,
    /// Largest challenge bond a game opened against this bond may
    /// require of the client.
    pub max_challenge_bond: u64,
    /// Blocks a game participant has to answer one move.
    pub move_timeout: u64,
    /// Protocol code of the dispute game this bond funds.
    pub game_protocol: u8,
}

/// Terms of the payment edge of a work channel.
///
/// The client is the maker and funds the capacity; the provider is the
/// taker and earns against it off-chain. The body embeds the complete
/// canonical bytes of the bond it names, so the kernel can bind a
/// payment to one exact bond policy without a second state read at
/// signing time.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct WorkPaymentTerms {
    /// Chain-version-local protocol code.
    pub protocol: ProtocolCode,
    /// Maker = client (capacity funder), taker = provider (earner).
    pub parties: Parties,
    /// Last height at which a job may be admitted, and the rent horizon
    /// the edge pays for. It is not a refund deadline: this shape has
    /// no timeout close.
    ///
    /// The consequence is worth stating for whoever operates one of
    /// these. Passing this height retires the channel's capacity to
    /// admit work and nothing else — it does not release the edge, does
    /// not pay anyone, and does not start a clock that will. An
    /// abandoned payment edge is settled by a co-signed `Freeze` or by
    /// the unilateral `Adjudicated` route, and by nothing else, however
    /// long it is left.
    pub admission_horizon: BlockHeight,
    /// Edge holding the bond that insures this channel's work.
    ///
    /// Naming an edge id from inside terms looks circular, because an
    /// edge id is `H(funding, terms_hash)` of the edge it names. It is
    /// not: this is a *different* edge. The bond is opened first, by the
    /// provider, from its own funding under its own
    /// [`WorkStakeBondTerms`]; only then can a payment name it. The
    /// reference points backwards in time, so the two ids form a chain,
    /// never a cycle.
    ///
    /// What the field adds over [`Self::bond_terms`] is narrower than it
    /// looks, and worth stating so nobody deletes it as redundant. The
    /// embedded body already yields the bond's terms hash, so of the two
    /// inputs to the bond's id — its funding and its terms hash — only
    /// the funding is new information here. This field is therefore not
    /// "which policy", which the body already fixes; it is "which
    /// *instantiation* of that policy", i.e. the exact coins the
    /// provider staked. Carrying the funding instead would be larger and
    /// would still need the id derived at every lookup, and the id is
    /// what the store is keyed by.
    ///
    /// The useful consequence: this payment's own id commits to
    /// `bond_edge`, which commits to the bond's funding and terms, so a
    /// payment edge transitively commits to the whole bond. It cannot be
    /// re-pointed at a different bond without becoming a different edge.
    /// That is why leasing the bond at open (see
    /// `tx::work::open_bond_lease`) is enough on its own, with no
    /// separate proof binding the two objects together.
    pub bond_edge: EdgeId,
    /// Complete bond terms the payment commits to. Their commitment is
    /// derived, not carried twice: see [`Self::bond_terms_hash`].
    pub bond_terms: WorkStakeBondTerms,
    /// Salted commitment to the bilateral risk and credit policy. The
    /// body stays private until a game reveals it.
    pub private_policy_commitment: [u8; HASH_LENGTH],
    /// Blocks the client has to answer a provider's close start before
    /// the provider's stated amount is taken as uncontested.
    pub omit_response_blocks: u64,
    /// Blocks a signed close start stays valid for inclusion.
    pub start_validity_blocks: u64,
    /// Amount the client forfeits to the provider when a close reveals
    /// the client understated the earned scalar.
    pub omission_bond: u64,
}

impl WorkPaymentTerms {
    /// Returns the commitment to the embedded bond terms.
    ///
    /// Derived rather than stored: the body already carries the bond's
    /// complete canonical bytes, so a second stored field could only
    /// ever disagree with them. The wire still spells the hash out —
    /// decode recomputes it and rejects a body whose two spellings
    /// differ.
    #[must_use]
    pub fn bond_terms_hash(&self) -> TermsHash {
        work_stake_bond_terms_hash(&self.bond_terms)
    }
}

/// Borrowed profile-specific body of a [`Terms`] value.
///
/// This is the only classification of a terms shape the kernel has.
/// Guards match on it exhaustively, so adding a shape is a compile
/// error at every site that decides policy from the shape, instead of a
/// silently skipped check.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum TermsProfile<'a> {
    /// Basic bilateral terms. Every field is reachable through the
    /// shape-independent accessors, so this arm carries no body.
    Basic,
    /// Legacy stake bond.
    StakeBond(&'a StakeBondTerms),
    /// Work-channel payment edge.
    WorkPayment(&'a WorkPaymentTerms),
    /// Work-channel stake bond.
    WorkStakeBond(&'a WorkStakeBondTerms),
}

/// Borrowed stake-bond base of a bond-shaped [`Terms`] value.
///
/// Every profile that locks slashable stake appears here, and
/// [`Self::base`] is total over them: a caller that only needs the
/// shared stake policy cannot forget a profile, and a caller that needs
/// profile-specific rules must say which profile it is handling.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum StakeBondBaseRef<'a> {
    /// Legacy tag-1 bond: the base is the whole body.
    Legacy(&'a StakeBondTerms),
    /// Tag-4 work bond: the base is its first fields.
    Work(&'a WorkStakeBondTerms),
}

impl<'a> StakeBondBaseRef<'a> {
    /// Returns the stake policy shared by every bond profile.
    #[must_use]
    pub const fn base(self) -> &'a StakeBondTerms {
        match self {
            Self::Legacy(bond) => bond,
            Self::Work(bond) => &bond.base,
        }
    }
}

impl Terms {
    /// Creates basic terms.
    #[must_use]
    pub fn basic(
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> Self {
        Self::commit(TermsBody::Basic {
            protocol,
            parties,
            timeout,
            timeout_outputs,
        })
    }

    /// Creates stake-bond terms.
    #[must_use]
    pub fn stake_bond(bond: StakeBondTerms) -> Self {
        Self::commit(TermsBody::StakeBond(bond))
    }

    /// Creates work-payment terms.
    #[must_use]
    pub fn work_payment(payment: WorkPaymentTerms) -> Self {
        Self::commit(TermsBody::WorkPayment(payment))
    }

    /// Creates work-stake-bond terms.
    #[must_use]
    pub fn work_stake_bond(bond: WorkStakeBondTerms) -> Self {
        Self::commit(TermsBody::WorkStakeBond(bond))
    }

    fn commit(body: TermsBody) -> Self {
        let hash = body.compute_hash();
        Self { body, hash }
    }

    /// Returns the canonical Xet commitment for these terms.
    ///
    /// Computed once at construction; this is a field load.
    #[must_use]
    pub const fn hash(&self) -> TermsHash {
        self.hash
    }

    /// Returns the borrowed profile-specific body.
    #[must_use]
    pub const fn profile(&self) -> TermsProfile<'_> {
        match &self.body {
            TermsBody::Basic { .. } => TermsProfile::Basic,
            TermsBody::StakeBond(bond) => TermsProfile::StakeBond(bond),
            TermsBody::WorkPayment(payment) => TermsProfile::WorkPayment(payment),
            TermsBody::WorkStakeBond(bond) => TermsProfile::WorkStakeBond(bond),
        }
    }

    /// Returns the stake-bond base when these terms lock slashable
    /// stake.
    ///
    /// Every stake rule — the open-time slash arithmetic, the violation
    /// payout routing, the consensus admission gate — reads the base
    /// through this one accessor. A bond profile answering `None` here
    /// would not be "a bond with no extra rules"; it would be a bond
    /// with no rules at all, which is why the match below is exhaustive
    /// over the body rather than a lookup of the shapes that happened to
    /// exist when it was written.
    #[must_use]
    pub const fn stake_bond_base(&self) -> Option<StakeBondBaseRef<'_>> {
        match &self.body {
            TermsBody::Basic { .. } | TermsBody::WorkPayment(_) => None,
            TermsBody::StakeBond(bond) => Some(StakeBondBaseRef::Legacy(bond)),
            TermsBody::WorkStakeBond(bond) => Some(StakeBondBaseRef::Work(bond)),
        }
    }

    /// Returns the chain-version-local protocol code.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolCode {
        match &self.body {
            TermsBody::Basic { protocol, .. } => *protocol,
            TermsBody::StakeBond(bond) => bond.protocol,
            TermsBody::WorkPayment(payment) => payment.protocol,
            TermsBody::WorkStakeBond(bond) => bond.base.protocol,
        }
    }

    /// Returns the committed parties.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        match &self.body {
            TermsBody::Basic { parties, .. } => *parties,
            TermsBody::StakeBond(bond) => bond.parties,
            TermsBody::WorkPayment(payment) => payment.parties,
            TermsBody::WorkStakeBond(bond) => bond.base.parties,
        }
    }

    /// Returns the committed lifetime horizon.
    ///
    /// For every shape but work payment this is the height a `Timeout`
    /// close becomes available. Work payment commits the same field as
    /// an admission and rent horizon with no refund attached.
    #[must_use]
    pub const fn timeout(&self) -> BlockHeight {
        match &self.body {
            TermsBody::Basic { timeout, .. } => *timeout,
            TermsBody::StakeBond(bond) => bond.timeout,
            TermsBody::WorkPayment(payment) => payment.admission_horizon,
            TermsBody::WorkStakeBond(bond) => bond.base.timeout,
        }
    }

    /// Returns the deterministic timeout payout shape, including any reserve
    /// surplus left after the open-time committed timeout close fee.
    ///
    /// `None` for work payment, the one shape with no timeout close: a
    /// fixed refund payable after the provider has earned against the
    /// channel would pay the wrong party. Callers that need a payout
    /// must handle the absence; none may substitute an empty list,
    /// which is a different commitment (pay nobody everything).
    #[must_use]
    pub const fn timeout_outputs(&self) -> Option<&List<Payout, MAX_EDGE_OUTPUTS>> {
        match &self.body {
            TermsBody::Basic {
                timeout_outputs, ..
            } => Some(timeout_outputs),
            TermsBody::StakeBond(bond) => Some(&bond.timeout_outputs),
            TermsBody::WorkPayment(_) => None,
            TermsBody::WorkStakeBond(bond) => Some(&bond.base.timeout_outputs),
        }
    }

    /// Returns the close kinds this terms shape admits.
    ///
    /// Fixed structurally per shape — no field to misconfigure. Each
    /// shape names its set explicitly, so a newly assigned close kind
    /// joins a shape only when someone decides it should.
    #[must_use]
    pub const fn allowed_closes(&self) -> CloseKindSet {
        match &self.body {
            TermsBody::Basic { .. } => CloseKindSet::BASIC,
            TermsBody::StakeBond(_) => CloseKindSet::STAKE_BOND,
            TermsBody::WorkPayment(_) => CloseKindSet::WORK_PAYMENT,
            TermsBody::WorkStakeBond(_) => CloseKindSet::WORK_STAKE_BOND,
        }
    }
}

/// Returns the commitment a tag-4 bond body carries.
///
/// The preimage is the bond's standalone `Terms` encoding, which is
/// exactly the witness a work-payment body embeds; a payment can
/// therefore name its bond by the same hash the bond edge stores.
fn work_stake_bond_terms_hash(bond: &WorkStakeBondTerms) -> TermsHash {
    let mut hasher = hellas_xet::SingleChunkHasher::new();
    hasher.update(crate::consts::TERMS_WORK_STAKE_BOND);
    encode_work_stake_bond_witness(&mut hasher, bond);
    TermsHash::from_bytes(hasher.finalize().into_bytes())
}

/// Writes the complete tag-4 `Terms` bytes for `bond`.
///
/// Deliberately not a nested owned `Terms`: the payment body carries a
/// bond's canonical bytes, and nothing in the decoder recurses into a
/// second terms object.
fn encode_work_stake_bond_witness<W: Writer + ?Sized>(writer: &mut W, bond: &WorkStakeBondTerms) {
    encode_envelope(writer, tag::TERMS);
    WORK_STAKE_BOND_TAG.encode_to(writer);
    bond.encode_to(writer);
}

fn decode_work_stake_bond_witness(buf: &[u8]) -> Result<(WorkStakeBondTerms, usize), DecodeError> {
    let mut consumed = decode_envelope(buf, tag::TERMS)?;
    let variant = decode_field::<u8>(buf, &mut consumed)?;
    if variant != WORK_STAKE_BOND_TAG {
        return Err(DecodeError::InvalidTag { tag: variant });
    }
    let bond = decode_field(buf, &mut consumed)?;
    Ok((bond, consumed))
}

const WORK_STAKE_BOND_WITNESS_MAX_SIZE: usize =
    ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + WorkStakeBondTerms::MAX_ENCODED_SIZE;

fn work_stake_bond_witness_size(bond: &WorkStakeBondTerms) -> usize {
    ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + bond.encoded_size()
}

impl TermsBody {
    fn compute_hash(&self) -> TermsHash {
        // The hash domain is the structural tag for this body shape:
        // different semantics can never share the same canonical bytes.
        let domain = match self {
            Self::Basic { .. } => crate::consts::TERMS_BASIC,
            Self::StakeBond(_) => crate::consts::TERMS_STAKE_BOND,
            Self::WorkPayment(_) => crate::consts::TERMS_WORK_PAYMENT,
            Self::WorkStakeBond(_) => crate::consts::TERMS_WORK_STAKE_BOND,
        };
        TermsHash::from_bytes(crate::canonical::hash(domain, self).into_bytes())
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

const BASIC_BODY_SIZE: usize = ProtocolCode::MAX_ENCODED_SIZE
    + Parties::MAX_ENCODED_SIZE
    + BlockHeight::MAX_ENCODED_SIZE
    + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE;

impl Encode for StakeBondTerms {
    const MAX_ENCODED_SIZE: usize =
        BASIC_BODY_SIZE + Key::MAX_ENCODED_SIZE + 5 * u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ProtocolCode::MAX_ENCODED_SIZE
            + Parties::MAX_ENCODED_SIZE
            + BlockHeight::MAX_ENCODED_SIZE
            + self.timeout_outputs.encoded_size()
            + Key::MAX_ENCODED_SIZE
            + 5 * u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.protocol.encode_to(writer);
        self.parties.encode_to(writer);
        self.timeout.encode_to(writer);
        self.timeout_outputs.encode_to(writer);
        self.treasury.encode_to(writer);
        self.award.encode_to(writer);
        self.stake.encode_to(writer);
        self.max_job_price.encode_to(writer);
        self.max_dispute_cost.encode_to(writer);
        self.challenge_margin.encode_to(writer);
    }
}

impl Decode for StakeBondTerms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let protocol = decode_field(buf, &mut consumed)?;
        let parties = decode_field(buf, &mut consumed)?;
        let timeout = decode_field(buf, &mut consumed)?;
        let timeout_outputs = decode_field(buf, &mut consumed)?;
        let treasury = decode_field(buf, &mut consumed)?;
        let award = decode_field(buf, &mut consumed)?;
        let stake = decode_field(buf, &mut consumed)?;
        let max_job_price = decode_field(buf, &mut consumed)?;
        let max_dispute_cost = decode_field(buf, &mut consumed)?;
        let challenge_margin = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                protocol,
                parties,
                timeout,
                timeout_outputs,
                treasury,
                award,
                stake,
                max_job_price,
                max_dispute_cost,
                challenge_margin,
            },
            consumed,
        ))
    }
}

impl Encode for WorkStakeBondTerms {
    const MAX_ENCODED_SIZE: usize =
        StakeBondTerms::MAX_ENCODED_SIZE + 2 * u64::MAX_ENCODED_SIZE + u8::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        self.base.encoded_size() + 2 * u64::MAX_ENCODED_SIZE + u8::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.base.encode_to(writer);
        self.max_challenge_bond.encode_to(writer);
        self.move_timeout.encode_to(writer);
        self.game_protocol.encode_to(writer);
    }
}

impl Decode for WorkStakeBondTerms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let base = decode_field(buf, &mut consumed)?;
        let max_challenge_bond = decode_field(buf, &mut consumed)?;
        let move_timeout = decode_field(buf, &mut consumed)?;
        let game_protocol = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                base,
                max_challenge_bond,
                move_timeout,
                game_protocol,
            },
            consumed,
        ))
    }
}

impl Encode for WorkPaymentTerms {
    const MAX_ENCODED_SIZE: usize = u8::MAX_ENCODED_SIZE
        + ProtocolCode::MAX_ENCODED_SIZE
        + Parties::MAX_ENCODED_SIZE
        + BlockHeight::MAX_ENCODED_SIZE
        + EdgeId::MAX_ENCODED_SIZE
        + TermsHash::MAX_ENCODED_SIZE
        + WORK_STAKE_BOND_WITNESS_MAX_SIZE
        + HASH_LENGTH
        + 3 * u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        u8::MAX_ENCODED_SIZE
            + ProtocolCode::MAX_ENCODED_SIZE
            + Parties::MAX_ENCODED_SIZE
            + BlockHeight::MAX_ENCODED_SIZE
            + EdgeId::MAX_ENCODED_SIZE
            + TermsHash::MAX_ENCODED_SIZE
            + work_stake_bond_witness_size(&self.bond_terms)
            + HASH_LENGTH
            + 3 * u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        WORK_PAYMENT_VERSION.encode_to(writer);
        self.protocol.encode_to(writer);
        self.parties.encode_to(writer);
        self.admission_horizon.encode_to(writer);
        self.bond_edge.encode_to(writer);
        self.bond_terms_hash().encode_to(writer);
        encode_work_stake_bond_witness(writer, &self.bond_terms);
        self.private_policy_commitment.encode_to(writer);
        self.omit_response_blocks.encode_to(writer);
        self.start_validity_blocks.encode_to(writer);
        self.omission_bond.encode_to(writer);
    }
}

impl Decode for WorkPaymentTerms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let version = decode_field::<u8>(buf, &mut consumed)?;
        if version != WORK_PAYMENT_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let protocol = decode_field(buf, &mut consumed)?;
        let parties = decode_field(buf, &mut consumed)?;
        let admission_horizon = decode_field(buf, &mut consumed)?;
        let bond_edge = decode_field(buf, &mut consumed)?;
        let committed_bond_hash = decode_field::<TermsHash>(buf, &mut consumed)?;
        let rest = buf.get(consumed..).ok_or(DecodeError::InvalidConsumption {
            consumed,
            available: buf.len(),
        })?;
        let (bond_terms, witness_size) = decode_work_stake_bond_witness(rest)?;
        consumed += witness_size;
        let private_policy_commitment = decode_field(buf, &mut consumed)?;
        let omit_response_blocks = decode_field(buf, &mut consumed)?;
        let start_validity_blocks = decode_field(buf, &mut consumed)?;
        let omission_bond = decode_field(buf, &mut consumed)?;
        // The witness is the source of truth for the bond policy; the
        // hash field is its spelled-out commitment. Accepting a body
        // where they disagree would give one bond two commitments.
        if committed_bond_hash != work_stake_bond_terms_hash(&bond_terms) {
            return Err(DecodeError::NonCanonical {
                field: "bond_terms_hash",
            });
        }
        Ok((
            Self {
                protocol,
                parties,
                admission_horizon,
                bond_edge,
                bond_terms,
                private_policy_commitment,
                omit_response_blocks,
                start_validity_blocks,
                omission_bond,
            },
            consumed,
        ))
    }
}

impl Encode for TermsBody {
    const MAX_ENCODED_SIZE: usize = {
        // The widest body decides every buffer that holds a `Terms`,
        // and through `Tx` every chain transaction buffer.
        let mut max_body = BASIC_BODY_SIZE;
        if StakeBondTerms::MAX_ENCODED_SIZE > max_body {
            max_body = StakeBondTerms::MAX_ENCODED_SIZE;
        }
        if WorkStakeBondTerms::MAX_ENCODED_SIZE > max_body {
            max_body = WorkStakeBondTerms::MAX_ENCODED_SIZE;
        }
        if WorkPaymentTerms::MAX_ENCODED_SIZE > max_body {
            max_body = WorkPaymentTerms::MAX_ENCODED_SIZE;
        }
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + max_body
    };

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Basic {
                    protocol,
                    parties,
                    timeout,
                    timeout_outputs,
                } => {
                    protocol.encoded_size()
                        + parties.encoded_size()
                        + timeout.encoded_size()
                        + timeout_outputs.encoded_size()
                }
                Self::StakeBond(bond) => bond.encoded_size(),
                Self::WorkPayment(payment) => payment.encoded_size(),
                Self::WorkStakeBond(bond) => bond.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::TERMS);
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                BASIC_TAG.encode_to(writer);
                protocol.encode_to(writer);
                parties.encode_to(writer);
                timeout.encode_to(writer);
                timeout_outputs.encode_to(writer);
            }
            Self::StakeBond(bond) => {
                STAKE_BOND_TAG.encode_to(writer);
                bond.encode_to(writer);
            }
            Self::WorkPayment(payment) => {
                WORK_PAYMENT_TAG.encode_to(writer);
                payment.encode_to(writer);
            }
            Self::WorkStakeBond(bond) => {
                WORK_STAKE_BOND_TAG.encode_to(writer);
                bond.encode_to(writer);
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
            STAKE_BOND_TAG => {
                let bond = decode_field(buf, &mut consumed)?;
                Ok((Self::StakeBond(bond), consumed))
            }
            WORK_PAYMENT_TAG => {
                let payment = decode_field(buf, &mut consumed)?;
                Ok((Self::WorkPayment(payment), consumed))
            }
            WORK_STAKE_BOND_TAG => {
                let bond = decode_field(buf, &mut consumed)?;
                Ok((Self::WorkStakeBond(bond), consumed))
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
        consts::{TERMS_BASIC, TERMS_STAKE_BOND, TERMS_WORK_PAYMENT},
        primitive::Key,
        tx::CloseKind,
    };

    fn sample_bond() -> StakeBondTerms {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(maker, 12);
        StakeBondTerms {
            protocol: ProtocolCode::new(2),
            parties: Parties::new(maker, taker),
            timeout: BlockHeight::new(77),
            timeout_outputs: List::take(outputs, 1),
            treasury: Key::from_bytes([9; Key::LENGTH]),
            award: 7,
            stake: 12,
            max_job_price: 4,
            max_dispute_cost: 3,
            challenge_margin: 5,
        }
    }

    fn sample_work_bond() -> WorkStakeBondTerms {
        WorkStakeBondTerms {
            base: sample_bond(),
            max_challenge_bond: 3,
            move_timeout: 20,
            game_protocol: ProtocolCode::CATENA_FRAUD_V2.get(),
        }
    }

    fn sample_payment() -> WorkPaymentTerms {
        let bond = sample_work_bond();
        WorkPaymentTerms {
            protocol: ProtocolCode::CATENA_FRAUD_V2,
            // Mirrored: the bond's taker (client) is the payment maker.
            parties: Parties::new(bond.base.parties.taker(), bond.base.parties.maker()),
            admission_horizon: bond.base.timeout,
            bond_edge: EdgeId::from_bytes([5; EdgeId::LENGTH]),
            bond_terms: bond,
            private_policy_commitment: [6; HASH_LENGTH],
            omit_response_blocks: 64,
            start_validity_blocks: 8,
            omission_bond: 3,
        }
    }

    fn round_trip(terms: &Terms) {
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let written = terms.write_to(&mut buf);
        assert_eq!(written, terms.encoded_size());
        let Ok((decoded, consumed)) = Terms::decode(&buf[..written]) else {
            panic!("terms decode");
        };
        assert_eq!(consumed, written);
        assert_eq!(&decoded, terms);
    }

    #[test]
    fn stake_bond_terms_round_trip_under_their_own_domain() {
        let bond = sample_bond();
        let terms = Terms::stake_bond(bond.clone());

        let expected = TermsHash::from_bytes(hash(TERMS_STAKE_BOND, &terms.body).into_bytes());
        assert_eq!(terms.hash(), expected);
        assert_eq!(
            terms.stake_bond_base().map(StakeBondBaseRef::base),
            Some(&bond),
        );
        assert_eq!(terms.protocol(), bond.protocol);
        assert_eq!(terms.parties(), bond.parties);
        assert_eq!(terms.timeout(), bond.timeout);
        assert_eq!(terms.timeout_outputs(), Some(&bond.timeout_outputs));

        round_trip(&terms);
    }

    #[test]
    fn work_stake_bond_exposes_the_same_base_as_a_legacy_bond() {
        let work = sample_work_bond();
        let terms = Terms::work_stake_bond(work.clone());

        assert_eq!(
            terms.stake_bond_base().map(StakeBondBaseRef::base),
            Some(&work.base),
        );
        assert_eq!(terms.protocol(), work.base.protocol);
        assert_eq!(terms.parties(), work.base.parties);
        assert_eq!(terms.timeout(), work.base.timeout);
        assert_eq!(terms.timeout_outputs(), Some(&work.base.timeout_outputs));
        round_trip(&terms);
    }

    #[test]
    fn work_payment_terms_round_trip_under_their_own_domain() {
        let payment = sample_payment();
        let terms = Terms::work_payment(payment.clone());

        let expected = TermsHash::from_bytes(hash(TERMS_WORK_PAYMENT, &terms.body).into_bytes());
        assert_eq!(terms.hash(), expected);
        assert_eq!(terms.protocol(), payment.protocol);
        assert_eq!(terms.parties(), payment.parties);
        assert_eq!(terms.timeout(), payment.admission_horizon);
        assert_eq!(terms.timeout_outputs(), None);
        assert_eq!(terms.stake_bond_base(), None);
        round_trip(&terms);
    }

    /// The embedded witness is the bond's own canonical `Terms` bytes,
    /// so a payment names its bond by the hash the bond edge stores.
    #[test]
    fn embedded_bond_witness_hashes_as_a_standalone_bond() {
        let payment = sample_payment();
        let standalone = Terms::work_stake_bond(payment.bond_terms.clone());

        assert_eq!(payment.bond_terms_hash(), standalone.hash());

        let mut witness = [0; WORK_STAKE_BOND_WITNESS_MAX_SIZE];
        let mut writer = BufferWriter::new(&mut witness);
        encode_work_stake_bond_witness(&mut writer, &payment.bond_terms);
        let written = writer.position();
        let mut standalone_bytes = [0; TermsBody::MAX_ENCODED_SIZE];
        let standalone_written = standalone.write_to(&mut standalone_bytes);
        assert_eq!(written, standalone_written);
        assert_eq!(&witness[..written], &standalone_bytes[..standalone_written]);
    }

    /// A body whose spelled-out bond commitment disagrees with the
    /// witness it carries has no canonical meaning; decode refuses it
    /// rather than picking one of the two.
    #[test]
    fn work_payment_rejects_a_bond_hash_that_does_not_bind_its_witness() {
        let terms = Terms::work_payment(sample_payment());
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let written = terms.write_to(&mut buf);
        // Offset of the first byte of the spelled-out commitment.
        let hash_start = ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + u8::MAX_ENCODED_SIZE
            + ProtocolCode::MAX_ENCODED_SIZE
            + Parties::MAX_ENCODED_SIZE
            + BlockHeight::MAX_ENCODED_SIZE
            + EdgeId::MAX_ENCODED_SIZE;
        buf[hash_start] ^= 0xff;

        assert_eq!(
            Terms::decode(&buf[..written]).map(|(_, consumed)| consumed),
            Err(DecodeError::NonCanonical {
                field: "bond_terms_hash",
            }),
        );
    }

    /// Variant 3 is reserved by the wire assignment table; the decoder
    /// must reject it rather than treat it as a future body it can skip.
    #[test]
    fn reserved_terms_variant_is_rejected() {
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let terms = Terms::stake_bond(sample_bond());
        let written = terms.write_to(&mut buf);
        buf[ENVELOPE_SIZE] = 3;

        assert_eq!(
            Terms::decode(&buf[..written]).map(|(_, consumed)| consumed),
            Err(DecodeError::InvalidTag { tag: 3 }),
        );
    }

    #[test]
    fn close_kind_sets_are_fixed_per_terms_shape() {
        let bond = Terms::stake_bond(sample_bond());
        assert!(!bond.allowed_closes().contains(CloseKind::Mutual));
        assert!(bond.allowed_closes().contains(CloseKind::Timeout));
        assert!(bond.allowed_closes().contains(CloseKind::Violation));

        let work_bond = Terms::work_stake_bond(sample_work_bond());
        assert!(!work_bond.allowed_closes().contains(CloseKind::Mutual));
        assert!(work_bond.allowed_closes().contains(CloseKind::Timeout));
        assert!(work_bond.allowed_closes().contains(CloseKind::Violation));
        assert!(
            work_bond
                .allowed_closes()
                .contains(CloseKind::WorkStakeMutual)
        );

        let payment = Terms::work_payment(sample_payment());
        assert!(payment.allowed_closes().contains(CloseKind::Freeze));
        assert!(payment.allowed_closes().contains(CloseKind::Adjudicated));
        assert!(!payment.allowed_closes().contains(CloseKind::Timeout));

        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let basic = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
        );
        for kind in [CloseKind::Mutual, CloseKind::Timeout, CloseKind::Violation] {
            assert!(basic.allowed_closes().contains(kind));
        }
        assert!(!basic.allowed_closes().contains(CloseKind::Freeze));
    }

    /// Every shape is classified once, and the bond shapes are exactly
    /// the shapes that expose a stake base. A profile added without a
    /// `stake_bond_base` answer fails to compile; a profile that
    /// answers wrongly fails here.
    #[test]
    fn only_bond_shapes_expose_a_stake_base() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let basic = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
        );
        let cases = [
            basic,
            Terms::stake_bond(sample_bond()),
            Terms::work_payment(sample_payment()),
            Terms::work_stake_bond(sample_work_bond()),
        ];

        let mut seen = [false; 4];
        for terms in &cases {
            // Adding a shape breaks this match, which is the point:
            // the shape has to be classified as bond or not-bond here
            // before its terms can be used anywhere.
            let (index, is_bond) = match terms.profile() {
                TermsProfile::Basic => (0, false),
                TermsProfile::StakeBond(_) => (1, true),
                TermsProfile::WorkPayment(_) => (2, false),
                TermsProfile::WorkStakeBond(_) => (3, true),
            };
            seen[index] = true;
            assert_eq!(
                terms.stake_bond_base().is_some(),
                is_bond,
                "shape {index} disagrees with its stake-base answer",
            );
            assert_eq!(terms.timeout_outputs().is_none(), index == 2);
        }
        assert_eq!(seen, [true; 4]);
    }

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

        let expected = TermsHash::from_bytes(hash(TERMS_BASIC, &terms.body).into_bytes());
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

        assert_eq!(body.encoded_size(), writer.position());
        assert!(body.encoded_size() <= TermsBody::MAX_ENCODED_SIZE);
        let maker_start =
            ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + ProtocolCode::MAX_ENCODED_SIZE + ENVELOPE_SIZE;
        let taker_start = maker_start + Key::LENGTH;
        let parties_end = taker_start + Key::LENGTH;

        assert_eq!(&buf[..4], &[1, tag::TERMS, BASIC_TAG, 1]);
        assert_eq!(&buf[4..maker_start], &[1, tag::PARTIES]);
        assert_eq!(&buf[maker_start..taker_start], maker.as_bytes());
        assert_eq!(&buf[taker_start..parties_end], taker.as_bytes());
    }

    /// The widest body is the work payment, and it is what every buffer
    /// sized by `Terms::MAX_ENCODED_SIZE` must hold.
    #[test]
    fn declared_body_bounds_match_the_widest_encoding() {
        assert_eq!(
            BASIC_BODY_SIZE
                + Key::MAX_ENCODED_SIZE
                + 5 * u64::MAX_ENCODED_SIZE
                + 2 * u64::MAX_ENCODED_SIZE
                + u8::MAX_ENCODED_SIZE,
            WorkStakeBondTerms::MAX_ENCODED_SIZE,
        );
        assert_eq!(
            TermsBody::MAX_ENCODED_SIZE,
            ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + WorkPaymentTerms::MAX_ENCODED_SIZE,
        );

        let maker = Key::from_bytes([1; Key::LENGTH]);
        let mut widest = sample_payment();
        widest.bond_terms.base.timeout_outputs =
            List::all([Payout::new(maker, 7); MAX_EDGE_OUTPUTS]);
        let terms = Terms::work_payment(widest);
        assert_eq!(terms.encoded_size(), Terms::MAX_ENCODED_SIZE);
        round_trip(&terms);
    }
}
