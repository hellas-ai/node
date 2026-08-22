//! The two-Open handshake on the wire: how two endpoints that have
//! never met get a channel to do paid work on.
//!
//! # What this is, and what it is not
//!
//! [`crate::protocol::work_bundle`] is the artifact, and it says of
//! itself that "somebody has to carry half-signed bytes between the two
//! processes". [`crate::work_store::setup`] is the journal that fsyncs
//! each revision before the signature it carries is exported. This is
//! the carrier those two were written for, and it adds no rule to
//! either: every check here is one of theirs, run by
//! [`SetupStore::commit`], and this module's whole content is who calls
//! it and in what order.
//!
//! # The order
//!
//! One method, two round trips, and the client drives both because the
//! client is the party that dials.
//!
//! 1. The client asks with nothing. The provider answers with the
//!    revision-1 bond proposal its own journal already holds — already
//!    signed, already durable, because the step that signed it
//!    (`SetupEndpoint::propose_bond`) journaled it first.
//! 2. The client journals that proposal, countersigns the bond, names
//!    the funding and terms of the payment channel it wants over it,
//!    and journals *that* — revision 2 — before it is sent.
//! 3. The provider journals the arriving revision 2, countersigns the
//!    payment, journals revision 3, and only then answers with it.
//!
//! Both transactions are now executable and only the provider holds
//! them both, which is what `SetupState::decide` resumes from.
//!
//! The rule this obeys is `work_store`'s and it bites hardest at step
//! 3: the co-signature is inside the record, so committing the record
//! first is the whole of what stops a signature leaving a process that
//! has no memory of making it. There is no signing in the handler and
//! then a write afterwards, and there is nothing here that could be
//! reordered into one.
//!
//! # Why no connection binding
//!
//! `DeliverResult` needs one because a `work_id` is an identifier: it
//! travels, and anyone holding one could make the provider release
//! plaintext and debit the real client's credit. Nothing here has that
//! shape. The request carries no identifier — it carries the artifact
//! itself, and every signature in that artifact is verified against the
//! party its own terms name before a byte of the answer is produced.
//!
//! So the two things a bearer capability would give an attacker are
//! both absent. A stranger cannot make the provider countersign
//! anything, because a revision 2 requires the client's signature over
//! both open hashes and those hashes are over this bond's terms, this
//! funding, and this network. And replaying a captured revision gains
//! nothing: the journal recognises what it already holds, writes
//! nothing, and returns the bytes it had already given the party that
//! signed them.
//!
//! # Who may sign what
//!
//! Not decided here either. `WorkChannelSetupBundleV1::check` reads the
//! signing party out of `bond_terms.parties` — maker is the provider,
//! taker is the client — so a client that tried to propose a bond, or a
//! provider that tried to propose a payment, fails its own journal's
//! commit. There is no role argument on any function below, because a
//! role argument would be a second answer to a question the signatures
//! already answer.

use std::sync::{Arc, Mutex};

use hellas_kernel::{
    Auth, Funding, NetworkId, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkPaymentTerms,
    WorkStakeBondTerms,
};
use hellas_wire::{StreamTransport, TransportContext, WireStatus};

use crate::pb::work::{
    ExchangeSetupRequest, ExchangeSetupResponse, SetupAdvanced, WorkRefused,
    exchange_setup_response::Outcome,
};
use crate::protocol::work_bundle::WorkChannelSetupBundleV1;
use crate::services::work_setup::{WorkSetupClientImpl, WorkSetupHandler};
use crate::work::{Refusal, WorkRefusal};
use crate::work_store::{SetupRecord, SetupState, SetupStateError, SetupStore, WorkStoreError};

// ── Refusals ──────────────────────────────────────────────────────────

/// Maps one journal answer onto the wire's six refusals.
///
/// The split that matters is whose fault it is. Everything a
/// [`SetupStateError`] grades is a judgement about the bytes the caller
/// sent — a signature that is not the named party's, a revision that
/// does not extend the retained one, a bundle over another bond — and
/// all of it is permanent for those bytes, which is what `Invalid`
/// means. The two exceptions are about state rather than bytes: a
/// handshake that has already ended will not take another revision
/// however well formed it is, and a file that will not append is this
/// endpoint's own storage.
fn refuse(error: &WorkStoreError) -> Refusal {
    let code = match error {
        WorkStoreError::Journal(_) => WorkRefusal::Unavailable,
        WorkStoreError::Setup(SetupStateError::Ended(_)) => WorkRefusal::Declined,
        WorkStoreError::Setup(_) => WorkRefusal::Invalid,
        // A channel record cannot reach a setup journal: `SetupStore`
        // takes `SetupRecord` and nothing else. Mapped so the match is
        // total, and no test claims to reach it.
        WorkStoreError::Channel(_) => WorkRefusal::Invalid,
    };
    Refusal::new(code, error.to_string())
}

/// Why one endpoint could not take a step of the handshake.
#[derive(Debug, thiserror::Error)]
pub enum SetupExchangeError {
    /// The peer refused.
    #[error("the peer refused as {refusal}: {reason}")]
    Refused {
        /// Which of the six answers came back.
        refusal: WorkRefusal,
        /// The peer's diagnostic text, unchecked and uncovered by any
        /// digest.
        reason: String,
    },
    /// The response was not one of the shapes the service defines.
    #[error("the peer's response has no readable {0}")]
    Malformed(&'static str),
    /// This endpoint holds no revision to offer or to extend.
    #[error("this endpoint has journaled no revision of this handshake")]
    NothingHeld,
    /// The journal refused the revision, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The call did not complete.
    #[error("the setup call failed: {0}")]
    Transport(#[from] WireStatus),
}

// ── One endpoint's half of the handshake ──────────────────────────────

/// One endpoint's setup journal and the key it signs revisions with.
///
/// Either endpoint: there is no role field, and the three steps below
/// are refused to the wrong party by the bundle's own signature checks
/// rather than by anything here.
#[derive(Debug)]
pub struct SetupEndpoint {
    store: SetupStore,
    signer: Secp256k1Signer,
}

impl SetupEndpoint {
    /// Takes one setup journal and the settlement key its revisions are
    /// signed with.
    #[must_use]
    pub const fn new(store: SetupStore, signer: Secp256k1Signer) -> Self {
        Self { store, signer }
    }

    /// Returns what this endpoint's handshake has durably reached.
    #[must_use]
    pub const fn state(&self) -> &SetupState {
        self.store.state()
    }

    /// Signs the bond this endpoint will stake, and journals it before
    /// there is anything to export.
    ///
    /// The provider's first step, and the only one that is not a reply.
    /// Called again with the same funding and terms it writes nothing:
    /// the journal recognises the revision it already holds, and the
    /// signature is deterministic, so the second call reproduces the
    /// first one's bytes rather than replacing them.
    ///
    /// # Errors
    ///
    /// [`SetupExchangeError::Store`] when the bond is not one this
    /// signer may propose — the bundle's own check requires the
    /// signature to be the maker's, which is the staking party — when
    /// the bundle is over another network or bond than this journal is
    /// keyed to, when the handshake has already moved past its first
    /// revision, or when the record cannot be made durable.
    pub fn propose_bond(
        &mut self,
        network: NetworkId,
        bond_funding: Funding,
        bond_terms: WorkStakeBondTerms,
    ) -> Result<&SetupState, SetupExchangeError> {
        // The kernel's own open hash, which is the same function
        // `WorkChannelSetupBundleV1::bond_open_hash` calls. It is
        // reached directly here only because the bundle that would
        // expose it is the thing this signature is being made to build.
        let hash = Tx::open_hash(
            network,
            &bond_funding,
            &Terms::work_stake_bond(bond_terms.clone()),
        );
        let auth = Auth::native(self.signer.sign(hash));
        let bundle =
            WorkChannelSetupBundleV1::propose_bond(network, bond_funding, bond_terms, auth)
                .map_err(|error| WorkStoreError::Setup(SetupStateError::Bundle(error)))?;
        self.commit(&bundle)
    }

    /// Countersigns the retained bond and names the payment channel to
    /// open over it, journaling both before either signature can leave.
    ///
    /// The client's step, and it fixes both of the client's own choices
    /// in the revision that releases its bond countersignature — which
    /// is `work_bundle`'s rule, not a convenience: no endpoint stakes a
    /// signature on a bond and only afterwards learns what channel it
    /// will be asked to fund over it.
    ///
    /// # Errors
    ///
    /// [`SetupExchangeError::NothingHeld`] before the provider's
    /// proposal has been imported, and [`SetupExchangeError::Store`]
    /// when the payment terms are not over the retained bond, when a
    /// coin funds both opens, when this signer is not the party the
    /// bond terms name as taker, or when the record cannot be made
    /// durable.
    pub fn propose_payment(
        &mut self,
        payment_funding: Funding,
        payment_terms: WorkPaymentTerms,
    ) -> Result<&SetupState, SetupExchangeError> {
        let held = self
            .state()
            .bundle()
            .ok_or(SetupExchangeError::NothingHeld)?
            .clone();
        let payment_hash = Tx::open_hash(
            held.network(),
            &payment_funding,
            &Terms::work_payment(payment_terms.clone()),
        );
        let bond_auth = Auth::native(self.signer.sign(held.bond_open_hash()));
        let bundle = held
            .countersign_bond_and_propose_payment(
                bond_auth,
                payment_funding,
                payment_terms,
                Auth::native(self.signer.sign(payment_hash)),
            )
            .map_err(|error| WorkStoreError::Setup(SetupStateError::Bundle(error)))?;
        self.commit(&bundle)
    }

    /// Takes one revision a peer answered with.
    ///
    /// Every rule is the journal's: the signatures are verified against
    /// the parties the terms name, the revision must extend the one
    /// held without rewriting it, and the bundle must be over this
    /// journal's own network and bond.
    ///
    /// # Errors
    ///
    /// [`SetupExchangeError::Store`] for every one of those rules, and
    /// when the record cannot be made durable.
    pub fn import(&mut self, bundle: &[u8]) -> Result<&SetupState, SetupExchangeError> {
        Ok(self.store.commit(
            SetupRecord::Bundle {
                bundle: bundle.to_vec(),
            },
            &Secp256k1Verifier::new(),
        )?)
    }

    /// Answers one offered revision with the revision that extends it.
    ///
    /// The server half, and the order is the whole of it: the offered
    /// revision is journaled, this endpoint's own countersignature is
    /// journaled inside the revision that carries it, and only then are
    /// bytes returned. Nothing is signed and held in memory.
    ///
    /// An empty offer is a caller that holds nothing and wants this
    /// endpoint's proposal. A replayed offer writes nothing and is
    /// answered with the same bytes.
    fn advance(&mut self, offered: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !offered.is_empty() {
            self.store
                .commit(
                    SetupRecord::Bundle {
                        bundle: offered.to_vec(),
                    },
                    &Secp256k1Verifier::new(),
                )
                .map_err(|error| refuse(&error))?;
        }

        // The one revision that asks this endpoint for a signature.
        // `payment_open_hash` is `Some` exactly when a payment leg
        // exists, which is what revision 2 means, so the hash is read
        // through the accessor rather than respelled here.
        let countersigned = self
            .state()
            .bundle()
            .filter(|bundle| bundle.revision() == 2)
            .and_then(|bundle| Some((bundle.clone(), bundle.payment_open_hash()?)))
            .map(|(bundle, hash)| bundle.countersign_payment(Auth::native(self.signer.sign(hash))));
        if let Some(next) = countersigned {
            // `countersign_payment` refuses every stage but the second,
            // and the filter above is that stage. Mapped so the match
            // is total; no test reaches it, and none claims to.
            let next =
                next.map_err(|error| Refusal::new(WorkRefusal::Invalid, error.to_string()))?;
            self.commit(&next).map_err(|error| match error {
                SetupExchangeError::Store(store) => refuse(&store),
                other => Refusal::new(WorkRefusal::Unavailable, other.to_string()),
            })?;
        }

        self.state()
            .bundle_bytes()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                Refusal::new(
                    WorkRefusal::NotReady,
                    "this endpoint has journaled no revision of this handshake",
                )
            })
    }

    /// Journals one revision this endpoint built.
    ///
    /// The bytes committed are the encoding, because a revision this
    /// endpoint made has no earlier bytes to be faithful to.
    fn commit(
        &mut self,
        bundle: &WorkChannelSetupBundleV1,
    ) -> Result<&SetupState, SetupExchangeError> {
        Ok(self.store.commit(
            SetupRecord::Bundle {
                bundle: bundle.encode(),
            },
            &Secp256k1Verifier::new(),
        )?)
    }
}

// ── The service ───────────────────────────────────────────────────────

/// The generated `WorkSetup` handler over one endpoint's setup journal.
///
/// Cheap to clone and shared by every connection, because one bond has
/// one journal however many peers dial it. The lock serialises the
/// concurrent calls of one process; the journal's own exclusive lock is
/// what excludes a second process. It is never held across an await,
/// because deciding a revision — verifying signatures, one signature of
/// its own, and two synchronous journal appends — never awaits.
#[derive(Clone, Debug)]
pub struct SetupService(Arc<Mutex<SetupEndpoint>>);

impl SetupService {
    /// Wraps one setup endpoint as a dispatchable service.
    #[must_use]
    pub fn new(endpoint: SetupEndpoint) -> Self {
        Self(Arc::new(Mutex::new(endpoint)))
    }

    /// Answers one exchange, or says why not.
    ///
    /// Synchronous, which is why the lock above is a plain [`Mutex`]:
    /// nothing between taking it and dropping it can await.
    fn exchange(&self, request: &ExchangeSetupRequest) -> ExchangeSetupResponse {
        let outcome = match self.0.lock() {
            Ok(mut endpoint) => endpoint.advance(&request.bundle),
            // A handler panicked mid-commit while holding this. The
            // durable effect of that is not knowable here, so the
            // endpoint is not recovered and every later call says so.
            Err(_) => Err(Refusal::new(
                WorkRefusal::Unavailable,
                "the setup endpoint lock is poisoned",
            )),
        };
        ExchangeSetupResponse {
            outcome: Some(match outcome {
                Ok(bundle) => Outcome::Advanced(SetupAdvanced { bundle }),
                Err(refusal) => Outcome::Refused(WorkRefused {
                    code: refusal.code.code() as i32,
                    reason: refusal.reason,
                }),
            }),
        }
    }
}

impl WorkSetupHandler for SetupService {
    fn exchange_setup(
        &self,
        request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<crate::call::WithTrailer<ExchangeSetupResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(self.exchange(&request)))
    }
}

// ── The client half ───────────────────────────────────────────────────

/// Offers what this endpoint holds and journals what comes back.
///
/// One round trip of the handshake, over a live transport. Called with
/// nothing held it asks for the peer's proposal; called holding a
/// revision the peer has not answered yet it asks for the answer.
/// Called holding the last revision it is a no-op that costs a round
/// trip, because both journals recognise what they already hold.
///
/// What it advanced to is read off the endpoint, because that is where
/// the answer durably is: a revision this function returned and the
/// journal did not hold would be two accounts of the same handshake.
///
/// # Errors
///
/// [`SetupExchangeError::Transport`] when the call does not complete,
/// [`SetupExchangeError::Refused`] for a refusal,
/// [`SetupExchangeError::Malformed`] for a response this service does
/// not define, and whatever [`SetupEndpoint::import`] raises.
pub async fn exchange_setup<T>(
    transport: T,
    endpoint: &mut SetupEndpoint,
) -> Result<(), SetupExchangeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = ExchangeSetupRequest {
        bundle: endpoint
            .state()
            .bundle_bytes()
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
    };
    let response = WorkSetupClientImpl::new(transport)
        .exchange_setup(request)
        .await?;
    let bundle = match response.outcome {
        Some(Outcome::Advanced(advanced)) => advanced.bundle,
        Some(Outcome::Refused(refused)) => {
            return Err(SetupExchangeError::Refused {
                refusal: WorkRefusal::from_code(refused.code)
                    .ok_or(SetupExchangeError::Malformed("refusal code"))?,
                reason: refused.reason,
            });
        }
        None => return Err(SetupExchangeError::Malformed("outcome")),
    };
    endpoint.import(&bundle)?;
    Ok(())
}
