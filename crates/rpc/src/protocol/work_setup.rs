//! Which channel this endpoint will work over, and whether it may.
//!
//! # What a configured channel is
//!
//! [`WorkChannelDescriptor`] is everything an endpoint was told about
//! one paid channel: the network, both edge ids, the complete tag-2
//! payment terms — which embed the complete tag-4 bond — the private
//! policy body and its salt, the execution policy, and the two live
//! measurements the omission contest's economics depend on. It is
//! configuration, and none of it is evidence.
//!
//! [`WorkChannelDescriptor::check_ready`] is what turns it into
//! evidence, by comparing it against one finalized read the caller
//! supplies. What it establishes is that at that read: both edges are
//! live, both hash to the configured terms, both name the parties those
//! terms fix, the bond is leased to *this* payment edge, no contest is
//! open, the funded edge still clears the omission inequality, and the
//! height is inside the admission horizon.
//!
//! That the read is coherent — one block, one state root, one database
//! snapshot — is the caller's, not this module's. See
//! [`ObservedChannel`].
//!
//! # Why the terms are hashed locally
//!
//! A finalized edge carries a terms *hash*, not a terms body. Nothing
//! read off the chain says what shape the terms have, who the parties
//! are, or what the bond covers. So the descriptor's own bodies are
//! hashed here and compared with the edge's commitment; the shape is
//! never inferred from the lookup. That is also why the payment terms
//! are carried whole rather than as a hash: the bond edge, the parties,
//! the admission horizon, and the policy commitment are all read out of
//! them, and a hash answers none of those questions.
//!
//! # What readiness does not claim
//!
//! Not that the objects were authenticated. In this milestone's trusted
//! mode the values come from a chain process inside the endpoint's trust
//! boundary and carry no membership proof; readiness is a statement
//! about what was reported, and the report's provenance is the
//! operator's.
//!
//! Not that a correctness game is available. This profile has no
//! challenge path, so the section-7 provider-deterrence inequality is
//! not checked and is not claimed. What *is* checked is the omission
//! contest's economics, because that contest is implemented
//! ([`check_omission_economics`]).
//!
//! Not that a job may be signed. That is a per-signature question with
//! its own deadlines, and it is [`ReadyChannel::check_signable`].

use hellas_kernel::{
    BlockHeight, Edge, EdgeId, EdgeValues, LeaseSlots, NetworkId, PendingSlot, Terms, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms, work_payment_settlement,
};

use crate::protocol::work::{
    PaidChannel, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidWorkError, check_execution_policy,
};

/// Denominator of the omission-contest probability `q`.
///
/// `q` is a measured availability, and a measured availability is a
/// ratio. Fixing the denominator here rather than carrying a pair means
/// the two sides of the inequality below cannot be computed against two
/// different scales.
pub const OMISSION_PROBABILITY_SCALE: u64 = 1_000_000;

/// Why a configured channel is not one this endpoint may work over.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorkSetupError {
    /// A record, policy, or price rule of the private protocol failed.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// An object the channel is made of was not present at the
    /// finalized block that was read.
    #[error("{object} is not live at the finalized state that was read")]
    NotLive {
        /// Which object was missing.
        object: &'static str,
    },
    /// A live object does not commit to the configured terms.
    #[error("{object} commits to other terms than the ones configured for this channel")]
    TermsMismatch {
        /// Which object disagreed.
        object: &'static str,
    },
    /// A live edge names other parties than its terms fix.
    #[error("{object} names other parties than its terms fix")]
    PartiesMismatch {
        /// Which object disagreed.
        object: &'static str,
    },
    /// The bond is not leased to this channel.
    #[error("the bond's lease is {found}, not this channel's lease")]
    Lease {
        /// What the lease slots held.
        found: LeaseState,
    },
    /// A contest is open, or the slot that would say so is unreadable.
    /// Either way the channel admits no new work.
    #[error("the payment edge's pending-close slot is {found}, so no new work is admitted")]
    PendingClose {
        /// What the pending slot held.
        found: PendingState,
    },
    /// The payment edge's reserve does not price both of its exits, so
    /// nothing it could settle is bounded.
    #[error("the payment edge's reserve does not price both of its close routes")]
    Unsettleable,
    /// An omission-economics gate failed.
    #[error("omission economics: {0}")]
    Omission(#[from] OmissionError),
    /// The finalized height is at or past the admission horizon.
    #[error("finalized height {height} is at or past the admission horizon {horizon}")]
    HorizonPassed {
        /// Finalized height the refusal is anchored at: the height the
        /// snapshot was read at, or the height a signature is being
        /// asked for at.
        height: u64,
        /// Height at and after which no work is admitted.
        horizon: u64,
    },
    /// The endpoint's finalized cursor has not reached the snapshot the
    /// decision is being made from.
    #[error("cursor is at height {cursor}, behind the snapshot at {height}")]
    CursorBehind {
        /// Height the endpoint has processed blocks through.
        cursor: u64,
        /// Height the snapshot was read at.
        height: u64,
    },
    /// The deadlines a job would carry do not fit the margins the
    /// policy measured.
    #[error(
        "height {height} plus dispatch {dispatch} and delivery {delivery} margins \
         exceeds the terminal deadline {terminal}"
    )]
    TerminalUnreachable {
        /// Finalized height the job would be signed at.
        height: u64,
        /// Blocks the policy allows to dispatch.
        dispatch: u64,
        /// Blocks the policy allows to deliver.
        delivery: u64,
        /// Deadline the authorization carries.
        terminal: u64,
    },
    /// The measured delivery margin no longer fits before the terminal
    /// deadline, so plaintext released now would not arrive in time.
    #[error(
        "height {height} plus the delivery margin {delivery} exceeds \
         the terminal deadline {terminal}"
    )]
    DeliveryUnreachable {
        /// Finalized height the release would begin at.
        height: u64,
        /// Blocks the policy allows to deliver.
        delivery: u64,
        /// Deadline the authorization carries.
        terminal: u64,
    },
    /// The gap between terminal and payment deadlines is under the
    /// oracle grace the policy measured.
    #[error(
        "terminal {terminal} to payment {payment} leaves {actual} blocks, \
         under the measured oracle grace {grace}"
    )]
    OracleGraceTooShort {
        /// Deadline a terminal result is owed by.
        terminal: u64,
        /// Deadline payment is owed by.
        payment: u64,
        /// Blocks the two deadlines actually leave.
        actual: u64,
        /// Blocks the policy measured as necessary.
        grace: u64,
    },
}

/// What the bond's two lease slots held, without the record itself.
///
/// The lease body is not carried into the error: what a refusal needs to
/// say is which of the three answers came back, and a `Faulty` lease has
/// no body to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// Both slots were empty.
    Absent,
    /// A readable lease, over another payment channel.
    AnotherChannel,
    /// The slots held something that is not a whole lease.
    Faulty,
}

impl core::fmt::Display for LeaseState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Absent => "absent",
            Self::AnotherChannel => "held by another payment channel",
            Self::Faulty => "not a readable lease",
        })
    }
}

/// What the payment edge's pending-close slot held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingState {
    /// A readable live contest.
    Live,
    /// Something that is not this edge's readable record.
    Faulty,
}

impl core::fmt::Display for PendingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Live => "a live contest",
            Self::Faulty => "not a readable record",
        })
    }
}

/// Why the omission contest's economics do not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OmissionError {
    /// The measured response probability is outside `1..=M`.
    #[error("measured response probability {q} is outside 1..={OMISSION_PROBABILITY_SCALE}")]
    ProbabilityOutOfRange {
        /// Probability numerator that was configured.
        q: u64,
    },
    /// The funded bond does not exceed the measured cost of responding.
    #[error("omission bond {bond} does not exceed the measured response cost cap {cap}")]
    BondBelowResponseCost {
        /// Bond the payment terms fund.
        bond: u64,
        /// Measured cost of answering one contest.
        cap: u64,
    },
    /// Omitting a response is not loss-making at this bond, probability,
    /// and capacity.
    #[error(
        "q*bond = {responded} does not exceed (M-q)*capacity = {omitted}, \
         so omission is not loss-making"
    )]
    OmissionNotLossMaking {
        /// `q * omission_bond`.
        responded: u128,
        /// `(M - q) * payment_capacity`.
        omitted: u128,
    },
}

/// What an operator configured for one paid channel, before anything
/// has been checked.
///
/// A plain record with public fields: this is the shape a CLI or a
/// config file fills in. It is also why [`WorkChannelDescriptor::open`]
/// takes one argument — nine positional arguments, four of them `u64`,
/// is a signature whose mistakes compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkChannelConfig {
    /// The network every signature on this channel is bound to.
    pub network: NetworkId,
    /// The tag-2 payment edge work is paid from.
    pub payment_edge: EdgeId,
    /// The complete payment terms, which embed the complete bond.
    pub payment_terms: WorkPaymentTerms,
    /// Salt of the private credit-policy commitment.
    pub policy_salt: [u8; 32],
    /// The credit policy those terms commit to.
    pub channel_policy: PaidChannelPolicyV1,
    /// The execution policy in force on this channel.
    pub execution_policy: PaidExecutionPolicyV1,
    /// The payment edge's value, reserve, and close fees as the
    /// operator expects them to be funded.
    pub expected_payment_values: EdgeValues,
    /// Measured probability, out of [`OMISSION_PROBABILITY_SCALE`], that
    /// the provider's watcher answers a contest in time.
    pub omission_response_probability: u64,
    /// Measured cost cap of answering one contest.
    pub omission_response_cost_cap: u64,
}

/// A configured channel whose static gates have passed.
///
/// Constructed only through [`Self::open`], which is where the policy
/// commitment is opened and those gates run. A descriptor in hand is
/// therefore a channel whose policy body matches its terms and whose
/// omission economics hold at the configured measurements — none of
/// which says anything yet about what is on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkChannelDescriptor {
    channel: PaidChannel,
    bond_edge: EdgeId,
    bond_terms_hash: TermsHash,
    execution_policy: PaidExecutionPolicyV1,
    omission_response_probability: u64,
    omission_response_cost_cap: u64,
}

impl WorkChannelDescriptor {
    /// Opens a configured channel: checks its policy commitment, its
    /// execution policy, and its omission economics.
    ///
    /// The bond edge and its terms hash are read out of the payment
    /// terms rather than configured separately, for the same reason
    /// [`PaidChannel::new`] reads them there: the payment body already
    /// embeds the complete bond, so a separately configured bond could
    /// only ever be the wrong one.
    ///
    /// The capacity the omission inequality is checked against here is
    /// the *configured* capacity, derived from the edge values the
    /// operator expects. It is checked again against the finalized edge
    /// in [`Self::check_ready`], because a configured expectation is not
    /// a funded edge.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::Record`] when the policy commitment or the
    /// execution policy is refused, [`WorkSetupError::Unsettleable`]
    /// when the expected edge values do not price both close routes, and
    /// [`WorkSetupError::Omission`] when the contest's economics do not
    /// hold.
    pub fn open(config: WorkChannelConfig) -> Result<Self, WorkSetupError> {
        let bond_edge = config.payment_terms.bond_edge;
        let bond_terms_hash = config.payment_terms.bond_terms_hash();
        let omission_bond = config.payment_terms.omission_bond;
        let channel = PaidChannel::new(
            config.network,
            config.payment_edge,
            config.payment_terms,
            &config.policy_salt,
            config.channel_policy,
        )?;
        check_execution_policy(&config.execution_policy)?;

        let settlement = work_payment_settlement(config.expected_payment_values, omission_bond)
            .ok_or(WorkSetupError::Unsettleable)?;
        check_omission_economics(
            config.omission_response_probability,
            omission_bond,
            config.omission_response_cost_cap,
            settlement.capacity(),
        )?;

        Ok(Self {
            channel,
            bond_edge,
            bond_terms_hash,
            execution_policy: config.execution_policy,
            omission_response_probability: config.omission_response_probability,
            omission_response_cost_cap: config.omission_response_cost_cap,
        })
    }

    /// Returns the channel these records are bound to.
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns the bond edge insuring this channel.
    pub const fn bond_edge(&self) -> EdgeId {
        self.bond_edge
    }

    /// Returns the execution policy in force on this channel.
    pub const fn execution_policy(&self) -> &PaidExecutionPolicyV1 {
        &self.execution_policy
    }

    /// Returns the height at and after which the channel admits no work.
    pub const fn admission_horizon(&self) -> BlockHeight {
        self.channel.payment_terms().admission_horizon()
    }

    /// Decides whether this configured channel is the channel on chain.
    ///
    /// Every check is against the one read it is handed, and every one
    /// of them can refuse: a live payment edge whose bond is gone is not
    /// a channel, a live pair under other terms is not this channel, and
    /// a live pair with an open contest is a channel that admits no new
    /// work even though both edges are perfectly healthy.
    ///
    /// Whether that read is *coherent* is not established here and
    /// cannot be: five fields assembled from five point queries satisfy
    /// [`ObservedChannel`] exactly as well as one database snapshot
    /// does, and the difference is the caller's to owe.
    ///
    /// # Errors
    ///
    /// One [`WorkSetupError`] naming the first fact that failed.
    pub fn check_ready(
        &self,
        observed: &ObservedChannel<'_>,
    ) -> Result<ReadyChannel, WorkSetupError> {
        let terms = self.channel.payment_terms();

        let bond = observed.bond.ok_or(WorkSetupError::NotLive {
            object: "the bond edge",
        })?;
        let payment = observed.payment.ok_or(WorkSetupError::NotLive {
            object: "the payment edge",
        })?;

        // The terms body is what says who the parties are and what the
        // bond covers, and the edge carries only a hash of it. Locally
        // hashing the configured body is the only thing that makes the
        // rest of these checks about this channel.
        if bond.terms() != self.bond_terms_hash {
            return Err(WorkSetupError::TermsMismatch {
                object: "the bond edge",
            });
        }
        if payment.terms() != self.channel.payment_terms_hash() {
            return Err(WorkSetupError::TermsMismatch {
                object: "the payment edge",
            });
        }
        // The kernel fixes both pairings at open, so a disagreement here
        // is a hash collision or a wrongly assembled snapshot rather
        // than a channel in an unexpected state. It is checked because a
        // wrongly assembled snapshot is the reachable one: these two
        // edges arrive as two `Option`s of the same type.
        if bond.parties() != terms.bond_terms.parties {
            return Err(WorkSetupError::PartiesMismatch {
                object: "the bond edge",
            });
        }
        if payment.parties() != terms.parties() {
            return Err(WorkSetupError::PartiesMismatch {
                object: "the payment edge",
            });
        }

        match observed.lease {
            LeaseSlots::Present(lease) if lease.payment_edge() == self.channel.payment_edge() => {}
            LeaseSlots::Present(_) => {
                return Err(WorkSetupError::Lease {
                    found: LeaseState::AnotherChannel,
                });
            }
            LeaseSlots::Absent => {
                return Err(WorkSetupError::Lease {
                    found: LeaseState::Absent,
                });
            }
            LeaseSlots::Faulty(_) => {
                return Err(WorkSetupError::Lease {
                    found: LeaseState::Faulty,
                });
            }
        }

        match observed.pending {
            PendingSlot::Absent => {}
            PendingSlot::Present(_) => {
                return Err(WorkSetupError::PendingClose {
                    found: PendingState::Live,
                });
            }
            PendingSlot::Faulty(_) => {
                return Err(WorkSetupError::PendingClose {
                    found: PendingState::Faulty,
                });
            }
        }

        // The capacity every later amount is bounded by, taken from the
        // edge that will pay rather than from the operator's
        // expectation. The economics are re-checked against it for the
        // same reason: a channel funded below what was configured has
        // different economics than the ones that were approved.
        let settlement = work_payment_settlement(payment.values(), terms.omission_bond)
            .ok_or(WorkSetupError::Unsettleable)?;
        check_omission_economics(
            self.omission_response_probability,
            terms.omission_bond,
            self.omission_response_cost_cap,
            settlement.capacity(),
        )?;

        let horizon = terms.admission_horizon().get();
        if observed.height >= horizon {
            return Err(WorkSetupError::HorizonPassed {
                height: observed.height,
                horizon,
            });
        }

        Ok(ReadyChannel {
            channel: self.channel.clone(),
            execution_policy: self.execution_policy,
            settlement,
            finalized_height: observed.height,
            admission_horizon: horizon,
        })
    }
}

/// One finalized read of a channel's four objects.
///
/// A struct rather than five arguments because two of the five are
/// `Option<&Edge>` and would otherwise be silently swappable. Every
/// field is named at the call site that builds it, so a bond passed as a
/// payment edge is a visible mistake rather than a subtle one.
///
/// Nothing here proves the five fields came from one block, and nothing
/// downstream can: whoever fills this in owes the coherence.
/// `hellas_chain::WorkChannelSnapshot` is what supplies it in this
/// milestone, by reading every object under one database snapshot at one
/// finalized block; five separate point queries would satisfy the type
/// and not the requirement.
#[derive(Clone, Copy, Debug)]
pub struct ObservedChannel<'a> {
    /// Finalized height every field below was read at.
    pub height: u64,
    /// The bond edge, or its absence.
    pub bond: Option<&'a Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<&'a Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// What the payment edge's pending-close slot held.
    pub pending: PendingSlot,
}

/// A channel this endpoint has established is live, leased, uncontested,
/// and inside its horizon at one finalized height.
///
/// It can only be built by [`WorkChannelDescriptor::check_ready`], so
/// holding one is holding that decision — and holding it *only at*
/// [`Self::finalized_height`]. Liveness, the lease, and the absence of a
/// contest are facts about that one block, and nothing on this type
/// refreshes them: a close opened one block later is invisible to every
/// method here, because the objects it would have to re-read are not
/// carried.
///
/// So the obligation is the holder's, in the same way [`ObservedChannel`]
/// owes coherence: run [`WorkChannelDescriptor::check_ready`] again
/// against a fresh snapshot before each signature, and sign against the
/// `ReadyChannel` that read produced. [`Self::check_signable`] is the
/// per-signature *arithmetic* — the horizon and the deadline margins,
/// against the height the endpoint has actually reached. It is not a
/// substitute for the refresh, and it does not claim to be one: no
/// arithmetic over a stale read can see a contest that opened after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyChannel {
    channel: PaidChannel,
    execution_policy: PaidExecutionPolicyV1,
    settlement: WorkPaymentSettlement,
    finalized_height: u64,
    admission_horizon: u64,
}

impl ReadyChannel {
    /// Returns the channel every private record is bound to.
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns what this edge can settle, at the funding it actually
    /// has.
    pub const fn settlement(&self) -> WorkPaymentSettlement {
        self.settlement
    }

    /// Returns the execution policy this readiness was decided under.
    ///
    /// The policy an endpoint checks a proposal against must be the one
    /// whose margins [`Self::check_signable`] measures against and whose
    /// digest the authorization names. Carrying it here is what stops
    /// those three from being three copies.
    pub const fn execution_policy(&self) -> &PaidExecutionPolicyV1 {
        &self.execution_policy
    }

    /// Returns the finalized height this readiness was decided at.
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Checks that a job with these deadlines may be signed now.
    ///
    /// Readiness was decided at a height; this is decided at a
    /// signature, which is a different moment and a different question.
    /// `cursor_height` is that moment: how far the endpoint has actually
    /// processed finalized blocks. An endpoint that has read a snapshot
    /// it has not caught up to has seen a state it cannot yet act on,
    /// because the blocks between are where a contest it must not sign
    /// over would appear.
    ///
    /// Every bound below is therefore anchored at `cursor_height` and
    /// not at [`Self::finalized_height`]. The readiness height is the
    /// past; the chain has moved since, and a horizon or a deadline
    /// measured from the past is measured from a moment the signature
    /// will not be made at. Anchored at the readiness height, the whole
    /// interval `[finalized_height + margins, cursor_height + margins)`
    /// passes — and that interval is exactly the deadlines already
    /// missed by the time the signature is made.
    ///
    /// The two margins are the policy's measured ones, so this refuses a
    /// deadline that is legal, ordered, and unreachable — which is the
    /// only kind of deadline an honest provider signs and then misses.
    ///
    /// The ordering of the four deadlines is not re-derived here:
    /// [`crate::protocol::work::check_authorization`] fixes
    /// `acceptance < terminal < payment < horizon` against the same
    /// terms, and a second spelling of that chain is a second chance to
    /// spell it differently.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::CursorBehind`] when the endpoint has not
    /// processed blocks through the height this was decided at,
    /// [`WorkSetupError::HorizonPassed`] when the channel admits no more
    /// work, [`WorkSetupError::TerminalUnreachable`] when the measured
    /// margins do not fit before the terminal deadline, and
    /// [`WorkSetupError::OracleGraceTooShort`] when the payment deadline
    /// leaves less than the measured oracle grace.
    pub fn check_signable(
        &self,
        cursor_height: u64,
        terminal_deadline: u64,
        payment_deadline: u64,
    ) -> Result<(), WorkSetupError> {
        self.check_caught_up(cursor_height)?;
        if cursor_height >= self.admission_horizon {
            return Err(WorkSetupError::HorizonPassed {
                height: cursor_height,
                horizon: self.admission_horizon,
            });
        }

        let policy = &self.execution_policy;
        let reachable = cursor_height
            .checked_add(policy.dispatch_margin_blocks)
            .and_then(|sum| sum.checked_add(policy.delivery_margin_blocks))
            .ok_or(PaidWorkError::Overflow {
                field: "dispatch and delivery margins",
            })?;
        if reachable > terminal_deadline {
            return Err(WorkSetupError::TerminalUnreachable {
                height: cursor_height,
                dispatch: policy.dispatch_margin_blocks,
                delivery: policy.delivery_margin_blocks,
                terminal: terminal_deadline,
            });
        }

        let grace =
            payment_deadline
                .checked_sub(terminal_deadline)
                .ok_or(PaidWorkError::Overflow {
                    field: "oracle grace interval",
                })?;
        if grace < policy.oracle_grace_blocks {
            return Err(WorkSetupError::OracleGraceTooShort {
                terminal: terminal_deadline,
                payment: payment_deadline,
                actual: grace,
                grace: policy.oracle_grace_blocks,
            });
        }
        Ok(())
    }

    /// Checks that this endpoint has processed finalized blocks through
    /// the height this readiness was decided at.
    ///
    /// Every decision taken against a `ReadyChannel` needs this and
    /// only this in common: a snapshot the endpoint has not caught up
    /// to is a state it cannot yet act on, because the blocks between
    /// are where the fact that would change the decision would appear.
    /// It is written once here and called by each of them.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::CursorBehind`] when the cursor is behind.
    pub const fn check_caught_up(&self, cursor_height: u64) -> Result<(), WorkSetupError> {
        if cursor_height < self.finalized_height {
            return Err(WorkSetupError::CursorBehind {
                cursor: cursor_height,
                height: self.finalized_height,
            });
        }
        Ok(())
    }

    /// Checks that plaintext released now can still reach the client
    /// before the deadline it was promised by.
    ///
    /// The dispatch margin is deliberately absent: by the time there is
    /// plaintext to release it has already been spent, and charging it
    /// again would refuse a delivery that is in fact on time. What
    /// remains is the transfer the policy measured for the largest
    /// legal result.
    ///
    /// The admission horizon is likewise absent, and does not need to be
    /// here: `check_authorization` fixes `terminal < payment < horizon`
    /// for every signed job, so a height inside the terminal deadline is
    /// inside the horizon.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::CursorBehind`] when the endpoint has not
    /// processed blocks through the height this was decided at,
    /// [`WorkSetupError::DeliveryUnreachable`] when the measured margin
    /// no longer fits, and [`WorkSetupError::Record`] when that
    /// arithmetic would overflow.
    pub fn check_releasable(
        &self,
        cursor_height: u64,
        terminal_deadline: u64,
    ) -> Result<(), WorkSetupError> {
        self.check_caught_up(cursor_height)?;
        let delivery = self.execution_policy.delivery_margin_blocks;
        let arrives = cursor_height
            .checked_add(delivery)
            .ok_or(PaidWorkError::Overflow {
                field: "delivery margin",
            })?;
        if arrives > terminal_deadline {
            return Err(WorkSetupError::DeliveryUnreachable {
                height: cursor_height,
                delivery,
                terminal: terminal_deadline,
            });
        }
        Ok(())
    }
}

/// Checks that understating a payment close costs the client more than
/// it stands to keep.
///
/// The thief the implemented contest admits is the *client*, and the
/// theft is an understatement: the client opens a close naming less than
/// it has already signed for, and if this provider's watcher is offline
/// for `omit_response_blocks` that understated start settles and the
/// client keeps the difference. The provider's omission is the
/// opportunity; it is not the profit, and a provider that stays offline
/// only loses. The kernel's rule is `WorkPaymentTerms::omission_bond` —
/// "amount the client forfeits to the provider when a close reveals the
/// client understated" — charged on a `Party::Maker` opener, and the
/// payment edge's maker is the client.
///
/// What deters it is that bond, and what makes the bond sufficient is an
/// inequality over three measured quantities. With `M` =
/// [`OMISSION_PROBABILITY_SCALE`]:
///
/// - `1 <= q <= M`, where `q/M` is the measured probability that this
///   provider's watcher answers a contest in time;
/// - `omission_bond > omission_response_cost_cap`, so answering pays the
///   provider more than answering costs it, and the response the whole
///   deterrence rests on is one the provider actually wants to make;
/// - `q * omission_bond > (M - q) * payment_capacity`, so the client's
///   expected forfeit exceeds its expected theft.
///
/// The products are `u128` because both factors are `u64` and their
/// product is not. The `q > M` half of the range check is load-bearing:
/// `M - q` below would underflow without it. The `q == 0` half is not —
/// `q = 0` makes the third inequality `0 > M * capacity`, which is false
/// for *every* capacity, zero included, because the comparison is
/// strict. It is kept for the answer it gives rather than the refusal:
/// `ProbabilityOutOfRange` names the configuration mistake, where
/// `OmissionNotLossMaking { responded: 0, .. }` would report an
/// arithmetic result that says nothing about what to change.
///
/// These are bilateral policy gates, not kernel facts. The kernel checks
/// that the bond is funded and that a proved understatement forfeits it.
/// Nothing on chain checks that a provider is actually online, and no
/// hash can make one respond.
///
/// # Errors
///
/// One [`OmissionError`] naming the inequality that failed.
pub fn check_omission_economics(
    q: u64,
    omission_bond: u64,
    omission_response_cost_cap: u64,
    payment_capacity: u64,
) -> Result<(), OmissionError> {
    if q == 0 || q > OMISSION_PROBABILITY_SCALE {
        return Err(OmissionError::ProbabilityOutOfRange { q });
    }
    if omission_bond <= omission_response_cost_cap {
        return Err(OmissionError::BondBelowResponseCost {
            bond: omission_bond,
            cap: omission_response_cost_cap,
        });
    }
    let responded = u128::from(q) * u128::from(omission_bond);
    let omitted = u128::from(OMISSION_PROBABILITY_SCALE - q) * u128::from(payment_capacity);
    if responded <= omitted {
        return Err(OmissionError::OmissionNotLossMaking { responded, omitted });
    }
    Ok(())
}

/// Returns the terms hash of one payment body, as the edge commits to
/// it.
///
/// One line, and it exists so no caller writes
/// `Terms::work_payment(..).hash()` for itself: the edge's commitment is
/// over the tagged `Terms` envelope, not over the body, and a caller
/// that hashed the body would compare a value no edge carries.
#[must_use]
pub fn payment_terms_hash(terms: WorkPaymentTerms) -> TermsHash {
    Terms::work_payment(terms).hash()
}
