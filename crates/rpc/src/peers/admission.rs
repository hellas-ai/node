use std::fmt;

use super::{PeerId, ServiceKey};

/// Transport-independent RPC identity used for accounting and admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestKind {
    pub service: &'static str,
    pub method: &'static str,
}

impl RequestKind {
    pub const fn new(service: &'static str, method: &'static str) -> Self {
        Self { service, method }
    }

    pub const fn for_service<S: ServiceKey>(method: &'static str) -> Self {
        Self {
            service: S::NAME,
            method,
        }
    }
}

/// Admission token returned before a request starts.
///
/// The caller must pass this value to `PeerRegistry::release` when the request
/// completes so in-flight counters and latency stats stay accurate.
///
/// This low-level permit is intentionally explicit because it has no registry
/// owner, clock, or interior mutability. Higher-level managers should wrap it in
/// an RAII guard: `Drop` records [`Outcome::Cancelled`], while successful or
/// failed RPC completion consumes the guard and records the final [`Outcome`].
#[must_use = "permits must be released through PeerRegistry::release"]
#[derive(Debug)]
pub struct Permit {
    peer: PeerId,
    kind: RequestKind,
    started_at_ms: u64,
    cost: f32,
}

impl Permit {
    pub(super) const fn new(
        peer: PeerId,
        kind: RequestKind,
        started_at_ms: u64,
        cost: f32,
    ) -> Self {
        Self {
            peer,
            kind,
            started_at_ms,
            cost,
        }
    }

    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    pub const fn kind(&self) -> RequestKind {
        self.kind
    }

    pub const fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    pub const fn cost(&self) -> f32 {
        self.cost
    }
}

/// Result reported when a previously admitted request completes.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Ok { rtt_ms: f64 },
    Err { rtt_ms: Option<f64>, error: String },
    Cancelled,
}

impl Outcome {
    pub const fn ok(rtt_ms: f64) -> Self {
        Self::Ok { rtt_ms }
    }
}

/// Why a request was denied before any I/O should be attempted.
#[derive(Clone, Debug, PartialEq)]
pub enum AcquireDenied {
    PeerLimit {
        peer: PeerId,
        max_peers: usize,
    },
    InFlightPeer {
        peer: PeerId,
        limit: usize,
    },
    InFlightTotal {
        limit: usize,
    },
    RateLimited {
        peer: PeerId,
        retry_after_ms: Option<u64>,
    },
}

impl fmt::Display for AcquireDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerLimit { peer, max_peers } => {
                write!(
                    f,
                    "peer registry is full while admitting {peer} (max {max_peers})"
                )
            }
            Self::InFlightPeer { peer, limit } => {
                write!(f, "peer {peer} has reached its in-flight limit ({limit})")
            }
            Self::InFlightTotal { limit } => {
                write!(
                    f,
                    "registry has reached its total in-flight limit ({limit})"
                )
            }
            Self::RateLimited {
                peer,
                retry_after_ms: Some(ms),
            } => {
                write!(f, "peer {peer} is rate limited, retry after {ms} ms")
            }
            Self::RateLimited {
                peer,
                retry_after_ms: None,
            } => {
                write!(f, "peer {peer} is rate limited")
            }
        }
    }
}

impl std::error::Error for AcquireDenied {}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct TokenBucket {
    tokens: f64,
    last_refill_ms: u64,
}

impl TokenBucket {
    pub(super) fn new(now_ms: u64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill_ms: now_ms,
        }
    }

    pub(super) fn try_take(
        &mut self,
        now_ms: u64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f32,
    ) -> Result<(), Option<u64>> {
        let cost = f64::from(cost.max(0.0));
        self.refill(now_ms, capacity, refill_per_sec);

        if cost <= self.tokens {
            self.tokens -= cost;
            return Ok(());
        }

        let missing = cost - self.tokens;
        let retry_after_ms = if refill_per_sec > 0.0 {
            Some(((missing / refill_per_sec) * 1000.0).ceil() as u64)
        } else {
            None
        };
        Err(retry_after_ms)
    }

    fn refill(&mut self, now_ms: u64, capacity: f64, refill_per_sec: f64) {
        if now_ms <= self.last_refill_ms {
            return;
        }

        if refill_per_sec > 0.0 {
            let elapsed_ms = now_ms - self.last_refill_ms;
            self.tokens =
                (self.tokens + (elapsed_ms as f64 / 1000.0) * refill_per_sec).min(capacity);
        }
        self.last_refill_ms = now_ms;
    }
}
