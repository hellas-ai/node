/// What the transport proves about bytes received from a peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportSecurity {
    /// The transport cryptographically binds the channel to the peer identity.
    Authenticated,
    /// Local OS credentials or ACLs identify the process on the other end.
    LocalCredential,
    /// The channel is encrypted, but identity binding is application-level.
    ChannelEncrypted,
    /// The channel makes no useful identity or confidentiality guarantee.
    #[default]
    Untrusted,
}

impl TransportSecurity {
    pub const fn strength(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::ChannelEncrypted => 1,
            Self::LocalCredential => 2,
            Self::Authenticated => 3,
        }
    }

    pub const fn strongest(self, other: Self) -> Self {
        if self.strength() >= other.strength() {
            self
        } else {
            other
        }
    }
}

/// Policy-facing authentication view derived from transport facts and trust.
///
/// Conceptually ordered most-to-least authoritative: `Authenticated > Local >
/// Trusted > Untrusted`. The ordering is exposed only through explicit
/// `allows_*_policy` and `allows_at_least` predicates — no `Ord`/`PartialOrd`
/// is derived. Variant declaration order is therefore *not* load-bearing;
/// reordering variants will not silently flip filter semantics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthLevel {
    #[default]
    Untrusted,
    Trusted,
    Local,
    Authenticated,
}

impl AuthLevel {
    pub const fn from_transport_and_trust(
        security: TransportSecurity,
        manually_trusted: bool,
    ) -> Self {
        match security {
            TransportSecurity::Authenticated => Self::Authenticated,
            TransportSecurity::LocalCredential => Self::Local,
            TransportSecurity::ChannelEncrypted | TransportSecurity::Untrusted => {
                if manually_trusted {
                    Self::Trusted
                } else {
                    Self::Untrusted
                }
            }
        }
    }

    /// Numeric authority rank used internally by the policy predicates.
    /// Lives in one place so adding a new variant only requires updating
    /// this match — everywhere else uses `allows_at_least` and friends.
    const fn rank(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::Trusted => 1,
            Self::Local => 2,
            Self::Authenticated => 3,
        }
    }

    /// True when `self`'s authority is at least as strong as `threshold`'s.
    /// Use this in place of `auth_level >= threshold` — it documents intent
    /// at the call site and keeps the ordering inside the type.
    pub const fn allows_at_least(self, threshold: Self) -> bool {
        self.rank() >= threshold.rank()
    }

    pub const fn allows_authenticated_policy(self) -> bool {
        matches!(self, Self::Authenticated)
    }

    pub const fn allows_local_policy(self) -> bool {
        matches!(self, Self::Authenticated | Self::Local)
    }

    pub const fn allows_trusted_policy(self) -> bool {
        matches!(self, Self::Authenticated | Self::Local | Self::Trusted)
    }
}
