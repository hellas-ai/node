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
/// Ordered most-to-least authoritative: `Authenticated > Local > Trusted >
/// Untrusted`. Callers filter by minimum level with `entry.auth_level >=
/// AuthLevel::Authenticated`. The variant order below is load-bearing —
/// `PartialOrd` and `Ord` are derived from it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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
