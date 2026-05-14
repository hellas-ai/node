//! Wire status code — mirrors gRPC's canonical 17 codes.
//!
//! Translation to/from `tonic::Status` (if ever needed during a future
//! interop phase) is a single match.

use smol_str::SmolStr;

use crate::metadata::Metadata;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum WireCode {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl WireCode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Unknown),
            3 => Some(Self::InvalidArgument),
            4 => Some(Self::DeadlineExceeded),
            5 => Some(Self::NotFound),
            6 => Some(Self::AlreadyExists),
            7 => Some(Self::PermissionDenied),
            8 => Some(Self::ResourceExhausted),
            9 => Some(Self::FailedPrecondition),
            10 => Some(Self::Aborted),
            11 => Some(Self::OutOfRange),
            12 => Some(Self::Unimplemented),
            13 => Some(Self::Internal),
            14 => Some(Self::Unavailable),
            15 => Some(Self::DataLoss),
            16 => Some(Self::Unauthenticated),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WireStatus {
    pub code: WireCode,
    pub message: SmolStr,
    pub details: bytes::Bytes,
    pub metadata: Metadata,
}

impl WireStatus {
    pub fn ok() -> Self {
        Self {
            code: WireCode::Ok,
            message: SmolStr::new_static(""),
            details: bytes::Bytes::new(),
            metadata: Metadata::default(),
        }
    }

    pub fn new(code: WireCode, message: impl Into<SmolStr>) -> Self {
        Self {
            code,
            message: message.into(),
            details: bytes::Bytes::new(),
            metadata: Metadata::default(),
        }
    }

    pub fn unimplemented(message: impl Into<SmolStr>) -> Self {
        Self::new(WireCode::Unimplemented, message)
    }

    pub fn internal(message: impl Into<SmolStr>) -> Self {
        Self::new(WireCode::Internal, message)
    }

    pub fn cancelled(message: impl Into<SmolStr>) -> Self {
        Self::new(WireCode::Cancelled, message)
    }

    pub fn deadline_exceeded() -> Self {
        Self::new(WireCode::DeadlineExceeded, "deadline exceeded")
    }
}

impl std::fmt::Display for WireStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for WireStatus {}
