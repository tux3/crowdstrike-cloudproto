//! This module provides an async [`CloudProtoSocket`](socket::CloudProtoSocket) Stream + Sink that handles [`CloudProtoPacket`](packet::CloudProtoPacket)s.
//!
//! CLOUDPROTO is a packet-based big endian binary protocol that transports events or other payloads.
//! The framing layer handles the common outer header/framing,
//! but ignores the inner service-specific payload format and interpretation of packet kinds.

mod hdr_version;
mod packet;
mod socket;

pub use hdr_version::CloudProtoVersion;
pub use packet::CloudProtoPacket;
pub use socket::{CloudProtoSocket, DEFAULT_MAX_FRAME_LENGTH};

use crate::services::CloudProtoMagic;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CloudProtoError {
    #[error("Bad CloudProto magic {0:#x}, expected {1:#x}")]
    BadMagic(CloudProtoMagic, CloudProtoMagic),
    #[error("Bad CloudProto header version {0:#x}, expected {1:#x}")]
    BadVersion(CloudProtoVersion, CloudProtoVersion),
    #[error("Bad CloudProto payload size {0:#x}, frame header announced {1:#x}")]
    BadFrameSize(usize, usize),
    #[error("Received payload size too short, got {0:#x} but wanted at least {1:#x}")]
    PayloadTooShort(usize, usize),
    #[error("Received payload with invalid size, got {0:#x} but expected {1:#x}")]
    PayloadInvalidSize(usize, usize),
    #[error("Received packet kind {0} while connecting, but expected {1}")]
    WrongConnectionPacketKind(u8, u8),
    #[error("{0}")]
    ClosedByPeer(String),
    #[error("CloudProto IO error")]
    Io {
        #[from]
        source: std::io::Error,
    },
}
