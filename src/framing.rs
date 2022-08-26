//! This module provides an async [`CloudProtoSocket`](socket::CloudProtoSocket) Stream + Sink that handles [`CloudProtoPacket`](packet::CloudProtoPacket)s.
//!
//! CLOUDPROTO is a packet-based big endian binary protocol that transports events or other payloads.
//! The framing layer handles the common outer header/framing,
//! but ignores the inner service-specific payload format and interpretation of packet kinds.

mod hdr_version;
pub mod packet;
mod socket;

pub use hdr_version::CloudProtoVersion;
pub use socket::CloudProtoSocket;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CloudProtoError {
    #[error("Bad CloudProto magic {0:#x}, expected {1:#x}")]
    BadMagic(u8, u8),
    #[error("Bad CloudProto header version {0:#x}, expected {1:#x}")]
    BadVersion(u16, u16),
    #[error("Bad CloudProto payload size {0:#x}, header announced {1:#x}")]
    BadSize(usize, usize),
    #[error("Received packet kind {0} as connection reply, expected {1}")]
    WrongConnectionEstablishedKind(u8, u8),
    #[error("{0}")]
    ClosedByPeer(String),
    #[error("CloudProto IO error")]
    Io {
        #[from]
        source: std::io::Error,
    },
}
