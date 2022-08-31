//! High-level support for the LFO file server

mod client;
mod file_header;
mod pkt_kind;
mod request;
mod response;

use bytes::Bytes;
pub use client::LfoClient;
pub use file_header::{CompressionFormats, LfoFileHeader};
pub use request::LfoRequest;
pub use response::LfoResponse;

use crate::framing::CloudProtoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LfoError {
    #[error("Requested file not found")]
    NotFound,
    #[error("Invalid LFO request")]
    InvalidRequest,
    #[error("{0}")]
    ServerError(String),
    #[error("Received LFO reply packet with kind {0}, but expected ReplyOk or ReplyFail")]
    BadReplyKind(u8),
    #[error("Failed to parse LFO reply: {reason}")]
    ReplyParseError { reason: String, raw_payload: Bytes },
    #[error("LFO data has final size {actual}, but expected {expected}")]
    InvalidFinalSize { expected: usize, actual: usize },
    #[error("LFO data has an invalid hash, it may be corrupt")]
    InvalidHash {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error(transparent)]
    CloudProto(#[from] CloudProtoError),
}

impl From<std::io::Error> for LfoError {
    fn from(e: std::io::Error) -> Self {
        Self::CloudProto(CloudProtoError::Io { source: e })
    }
}

#[cfg(test)]
mod test {
    // We can reuse this test vector in a couple tests
    pub(crate) const TEST_REPLY_DATA: &str = "00000000000000d4a330869acb341ad81b4b64f92ed7b85e0a361ab0449017a9f7a5f09276a436550000aaaaaaaa01002200000003000000000002000000c800\
                                              0000ac00000003000800010000000c00000003000000020000001c000000280000000000000038000000940000007800790058ff61006e000000416263644566\
                                              4768696a6b6c4d000000002f1100005c110001470e00014715000158160001470e00015c030001450400007cffff002f0500005c050005000800014d0600012e\
                                              070001410c00014d0d0003000100007cffff002f0800005c08000500110001410f0001451000a00000001c0000000c00000001000000bc000000000000007fc1\
                                              f36f";
}
