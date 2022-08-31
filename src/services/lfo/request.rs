use crate::services::lfo::CompressionFormats;
use crate::services::{DEFAULT_AID_HEX, DEFAULT_CID_HEX};

/// Ask for a single file on a remote LFO server by path.
///
/// By default requests indicate support for XZ compression, but this is configurable.
/// Even if a request accepts compression, the server may decide to reply with an uncompressed
/// response if the requested file is itself an archive on disk.
///
/// Requests contain the CID (Customer ID) and AID (Agent ID) of the client, but the LFO server
/// will accept any value for these, so in practice no authentication is required.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct LfoRequest {
    // The CID assigned to a Crowdstrike customer (same as the CCID without the last -N number)
    // The LFO server doesn't really check if it belongs to anyone. Just try to pass a valid CID.
    pub(crate) cid: [u8; 16],
    // Agent ID. LFO isn't uptight like TS if the AID is not an active customer.
    // In fact, you can give it all zeroes. LFO is friendly like that.
    pub(crate) aid: [u8; 16],
    // The real client supports values 0 or 1. We only support 0.
    pub(crate) compression: u16,
    // The file to download
    pub(crate) remote_path: String,
    // This field is probably the offset for chunked downloads. Not supported or tested yet.
    // Large files can't be downloaded in one packet, so the client may get partial responses
    // The offset allows downloading the rest of those large files in multiple queries
    pub(crate) offset: u32,
}

impl LfoRequest {
    /// Create a request for `remote_path` with default values
    pub fn new_simple(remote_path: String) -> Self {
        Self {
            // LFO doesn't mind all zeroes
            cid: hex::decode(DEFAULT_CID_HEX).unwrap().try_into().unwrap(),
            aid: hex::decode(DEFAULT_AID_HEX).unwrap().try_into().unwrap(),
            compression: 0,
            remote_path,
            offset: 0,
        }
    }

    pub fn new_custom(
        cid: [u8; 16],
        aid: [u8; 16],
        compression: CompressionFormats,
        remote_path: String,
    ) -> Self {
        Self {
            cid,
            aid,
            compression: compression as u16,
            remote_path,
            // Only 0 if supported for now
            // The receive side WILL break right now if it sees a reply with non-zero offset
            offset: 0,
        }
    }

    pub(crate) fn to_payload(&self) -> Vec<u8> {
        let mut payload = vec![];
        payload.extend_from_slice(&self.cid); // CU "simple store" value
        payload.extend_from_slice(&self.aid); // AG "simple store" value
        payload.extend_from_slice(8u32.to_be_bytes().as_slice());
        payload.extend_from_slice(&self.offset.to_be_bytes());
        payload.extend_from_slice(&self.compression.to_be_bytes());
        payload.extend_from_slice(self.remote_path.as_bytes());
        payload
    }

    #[cfg(test)]
    pub(crate) fn try_from_payload(payload: &[u8]) -> Result<Self, super::LfoError> {
        use super::LfoError;
        use byteorder::{ReadBytesExt, BE};
        use std::io::Read;

        let mut cursor = std::io::Cursor::new(payload);
        let mut cid = [0u8; 16];
        cursor.read_exact(&mut cid)?;
        let mut aid = [0u8; 16];
        cursor.read_exact(&mut aid)?;
        _ = cursor.read_u32::<BE>()?;
        let offset = cursor.read_u32::<BE>()?;
        let compression = cursor.read_u16::<BE>()?;
        let remote_path = String::from_utf8(payload[cursor.position() as usize..].into())
            .map_err(|_| LfoError::InvalidRequest)?;
        Ok(Self {
            cid,
            aid,
            compression,
            remote_path,
            offset,
        })
    }
}
