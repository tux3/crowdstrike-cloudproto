use crate::services::DEFAULT_CID_HEX;

mod pkt_kind;

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
            cid: hex::decode(DEFAULT_CID_HEX).unwrap().try_into().unwrap(),
            aid: [0; 16], // LFO doesn't mind all zeroes
            compression: 0,
            remote_path,
            offset: 0,
        }
    }

    pub fn new_custom(cid: [u8; 16], aid: [u8; 16], remote_path: String) -> Self {
        Self {
            cid,
            aid,
            compression: 0, // Only 0 supported for now
            remote_path,
            offset: 0, // Only 0 supported for now
        }
    }
}
