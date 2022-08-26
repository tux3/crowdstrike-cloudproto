mod pkt_kind;
pub use pkt_kind::TsPacketKind;

use crate::services::{DEFAULT_BOOTID_HEX, DEFAULT_UNK0_HEX};

/// Connection information required to open a session with the TS server
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct TsConnectInfo {
    // The CID assigned to a Crowdstrike customer (same as the CCID without the last -N number)
    // These are not random, there's a sort of checksum that must pass for a CID to be valid.
    // For TS the CID needs to be not only valid, but belong to an active customer
    pub(crate) cid: [u8; 16],
    // Unknown, but has never changed and the AID returned by TS depends on it (can also be 0)
    pub(crate) unk0: [u8; 16],
    // Agent ID. Saved in "falconstore". New values can be assigned by the TS server on connection
    pub(crate) aid: [u8; 16],
    // Per-machine value (the stable /proc/sys/kernel/random/boot_id, or a timestamp if unavailable)
    pub(crate) bootid: [u8; 16],
    // The "PT" value from "falconstore". Can be left as zeroes.
    pub(crate) pt: [u8; 8],
}

impl TsConnectInfo {
    /// Connect using the provided Crowdstrike customer ID
    /// The CID must belong to an active customer.
    /// Unlike for the LSO server and falcon-sensor it's not enough to use a structurally valid but inactive CID.
    /// Uses hardcoded default values for the other non-critical fields.
    pub fn new_simple(cid: [u8; 16]) -> Self {
        Self {
            cid,
            unk0: hex::decode(DEFAULT_UNK0_HEX).unwrap().try_into().unwrap(),
            aid: [0; 16],
            bootid: hex::decode(DEFAULT_BOOTID_HEX).unwrap().try_into().unwrap(),
            pt: [0; 8],
        }
    }

    pub fn new_custom(
        cid: [u8; 16],
        unk0: [u8; 16],
        aid: [u8; 16],
        bootid: [u8; 16],
        pt: [u8; 8],
    ) -> Self {
        Self {
            cid,
            unk0,
            aid,
            bootid,
            pt,
        }
    }
}
