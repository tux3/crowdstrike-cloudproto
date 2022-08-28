use strum_macros::{Display, EnumCount, FromRepr};

/// Besides transporting events, the protocol carries different kind of packets internally
#[repr(u8)]
#[derive(Eq, PartialEq, Copy, Clone, Debug, Display, EnumCount, FromRepr)]
pub enum LfoPacketKind {
    /// Sent by client to request file data
    GetFileRequest,
    /// Successful response to a request
    ReplyOk,
    /// May contain a friendly error message (at offset 0x8).
    /// If you send bad requests, you may get a ReplyFail with "internal error" (consider not doing that!)
    /// If the request is sufficiently bad, the server may also just close the socket without replying
    ReplyFail,
    /// Other values have not been observed yet
    Other(u8),
}

impl From<LfoPacketKind> for u8 {
    fn from(kind: LfoPacketKind) -> Self {
        match kind {
            LfoPacketKind::GetFileRequest => 1,
            LfoPacketKind::ReplyOk => 2,
            LfoPacketKind::ReplyFail => 3,
            LfoPacketKind::Other(x) => x,
        }
    }
}

impl From<&LfoPacketKind> for u8 {
    fn from(pkt: &LfoPacketKind) -> Self {
        u8::from(*pkt)
    }
}

impl From<u8> for LfoPacketKind {
    fn from(value: u8) -> Self {
        match value {
            x if x == Self::GetFileRequest => Self::GetFileRequest,
            x if x == Self::ReplyOk => Self::ReplyOk,
            x if x == Self::ReplyFail => Self::ReplyFail,
            x => Self::Other(x),
        }
    }
}

impl PartialEq<u8> for LfoPacketKind {
    fn eq(&self, other: &u8) -> bool {
        u8::from(self) == *other
    }
}

impl PartialEq<LfoPacketKind> for u8 {
    fn eq(&self, other: &LfoPacketKind) -> bool {
        u8::from(other) == *self
    }
}

impl std::fmt::LowerHex for LfoPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u8 = self.into();
        std::fmt::LowerHex::fmt(&val, f)
    }
}

impl std::fmt::UpperHex for LfoPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u8 = self.into();
        std::fmt::UpperHex::fmt(&val, f)
    }
}

#[cfg(test)]
mod test {
    use super::LfoPacketKind;
    use std::collections::HashSet;
    use strum::EnumCount;

    #[test]
    fn lfo_kind_roundtrip() {
        let mut seen = HashSet::new();
        for v in 0..=u8::MAX {
            let m = LfoPacketKind::from(v);
            seen.insert(std::mem::discriminant(&m));
            assert_eq!(u8::from(m), v);
        }
        // If this fails, you may have forgotten to update From<u8>
        assert_eq!(seen.len(), LfoPacketKind::COUNT)
    }
}
