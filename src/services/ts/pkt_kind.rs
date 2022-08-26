/// Besides transporting events, the TS sub-protocol has handshake packets and an ACK mechanism
#[repr(u8)]
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(test, derive(strum_macros::EnumCount))]
pub enum TsPacketKind {
    /// First packet from client to server
    Connect,
    /// First reply from server to client
    ConnectionEstablished,
    /// Application data is carried with this packet kind
    /// Usually contains Event messages with a tx id (for ACKs) and other fields depending on the event's Protobuf schema.
    Event,
    /// CloudProto is normally carried over TLS, but it still has ACKs (seemingly to enforce backpressure).
    /// Too many event messages sent without waiting for ACKs will be dropped by the other side.
    Ack,
    /// This escape hatch is provided with no warranty including fitness for a particular purpose.
    /// Good luck!
    Other(u8),
}

impl From<TsPacketKind> for u8 {
    fn from(kind: TsPacketKind) -> Self {
        match kind {
            TsPacketKind::Connect => 1,
            TsPacketKind::ConnectionEstablished => 2,
            TsPacketKind::Event => 3,
            TsPacketKind::Ack => 4,
            TsPacketKind::Other(x) => x,
        }
    }
}

impl From<&TsPacketKind> for u8 {
    fn from(pkt: &TsPacketKind) -> Self {
        u8::from(*pkt)
    }
}

impl From<u8> for TsPacketKind {
    fn from(value: u8) -> Self {
        match value {
            x if x == Self::Connect => Self::Connect,
            x if x == Self::ConnectionEstablished => Self::ConnectionEstablished,
            x if x == Self::Event => Self::Event,
            x if x == Self::Ack => Self::Ack,
            x => Self::Other(x),
        }
    }
}

impl PartialEq<u8> for TsPacketKind {
    fn eq(&self, other: &u8) -> bool {
        u8::from(self) == *other
    }
}

impl PartialEq<TsPacketKind> for u8 {
    fn eq(&self, other: &TsPacketKind) -> bool {
        u8::from(other) == *self
    }
}

impl std::fmt::LowerHex for TsPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u8 = self.into();
        std::fmt::LowerHex::fmt(&val, f)
    }
}

impl std::fmt::UpperHex for TsPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u8 = self.into();
        std::fmt::UpperHex::fmt(&val, f)
    }
}

#[cfg(test)]
mod test {
    use super::TsPacketKind;
    use std::collections::HashSet;
    use strum::EnumCount;

    #[test]
    fn ts_kind_roundtrip() {
        let mut seen = HashSet::new();
        for v in 0..=u8::MAX {
            let m = TsPacketKind::from(v);
            seen.insert(std::mem::discriminant(&m));
            assert_eq!(u8::from(m), v);
        }
        // If this fails, you may have forgotten to update From<u8>
        assert_eq!(seen.len(), TsPacketKind::COUNT)
    }
}
