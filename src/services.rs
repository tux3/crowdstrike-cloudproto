pub mod lfo;
pub mod ts;

use strum_macros::{Display, EnumCount, FromRepr};

/// This CID is **NOT** structurally valid, it would not be accepted by the sensor.
/// It is also possible to use a structurally valid CID that belongs to no one, but all zeros are accepted by LFO.
pub const DEFAULT_CID_HEX: &str = "00000000000000000000000000000000";
/// The AID is a value assigned to clients by TS on connection. It is zero for new agents.
pub const DEFAULT_AID_HEX: &str = "00000000000000000000000000000000";
/// Arbitrary machine-specific value generated on an isolated VM (from /proc/sys/kernel/random/boot_id)
pub const DEFAULT_BOOTID_HEX: &str = "6c959680d4945d45924301a720debc88";
/// Arbitrary machine-specific value generated on an isolated VM
pub const DEFAULT_UNK0_HEX: &str = "54645dacc392cb43b4803094141e0087";

#[repr(u8)]
#[derive(Eq, PartialEq, Debug, Copy, Clone, Display, EnumCount, FromRepr)]
pub enum CloudProtoMagic {
    TS,
    LFO,
    Other(u8),
}

impl From<u8> for CloudProtoMagic {
    fn from(value: u8) -> Self {
        match value {
            x if x == Self::TS => Self::TS,
            x if x == Self::LFO => Self::LFO,
            x => Self::Other(x),
        }
    }
}

impl From<CloudProtoMagic> for u8 {
    fn from(kind: CloudProtoMagic) -> Self {
        match kind {
            CloudProtoMagic::TS => 0x8F,
            CloudProtoMagic::LFO => 0x9F,
            CloudProtoMagic::Other(x) => x,
        }
    }
}

impl From<&CloudProtoMagic> for u8 {
    fn from(v: &CloudProtoMagic) -> Self {
        u8::from(*v)
    }
}

impl PartialEq<u8> for CloudProtoMagic {
    fn eq(&self, other: &u8) -> bool {
        u8::from(self) == *other
    }
}

impl PartialEq<CloudProtoMagic> for u8 {
    fn eq(&self, other: &CloudProtoMagic) -> bool {
        u8::from(other) == *self
    }
}

impl std::fmt::LowerHex for CloudProtoMagic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u8 = self.into();
        std::fmt::LowerHex::fmt(&val, f)
    }
}

impl std::fmt::UpperHex for CloudProtoMagic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u8 = self.into();
        std::fmt::UpperHex::fmt(&val, f)
    }
}

#[cfg(test)]
mod test {
    use super::CloudProtoMagic;
    use std::collections::HashSet;
    use strum::EnumCount;

    #[test]
    fn cloud_proto_magic_roundtrip() {
        let mut seen = HashSet::new();
        for v in 0..=u8::MAX {
            let m = CloudProtoMagic::from(v);
            seen.insert(std::mem::discriminant(&m));
            assert_eq!(u8::from(m), v);
        }
        // If this fails, you may have forgotten to update From<u8>
        assert_eq!(seen.len(), CloudProtoMagic::COUNT)
    }
}
