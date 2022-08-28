use strum_macros::{Display, EnumCount, FromRepr};

#[repr(u16)]
#[derive(Eq, PartialEq, Copy, Clone, Debug, Display, EnumCount, FromRepr)]
pub enum CloudProtoVersion {
    /// All packets that don't fall in other categories
    Normal,
    /// Used for the first packets sent
    Connect,
    /// I haven't seen other values used yet
    Other(u16),
}

impl From<u16> for CloudProtoVersion {
    fn from(value: u16) -> Self {
        match value {
            x if x == Self::Normal.into() => Self::Normal,
            x if x == Self::Connect.into() => Self::Connect,
            x => Self::Other(x),
        }
    }
}

impl From<CloudProtoVersion> for u16 {
    fn from(kind: CloudProtoVersion) -> Self {
        match kind {
            CloudProtoVersion::Normal => 1,
            CloudProtoVersion::Connect => 2,
            CloudProtoVersion::Other(x) => x,
        }
    }
}

impl From<&CloudProtoVersion> for u16 {
    fn from(v: &CloudProtoVersion) -> Self {
        u16::from(*v)
    }
}

impl std::fmt::LowerHex for CloudProtoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u16 = self.into();
        std::fmt::LowerHex::fmt(&val, f)
    }
}

impl std::fmt::UpperHex for CloudProtoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: u16 = self.into();
        std::fmt::UpperHex::fmt(&val, f)
    }
}

#[cfg(test)]
mod test {
    use crate::framing::CloudProtoVersion;
    use std::collections::HashSet;
    use strum::EnumCount;

    #[test]
    fn cloud_proto_magic_roundtrip() {
        let mut seen = HashSet::new();
        for v in 0..=u16::MAX {
            let m = CloudProtoVersion::from(v);
            seen.insert(std::mem::discriminant(&m));
            assert_eq!(u16::from(m), v);
        }
        // If this fails, you may have forgotten to update From<u16>
        assert_eq!(seen.len(), CloudProtoVersion::COUNT)
    }
}
