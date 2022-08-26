use crate::framing::{CloudProtoError, CloudProtoVersion};
use crate::services::CloudProtoMagic;
use byteorder::{ReadBytesExt, BE};
use std::io::Cursor;

pub(crate) const COMMON_HDR_LEN: usize = 8;

/// The common framing packet structure of the protocol
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct CloudProtoPacket {
    /// One magic value corresponds to one backend service
    pub magic: CloudProtoMagic,
    /// Each value can have a different interpretation for each backend service
    /// There is no common definition of packet kind at the framing level
    pub kind: u8,
    /// Used
    pub version: CloudProtoVersion,
    pub payload: Vec<u8>,
}

impl CloudProtoPacket {
    pub(crate) fn from_buf(buf: &[u8]) -> Result<Self, CloudProtoError> {
        let mut reader = Cursor::new(buf);
        let magic = reader.read_u8()?.into();
        let kind = reader.read_u8()?;
        let version = reader.read_u16::<BE>()?.into();
        let pkt_size = reader.read_u32::<BE>()? as usize - COMMON_HDR_LEN;
        let remaining_size = buf.len() - reader.position() as usize;
        if remaining_size != pkt_size {
            return Err(CloudProtoError::BadSize(remaining_size, pkt_size));
        }
        let payload = buf[reader.position() as usize..].to_vec();
        Ok(Self {
            magic,
            kind,
            version,
            payload,
        })
    }

    pub(crate) fn to_buf(&self) -> Vec<u8> {
        use byteorder::WriteBytesExt;
        use std::io::Write;

        let mut buf = Vec::new();
        let mut writer = Cursor::new(&mut buf);
        writer.write_u8(self.magic.into()).unwrap();
        writer.write_u8(self.kind).unwrap();
        writer.write_u16::<BE>(self.version.into()).unwrap();
        writer
            .write_u32::<BE>((self.payload.len() + COMMON_HDR_LEN) as u32)
            .unwrap();
        writer.write_all(&self.payload).unwrap();
        writer.flush().unwrap();
        buf
    }
}

#[cfg(test)]
mod test {
    use crate::framing::packet::CloudProtoPacket;
    use crate::framing::CloudProtoVersion;
    use crate::services::CloudProtoMagic;
    use anyhow::Result;

    #[test_log::test]
    fn to_from_buf_serialization() -> Result<()> {
        let pkt = CloudProtoPacket {
            magic: CloudProtoMagic::Other(0xFF),
            kind: 0x73,
            version: CloudProtoVersion::Other(0x10E9),
            payload: b"Hello world".to_vec(),
        };
        let pkt2 = CloudProtoPacket::from_buf(&pkt.to_buf())?;
        assert_eq!(pkt, pkt2);

        Ok(())
    }
}
