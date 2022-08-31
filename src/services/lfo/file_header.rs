use byteorder::{ReadBytesExt, BE};
use std::io::{Cursor, Read};
use tracing::trace;

/// The size of the header in an LFO ReplyOk, which is *not* the size of an LFO file header on disk
pub(crate) const LFO_RESP_HDR_LEN: usize = 0x2A;
pub(crate) const CRC_LEN: usize = 4;

#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CompressionFormats {
    /// Transmit files uncompressed
    None = 0,
    /// Transmit XZ compressed files (LZMA algorithm)
    Xz = 1,
}

/// Reproduces the internal format of the LFO file headers, as used by the official client
/// If you just care about downloading a file, you probably don't need to look at this struct.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct LfoFileHeader {
    /// Constant value ("RHDL")
    pub magic: u32,
    /// Unclear, I have only seen the constant value 1 passed around
    pub unk_cst1: u16,
    /// See [`CompressionFormats`](CompressionFormats) for known values
    pub comp_format: u16,
    /// The size of the requested file data, after any decompression
    pub payload_size: u32,
    /// Sha256 hash of the final data, without LFO header and after any decompression
    pub data_hash: [u8; 32],
    // 0x2C: Other fields again
    /// In the official client, this field gets updated as it receives more data.
    /// You should ignore this field.
    pub cur_payload_size: u32,
    /// In the official client, this starts at 1, goes up to 5 as we continue downloading.
    /// Ignore this field.
    pub cur_state: u16,
    /// This field is physically present in LFO headers, but its purpose has not been documented.
    pub unk: u16,
}

impl TryFrom<&[u8]> for LfoFileHeader {
    type Error = String;

    fn try_from(lfo_payload: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: These function assumes no chunked/range downloads (i.e. a single chunk)
        // Otherwise it would need to take the previous LfoFileHeader and update it
        // In practice even the 700+MiB kernel module packages fit in a single blob
        // of only a few MiBs, since they're always sent and stored as XZ compressed archives

        if lfo_payload.len() < LFO_RESP_HDR_LEN + CRC_LEN {
            return Err("LFO OK header too small".into());
        }
        let header = &lfo_payload[..LFO_RESP_HDR_LEN];
        let payload_data = &lfo_payload[LFO_RESP_HDR_LEN..]; // Includes trailing CRC!
        let mut header_reader = Cursor::new(&header);
        let chunk_start_off = header_reader.read_u32::<BE>().unwrap();
        let chunk_end_off = header_reader.read_u32::<BE>().unwrap();
        let mut pkt_unk_buf = [0; 32];
        header_reader.read_exact(&mut pkt_unk_buf).unwrap();
        let comp_format = header_reader.read_u16::<BE>().unwrap();
        trace!("Received LFO header data: {}", hex::encode(header));

        if chunk_start_off > chunk_end_off {
            return Err(format!(
                "LFO response start offset {:#x} is past end offset {:#x}",
                chunk_start_off, chunk_end_off
            ));
        }

        let len_without_crc = payload_data.len() - CRC_LEN;
        if chunk_start_off != 0 {
            return Err("Unexpected non-0 offset in LFO response".into());
        }
        let chunk_size = chunk_end_off - chunk_start_off;
        if comp_format == 0 && chunk_size != len_without_crc as u32 {
            return Err(format!(
                "Expected {:#x} bytes LFO file data, but uncompressed payload is {:#x} bytes",
                chunk_size, len_without_crc
            ));
        }

        let expected_crc = u32::from_be_bytes(payload_data[len_without_crc..].try_into().unwrap());
        let crc = crc32fast::hash(&payload_data[..len_without_crc]);
        if crc != expected_crc {
            return Err(format!(
                "Expected CRC 0x{:X}, but computed 0x{:X}",
                expected_crc, crc
            ));
        }

        Ok(Self {
            magic: 0x4C444852, // "RHDL"
            unk_cst1: 1,
            comp_format,
            payload_size: chunk_end_off,
            data_hash: pkt_unk_buf,
            cur_payload_size: len_without_crc as u32,
            cur_state: 5,
            unk: 0,
        })
    }
}
