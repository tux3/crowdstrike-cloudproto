use crate::framing::CloudProtoPacket;
use crate::services::lfo::file_header::{CRC_LEN, LFO_RESP_HDR_LEN};
use crate::services::lfo::pkt_kind::LfoPacketKind;
use crate::services::lfo::{CompressionFormats, LfoError, LfoFileHeader};
use bytes::Bytes;
use std::cmp;
use std::io::{Read, Write};
use tracing::trace;

#[cfg(feature = "lfo-compress-xz")]
use bytes::Buf;
#[cfg(feature = "lfo-compress-xz")]
use xz2::read::XzDecoder;

enum ResponseReadState {
    Direct {
        read_pos: usize,
    },
    #[cfg(feature = "lfo-compress-xz")]
    Compressed {
        stream: XzDecoder<bytes::buf::Reader<Bytes>>,
    },
}

/// The reply from the server corresponding to a single [`LfoRequest`](super::LfoRequest).
pub struct LfoResponse {
    raw_lfo_payload: Bytes,
    header: LfoFileHeader,
    // This could be the plain file data, or compressed
    lfo_data: Bytes,
    read_state: ResponseReadState,
    #[cfg(feature = "lfo-check-hash")]
    read_hasher: sha2::Sha256,
    #[cfg(not(feature = "lfo-check-hash"))]
    read_hasher: (),
}

impl LfoResponse {
    /// Extracts the data of the requested file from the response.
    /// May fail if the received data (after any decompression) has the wrong size or hash.
    /// This ignores the [`Read`](std::io::Read) cursor and always returns the entire data.
    pub fn data(&self) -> Result<Bytes, LfoError> {
        let full_data = match self.read_state {
            ResponseReadState::Direct { .. } => self.lfo_data.clone(),
            #[cfg(feature = "lfo-compress-xz")]
            ResponseReadState::Compressed { .. } => {
                let mut stream = XzDecoder::new(self.lfo_data.clone().reader());
                let mut buf = Vec::with_capacity(self.header.payload_size as usize);
                stream.read_to_end(&mut buf)?;
                buf.into()
            }
        };
        // This explicitly does not use Read, so we have to do these checks here too
        self.check_full_data_len(full_data.len())?;
        self.validate_full_data_hash(full_data.as_ref())?;
        Ok(full_data)
    }

    /// This returns the raw, still serialized LFO server's response.
    /// You most likely want to use [`Self::data()`](Self::data) instead.
    /// Only use this if you would like to parse some fields of the LFO header yourself.
    pub fn raw_lfo_payload(&self) -> Bytes {
        self.raw_lfo_payload.clone()
    }

    /// The LFO file header mostly contains low-level details about the file being downloaded.
    /// You can use it check the size the decompressed file, before actually decompressing it.
    pub fn lfo_file_header(&self) -> &LfoFileHeader {
        &self.header
    }

    #[cfg(feature = "lfo-check-hash")]
    fn update_running_hash(hasher: &mut sha2::Sha256, buf: &[u8]) {
        use sha2::Digest;
        hasher.update(&buf);
    }
    #[cfg(not(feature = "lfo-check-hash"))]
    fn update_running_hash(_hasher: &mut (), _buf: &[u8]) {}

    #[cfg(feature = "lfo-check-hash")]
    fn check_hash_matches(expected: &[u8; 32], hasher: &mut sha2::Sha256) -> Result<(), LfoError> {
        use sha2::Digest;
        let actual = hasher.finalize_reset();
        if expected != actual.as_slice() {
            return Err(LfoError::InvalidHash {
                expected: *expected,
                actual: *actual.as_ref(),
            });
        }
        Ok(())
    }
    #[cfg(not(feature = "lfo-check-hash"))]
    fn check_hash_matches(_expected: &[u8; 32], _actual: &()) -> Result<(), LfoError> {
        Ok(())
    }

    #[cfg(feature = "lfo-check-hash")]
    fn validate_full_data_hash(&self, data: &[u8]) -> Result<(), LfoError> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        Self::check_hash_matches(&self.header.data_hash, &mut hasher)
    }
    #[cfg(not(feature = "lfo-check-hash"))]
    fn validate_full_data_hash(&self, _data: &[u8]) -> Result<(), LfoError> {
        Ok(())
    }

    fn check_full_data_len(&self, data_len: usize) -> Result<(), LfoError> {
        if data_len != self.header.payload_size as usize {
            return Err(LfoError::ReplyParseError {
                reason: format!(
                    "LFO file data has length {:#x}, but expected {:#x}",
                    data_len, self.header.payload_size
                ),
                raw_payload: Default::default(),
            });
        }
        Ok(())
    }

    fn try_from_raw_lfo_payload(raw_payload: Vec<u8>) -> Result<Self, LfoError> {
        let raw_payload = Bytes::from(raw_payload);
        let header = match LfoFileHeader::try_from(raw_payload.as_ref()) {
            Ok(h) => h,
            Err(e) => {
                return Err(LfoError::ReplyParseError {
                    reason: e,
                    raw_payload,
                })
            }
        };
        let chunk_data = raw_payload.slice(LFO_RESP_HDR_LEN..raw_payload.len() - CRC_LEN);
        let read_state = if header.comp_format == CompressionFormats::None as u16 {
            ResponseReadState::Direct { read_pos: 0 }
        } else if cfg!(feature = "lfo-compress-xz")
            && header.comp_format == CompressionFormats::Xz as u16
        {
            #[cfg(not(feature = "lfo-compress-xz"))]
            unreachable!();
            #[cfg(feature = "lfo-compress-xz")]
            ResponseReadState::Compressed {
                stream: XzDecoder::new(chunk_data.clone().reader()),
            }
        } else {
            return Err(LfoError::ReplyParseError {
                reason: format!("Unsupported compression format {}", header.comp_format),
                raw_payload,
            });
        };
        Ok(Self {
            raw_lfo_payload: raw_payload,
            header,
            lfo_data: chunk_data,
            read_state,
            read_hasher: Default::default(),
        })
    }
}

impl TryFrom<CloudProtoPacket> for LfoResponse {
    type Error = LfoError;

    fn try_from(reply: CloudProtoPacket) -> Result<Self, Self::Error> {
        if reply.kind == LfoPacketKind::ReplyFail && reply.payload.len() >= 8 {
            let msg = String::from_utf8_lossy(&reply.payload[8..]);

            // I realize this is terrible, but internal errors indicate file not found errors
            // I have not seen any other internal errors, except for when the path is wrong
            if msg == "internal error" {
                Err(LfoError::NotFound)
            } else {
                Err(LfoError::ServerError(msg.to_string()))
            }
        } else if reply.kind == LfoPacketKind::ReplyOk {
            trace!(
                "Received LfoOk with {:#x} bytes raw payload",
                reply.payload.len()
            );
            Self::try_from_raw_lfo_payload(reply.payload)
        } else {
            Err(LfoError::BadReplyKind(reply.kind))
        }
    }
}

impl Read for LfoResponse {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let hasher = &mut self.read_hasher;
        match &mut self.read_state {
            ResponseReadState::Direct { read_pos } => {
                let remaining = &self.lfo_data[*read_pos..];
                let attempted_count = cmp::min(buf.len(), remaining.len());
                let count = buf.write(&remaining[..attempted_count])?;

                Self::update_running_hash(hasher, &remaining[..count]);
                if count == remaining.len() && count != 0 {
                    Self::check_hash_matches(&self.header.data_hash, hasher)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                }

                *read_pos += count;
                Ok(count)
            }
            #[cfg(feature = "lfo-compress-xz")]
            ResponseReadState::Compressed { stream } => {
                let count = stream.read(buf)?;
                Self::update_running_hash(hasher, &buf[..count]);

                if stream.total_out() > self.header.payload_size as u64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        LfoError::InvalidFinalSize {
                            expected: self.header.payload_size as usize,
                            actual: stream.total_out() as usize,
                        },
                    ));
                } else if count != 0 && stream.total_out() == self.header.payload_size as u64 {
                    Self::check_hash_matches(&self.header.data_hash, hasher)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                }

                Ok(count)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::framing::{CloudProtoPacket, CloudProtoVersion};
    use crate::services::lfo::pkt_kind::LfoPacketKind;
    use crate::services::lfo::test::TEST_REPLY_DATA;
    use crate::services::lfo::{LfoError, LfoResponse};
    use crate::services::CloudProtoMagic;
    use std::io::Read;

    fn check_test_vector(lfo_reply_hex: &str, expected_hash: &str) -> Result<(), LfoError> {
        let lfo_reply = hex::decode(lfo_reply_hex).unwrap();
        let reply_pkt = CloudProtoPacket {
            magic: CloudProtoMagic::TS,
            kind: LfoPacketKind::ReplyOk.into(),
            version: CloudProtoVersion::Normal,
            payload: lfo_reply.clone(),
        };
        let mut resp = LfoResponse::try_from(reply_pkt)?;
        assert_eq!(resp.raw_lfo_payload(), &lfo_reply);

        let data = {
            let data_from_bytes1 = resp.data()?;
            let mut data_from_read = Vec::new();
            resp.read_to_end(&mut data_from_read)?;
            let data_from_bytes2 = resp.data()?;
            assert_eq!(data_from_bytes1, data_from_bytes2);
            assert_eq!(data_from_bytes1, data_from_read);
            data_from_read
        };

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        assert_eq!(&hex::encode(hasher.finalize().as_slice()), expected_hash);

        // We should already check the hash by default, but let's do it again for good measure
        assert_eq!(
            expected_hash,
            &hex::encode(&resp.lfo_file_header().data_hash)
        );
        Ok(())
    }

    #[test]
    fn simple_test_vector() -> Result<(), LfoError> {
        let expected_hash = "a330869acb341ad81b4b64f92ed7b85e0a361ab0449017a9f7a5f09276a43655";
        check_test_vector(TEST_REPLY_DATA, expected_hash)
    }

    #[test]
    #[cfg(feature = "lfo-compress-xz")]
    fn xz_test_vector() -> Result<(), LfoError> {
        let hex = "000000000000015658dd00985ef1c304b973374fad8726aeac9769fe45d1bea2335630b0899b9ef60001fd377a585a0000016922de36020021011c00000010cf\
                         58cce0015500645d0055687c400160306c2cec9513bc4360c68796e3b982a76ad18024af592b8f044aae3937e42bec03336fa43a3ecd228463d4545ae8cf99a9\
                         6368bfc3d7137b5f1fe5cb4201c3928e6a07895cba5f7220d2a3f5400768f1a63acc53ae5abbf13d5b6b84000000c3d9916a00017cd602000000155b09133e30\
                         0d8b020000000001595a75e2d281";
        let expected_hash = "58dd00985ef1c304b973374fad8726aeac9769fe45d1bea2335630b0899b9ef6";
        check_test_vector(hex, expected_hash)
    }
}
