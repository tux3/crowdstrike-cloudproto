use crate::framing::CloudProtoError::ClosedByPeer;
use crate::framing::{CloudProtoError, CloudProtoPacket, CloudProtoSocket, CloudProtoVersion};
use crate::services::ts::{TsConnectInfo, TsConnectResponse, TsEventSocket, TsPacketKind};
use crate::services::CloudProtoMagic;
use bytes::Buf;
use futures_util::{SinkExt, StreamExt};
use std::io::Read;
use tokio::io::{AsyncRead, AsyncWrite};

/// Accept [`TsEventSocket`](TsEventSocket) connections
pub struct TsEventAcceptor<IO: AsyncRead + AsyncWrite> {
    io: CloudProtoSocket<IO>,
}

impl<IO> TsEventAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    /// Wait for an incoming TS client connection, and return the received [`TsConnectInfo`](TsConnectInfo)
    pub async fn listen(
        mut io: CloudProtoSocket<IO>,
    ) -> Result<(Self, TsConnectInfo), CloudProtoError> {
        let pkt = match io.next().await {
            None => return Err(ClosedByPeer("TS client closed connection".into())),
            Some(Err(e)) => return Err(e),
            Some(Ok(pkt)) => pkt,
        };
        if pkt.magic != CloudProtoMagic::TS {
            return Err(CloudProtoError::BadMagic(pkt.magic, CloudProtoMagic::TS));
        }
        if pkt.kind != TsPacketKind::Connect {
            return Err(CloudProtoError::WrongConnectionPacketKind(
                pkt.kind,
                TsPacketKind::Connect.into(),
            ));
        }
        if pkt.version != CloudProtoVersion::Connect {
            return Err(CloudProtoError::BadVersion(
                pkt.version,
                CloudProtoVersion::Connect,
            ));
        }

        if pkt.payload.len() != 4 * 16 + 8 {
            return Err(CloudProtoError::PayloadInvalidSize(
                pkt.payload.len(),
                4 * 16 + 8,
            ));
        }
        let mut info = TsConnectInfo {
            cid: [0; 16],
            unk0: [0; 16],
            aid: [0; 16],
            bootid: [0; 16],
            pt: [0; 8],
        };
        let mut rd = pkt.payload.reader();
        rd.read_exact(&mut info.cid)?;
        rd.read_exact(&mut info.unk0)?;
        rd.read_exact(&mut info.aid)?;
        rd.read_exact(&mut info.bootid)?;
        rd.read_exact(&mut info.pt)?;

        Ok((Self { io }, info))
    }

    /// Accept an incoming TS client, establishing a connected socket
    pub async fn accept(
        mut self,
        reply: TsConnectResponse,
    ) -> Result<TsEventSocket<IO>, CloudProtoError> {
        let mut payload = Vec::with_capacity(1 + 16);
        payload.push(reply.agent_id_status as u8);
        payload.extend_from_slice(&reply.aid);
        let pkt = CloudProtoPacket {
            magic: CloudProtoMagic::TS,
            kind: TsPacketKind::ConnectionEstablished.into(),
            version: CloudProtoVersion::Normal,
            payload,
        };
        self.io.send(pkt).await?;

        Ok(TsEventSocket::new(self.io))
    }
}
