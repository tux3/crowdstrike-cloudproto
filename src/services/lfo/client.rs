use crate::framing::{CloudProtoError, CloudProtoPacket, CloudProtoSocket, CloudProtoVersion};
use crate::services::lfo::pkt_kind::LfoPacketKind;
use crate::services::lfo::request::LfoRequest;
use crate::services::lfo::{LfoError, LfoResponse};
use crate::services::CloudProtoMagic;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

/// Request files stored on an LFO file server.
pub struct LfoClient<IO: AsyncRead + AsyncWrite> {
    sock: CloudProtoSocket<IO>,
}

impl<IO> LfoClient<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    pub fn new(sock: CloudProtoSocket<IO>) -> Self {
        Self { sock }
    }

    /// Download the file at the remote path specified in the [`LfoRequest`](super::LfoRequest).
    pub async fn get(&mut self, request: &LfoRequest) -> Result<LfoResponse, LfoError> {
        let payload = request.to_payload();
        trace!("Sending LFO request payload: {}", hex::encode(&payload));
        let req_pkt = CloudProtoPacket {
            magic: CloudProtoMagic::LFO,
            kind: LfoPacketKind::GetFileRequest.into(),
            version: CloudProtoVersion::Connect,
            payload,
        };
        self.sock.send(req_pkt).await?;

        if let Some(reply) = self.sock.next().await {
            Ok(reply?.try_into()?)
        } else {
            Err(LfoError::CloudProto(CloudProtoError::ClosedByPeer(
                "LFO server closed connection".to_owned(),
            )))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::framing::{CloudProtoPacket, CloudProtoSocket, CloudProtoVersion};
    use crate::services::lfo::pkt_kind::LfoPacketKind;
    use crate::services::lfo::test::TEST_REPLY_DATA;
    use crate::services::lfo::{LfoClient, LfoError, LfoRequest};
    use crate::services::CloudProtoMagic;
    use futures_util::{SinkExt, StreamExt};
    use tokio::spawn;

    #[test_log::test(tokio::test)]
    async fn simple_mock_request() -> Result<(), LfoError> {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let mut client = LfoClient::new(CloudProtoSocket::new(client));
        let mut server = CloudProtoSocket::new(server);

        let req_path = "/test/foo".to_string();
        let req = LfoRequest::new_simple(req_path.clone());

        let server_task = spawn(async move {
            let req = server.next().await.unwrap()?;
            assert_eq!(req.magic, CloudProtoMagic::LFO);
            assert_eq!(req.version, CloudProtoVersion::Connect);
            assert_eq!(req.kind, LfoPacketKind::GetFileRequest);
            let req = LfoRequest::try_from_payload(&req.payload)?;
            assert_eq!(&req.remote_path, &req_path);

            server
                .send(CloudProtoPacket {
                    magic: CloudProtoMagic::LFO,
                    kind: LfoPacketKind::ReplyOk.into(),
                    version: CloudProtoVersion::Normal,
                    payload: hex::decode(TEST_REPLY_DATA).unwrap(),
                })
                .await?;
            Ok::<(), LfoError>(())
        });
        let reply = client.get(&req).await?;
        assert_eq!(hex::encode(reply.raw_lfo_payload()), TEST_REPLY_DATA);

        server_task.await.unwrap()?;
        Ok(())
    }
}
