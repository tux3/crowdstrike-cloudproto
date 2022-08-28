use crate::framing::packet::CloudProtoPacket;
use bytes::Bytes;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{error, trace};

pub struct CloudProtoSocket<IO> {
    read: FramedRead<ReadHalf<IO>, LengthDelimitedCodec>,
    write: FramedWrite<WriteHalf<IO>, BytesCodec>,
}

impl<IO> CloudProtoSocket<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    pub fn new(io: IO) -> Self {
        let (read, write) = tokio::io::split(io);
        let read = LengthDelimitedCodec::builder()
            .big_endian()
            .length_field_type::<u32>()
            .length_adjustment(0)
            .length_field_offset(4)
            .num_skip(0)
            .new_read(read);
        let write = FramedWrite::new(write, BytesCodec::new());
        Self { read, write }
    }
}

impl<IO> Stream for CloudProtoSocket<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    type Item = CloudProtoPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            let pkt = match ready!(this.read.poll_next_unpin(cx)) {
                Some(Ok(frame)) => CloudProtoPacket::from_buf(&frame),
                Some(Err(e)) => {
                    error!("Failed to read cloudproto frame: {}", e);
                    return Poll::Ready(None);
                }
                None => return Poll::Ready(None),
            };
            match pkt {
                Ok(pkt) => {
                    trace!(
                        "Received kind 0x{:x} packet with 0x{:x} bytes payload: {}",
                        pkt.kind,
                        pkt.payload.len(),
                        hex::encode(&pkt.payload),
                    );
                    return Poll::Ready(Some(pkt));
                }
                Err(e) => {
                    error!("Bad cloudproto packet: {}", e);
                    continue;
                }
            }
        }
    }
}

impl<IO> Sink<CloudProtoPacket> for CloudProtoSocket<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        SinkExt::<Bytes>::poll_ready_unpin(&mut self.get_mut().write, cx)
    }

    fn start_send(self: Pin<&mut Self>, pkt: CloudProtoPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let buf = Bytes::from(pkt.to_buf());
        trace!(
            "Sending kind 0x{:x} packet with 0x{:x} bytes payload: {}",
            pkt.kind,
            pkt.payload.len(),
            hex::encode(&pkt.payload),
        );
        this.write.start_send_unpin(buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        SinkExt::<Bytes>::poll_flush_unpin(&mut self.get_mut().write, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        SinkExt::<Bytes>::poll_close_unpin(&mut self.get_mut().write, cx)
    }
}

#[cfg(test)]
mod test {
    use crate::framing::{CloudProtoPacket, CloudProtoSocket, CloudProtoVersion};
    use crate::services::CloudProtoMagic;
    use anyhow::Result;
    use futures_util::{SinkExt, StreamExt};
    use rand::Rng;

    #[test_log::test(tokio::test)]
    async fn single_send_recv() -> Result<()> {
        let (client, server) = tokio::io::duplex(100 * 1024);
        let mut client = CloudProtoSocket::new(client);
        let mut server = CloudProtoSocket::new(server);

        let mut rng = rand::thread_rng();
        let len = rng.gen::<u16>() as usize;
        let mut payload = Vec::with_capacity(len);
        payload.resize(len, len as u8);
        let pkt = CloudProtoPacket {
            magic: CloudProtoMagic::TS,
            kind: 0,
            version: CloudProtoVersion::Normal,
            payload,
        };
        client.send(pkt.clone()).await?;
        let reply = server.next().await.unwrap();
        assert_eq!(pkt, reply);

        Ok(())
    }
}
