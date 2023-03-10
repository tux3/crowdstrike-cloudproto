use crate::framing::{CloudProtoError, CloudProtoPacket, CloudProtoSocket, CloudProtoVersion};
use crate::services::ts::event::EVT_HDR_LEN;
use crate::services::ts::{AgentIdStatus, Event, TsConnectInfo, TsPacketKind};
use crate::services::CloudProtoMagic;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use std::io::Cursor;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, error, trace, warn};

const HDR_TXID_SIZE: usize = std::mem::size_of::<u64>();
// Values observed from the official client.
// The TS server returns large quickly incrementing TXIDs, but these values here are fine.
const FIRST_TXID: u64 = 0x200;
const TXID_INCREMENT: u64 = 0x100;

/// Async socket used to stream [`Event`](Event)s with the TS service
///
/// You need to provide a valid Crowdstrike Customer ID (CID) to authenticate with the server.
/// The TS server checks that this CID belongs to a valid customer and will immediately close the socket otherwise.
///
/// You should have been provided with a "CCID" when installing the Falcon Sensor,
/// which looks something like "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-BB".
/// The CID is the first part before the "-BB".
///
/// After installation, you can still find your CID in binary form in the "falconstore" file,
/// saved as a 16 byte binary blob, right after the UTF-16 literal "CU".
pub struct TsEventSocket<IO: AsyncRead + AsyncWrite> {
    io: CloudProtoSocket<IO>,
    next_txid: u64,

    unacked_txid: Option<u64>,
    unacked_event: Option<Event>,
}

impl<IO> TsEventSocket<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    pub(crate) fn new(io: CloudProtoSocket<IO>) -> Self {
        Self {
            io,
            next_txid: FIRST_TXID,
            unacked_txid: None,
            unacked_event: None,
        }
    }

    pub async fn connect(
        mut io: CloudProtoSocket<IO>,
        info: TsConnectInfo,
    ) -> Result<Self, CloudProtoError> {
        let mut payload = Vec::with_capacity(4 * 16 + 8);
        payload.extend_from_slice(&info.cid);
        payload.extend_from_slice(&info.unk0);
        payload.extend_from_slice(&info.aid);
        payload.extend_from_slice(&info.bootid);
        payload.extend_from_slice(&info.pt);
        let pkt = CloudProtoPacket {
            magic: CloudProtoMagic::TS,
            kind: TsPacketKind::Connect.into(),
            version: CloudProtoVersion::Connect,
            payload,
        };
        io.send(pkt).await?;

        let reply = match io.next().await {
            Some(pkt) => pkt?,
            None => {
                return Err(CloudProtoError::ClosedByPeer(
                    "TS server closed connection".into(),
                ))
            }
        };
        // Log the connection packet for debugging, since we don't otherwise return the payload in errors
        trace!("Received TS connect reply: {}", hex::encode(&reply.payload));

        if reply.magic != CloudProtoMagic::TS {
            return Err(CloudProtoError::BadMagic(reply.magic, CloudProtoMagic::TS));
        }
        if reply.kind != TsPacketKind::ConnectionEstablished {
            error!(
                "Bad TS connect reply kind: {:X?}, payload: {}",
                reply,
                hex::encode(&reply.payload)
            );
            return Err(CloudProtoError::WrongConnectionPacketKind(
                reply.kind,
                TsPacketKind::ConnectionEstablished.into(),
            ));
        }
        if reply.version != CloudProtoVersion::Normal {
            error!(
                "Bad TS connect reply version: {:X?}, payload: {}",
                reply,
                hex::encode(&reply.payload)
            );
            return Err(CloudProtoError::BadVersion(
                reply.version,
                CloudProtoVersion::Normal,
            ));
        }

        if reply.payload.len() != 17 {
            warn!("TsEventSocket connect reply has unexpected size, continuing anyways")
        } else if reply.payload[0] == AgentIdStatus::Unchanged as u8 {
            debug!(
                received_aid = hex::encode(&reply.payload[1..]),
                "TS socket connected, AgentID unchanged",
            );
            if info.aid[..] != reply.payload {
                warn!("TS server says to keep our AgentID, but replied with a different one!");
            }
        } else if reply.payload[0] == AgentIdStatus::Changed as u8 {
            debug!(
                received_aid = hex::encode(&reply.payload[1..]),
                "TS socket connected, AgentID has changed",
            );
            if info.aid[..] == reply.payload {
                warn!("TS server says to change our AgentID, but replied with the same one!");
            }
        } else {
            warn!(
                "Unexpected value from TS server when checking whether the AgentID changed: {:#x}",
                reply.payload[0]
            )
        }

        Ok(Self::new(io))
    }
}

impl<IO> Stream for TsEventSocket<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    type Item = Result<Event, CloudProtoError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // (Shh, don't tell anyone, but this is a stealth goto we take just once after receiving an event!)
        'process_pending_acks: loop {
            if let Some(txid) = &this.unacked_txid {
                assert!(this.unacked_event.is_some());
                ready!(this.io.poll_ready_unpin(cx))?;

                this.io.start_send_unpin(CloudProtoPacket {
                    magic: CloudProtoMagic::TS,
                    kind: TsPacketKind::Ack.into(),
                    version: CloudProtoVersion::Normal,
                    payload: txid.to_be_bytes().to_vec(),
                })?;
                let _ = this.unacked_txid.take();

                // If the ACK doesn't finish leaving here, that's fine,
                // we also flush below when our io's recv side is still Pending
                ready!(this.io.poll_flush_unpin(cx))?;
            }
            if let Some(ev) = this.unacked_event.take() {
                assert!(this.unacked_txid.is_none());
                return Poll::Ready(Some(Ok(ev)));
            }

            '_receive_packets: loop {
                let pkt = match this.io.poll_next_unpin(cx)? {
                    Poll::Ready(Some(pkt)) => pkt,
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Pending => {
                        // If the user is only polling the read side, some of our ACKs might never finish flushing,
                        // the other server would stop sending, and this poll_next would be Pending forever :)
                        // So if we have nothing left but the user is still reading, it's a good time to flush our send side
                        ready!(this.io.poll_flush_unpin(cx))?;
                        return Poll::Pending; // We still have a queued wake on the read side
                    }
                };

                if pkt.kind == TsPacketKind::Ack {
                    // This would be the place to update a queue of un-ACKed inflight packets,
                    // so we can have backpressure, and retransmits packets after some time.
                    //
                    // We don't do any of that, because Crowdstrike's client doesn't either,
                    // and it's unreasonably hard to be the only side "following TCP rules"
                    // if the other side assumes packets it sends can never be dropped.
                    //
                    // See the other (large) comment below on the send side for more context.
                    if pkt.payload.len() == 8 {
                        let txid = u64::from_be_bytes(pkt.payload[..].try_into().unwrap());
                        trace!("Received ACK for event txid {:#x}", txid);
                    } else {
                        error!(
                            "Received ACK packet with invalid size: {:#x}",
                            pkt.payload.len()
                        )
                    }
                    continue;
                } else if pkt.kind == TsPacketKind::Event {
                    if pkt.payload.len() < HDR_TXID_SIZE + EVT_HDR_LEN {
                        return Poll::Ready(Some(Err(CloudProtoError::PayloadTooShort(
                            pkt.payload.len(),
                            HDR_TXID_SIZE + EVT_HDR_LEN,
                        ))));
                    }
                    let txid = u64::from_be_bytes(pkt.payload[..HDR_TXID_SIZE].try_into().unwrap());
                    let ev = Event::from_read(&mut Cursor::new(&pkt.payload[HDR_TXID_SIZE..]))?;

                    // We ACK received events before returning them, to make sure we keep getting polled until the ACK is sent
                    // So we have to buffer the event and its txid, in case we get Poll::Pending while trying to ACK it
                    trace!(
                        "Received event with txid {:#x}, preparing to send ACK",
                        txid
                    );
                    assert!(this.unacked_txid.is_none());
                    this.unacked_txid = Some(txid);
                    assert!(this.unacked_event.is_none());
                    this.unacked_event = Some(ev);
                    continue 'process_pending_acks;
                } else {
                    // Hoping this was a non-essential packet and continuing happily...
                    warn!(
                        "Received unexpected CloudProto packet kind: {:#x}",
                        pkt.kind
                    );
                    trace!("Unexpected packet payload: {}", hex::encode(&pkt.payload));
                }
            }
        }
    }
}

impl<IO> Sink<Event> for TsEventSocket<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // If we wanted to tracked ACKs for our tx, here we would need to block when the
        // queue of inflight un-ACKed events we're trackign becomes full.
        // But that queue can only shrink when we *receive* ACKs, so the TX side would depend
        // on Rust users of the lib also polling the RX side regularly, *while* they send.
        // If a user did some ts_sock.send().await in a loop without ever receiving, we'd DEADLOCK.
        //
        // So we could poll the RX internally from TX when our send queue is full until we get ACKs
        // But it's a single RX stream. We might receive real Events instead, all while inside send.
        // So we could stash them in an RX queue until full, but then we what should send() do?
        //
        // An unsatisfying option is to just return an error from start_send() when that happens,
        // because your RX queue is full, maybe no one's polling RX, and we don't want to deadlock.
        // But that error could also happen in normal usage if the TX races faster than the RX.
        // And in Rust, Sinks that return error are generally expected to be permanently closed.
        // Rust sinks don't normally do "oops you need to poll the read side a little!" errors :)
        //
        // This is where TX would just drop packets on the floor when the RX queue is full,
        // and that ought to be fine! If we drop them they won't be ACKd, and the other side
        // will just retransmit them to us later. A little bit of inefficiency on the RX side,
        // but this only happens when the RX queue is full, so that'd be reasonable.
        //
        // Except, as it turns out, the official Crowdstrike client does **none of that**!
        //
        // It *looks like* it has code to do it! It *seems* to track inflight packets,
        // walks all sorts of linked lists to process inflight packets and the ACKs for them,
        // its send worker thread has some kind of "send window" and "backpressure" like routines.
        //
        // But in practice, it completely ignores ACKs. It always just keeps forging ahead,
        // so we can't rely on being able to drop packets when our RX queue is full, they'd be lost.
        // This is the problem with being the only side trying to uphold guarantees, you only
        // get the constraints but you don't get to rely on the other side following them ^^'
        //
        // This is still work-around-able, either by telling users to always split() this socket
        // and always poll the RX side in an async task, so we get to just block in TX and be done.
        // This is pretty much how Crowdstrike's client is architectured too.
        // It has an RX and TX worker, and reality aside, in theory it should just work like this.
        //
        // Or, we could do "engineering" and add a 100ms timer since the last RX poll.
        // TX would only try to go receive ACKs itself after 100ms pass without any RX poll,
        // it'd put Events in the RX queue until full, and return an error when that's full.
        // Because of the timer this can't happen in normal usage anymore.
        // With this, if you are polling RX from time to time TX will just wait for you.
        // If you're only sending but you know you won't be received packets, it
        // TX *will* have to do reads, but it will see only ACKs, won't have to fill the RX queue,
        // and so you will not see the error in practice.
        // Only if you keep sending without having an RX worker, and the other side actually
        // replies with Events, then we'd return the error, because that's still better
        // than a deadlock or just dropping received packets that the other side won't retransmit.
        //
        //
        // But, instead of all that, we just do as the romans do and happily ignore received ACKs.
        // Firstly because it's completely unnecessary, the Crowdstrike server already has to
        // deal with a client that doesn't follow ACKs at all, so we're "bug-for-bug" compatible.
        //
        // Second because CLOUDPROTO is *always* carried over TLS, so ACKs were never necessary
        // in the first place! Even if you do TLS over UDP for some reason, you will already have
        // done retransmissions below the TLS layer, because TLS won't just let you drop packets in
        // the middle of an encrypted stream. The crypto layer tends to not like that idea.
        //
        // It's interesting that their client _almost_ implements all of this machinery,
        // but then gives up in practice. Maybe it was just too complex and/or annoying to debug?
        // I'm just curious why they still ship all of this code that doesn't run in practice...
        // For instance, the client has a check where if a function returns some status code,
        // that means a duplicate ACK was received. Except that status code is _never_ returned
        // by that function, in fact it's found nowhere else in the code accoring to IDA :)
        //
        // A lot of the client code is like this, half implemented stuff. But maybe we should
        // really be impressed by this surely purposeful obfuscation and misdirection.
        // (...almost as effective as having to follow all those damn C++ virtual calls everywhere!)
        let this = self.get_mut();
        this.io.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, ev: Event) -> Result<(), Self::Error> {
        let this = self.get_mut();

        let mut buf = Vec::with_capacity(HDR_TXID_SIZE + EVT_HDR_LEN + ev.data.len());
        buf.extend_from_slice(&this.next_txid.to_be_bytes());
        this.next_txid += TXID_INCREMENT;
        match ev.into_write(&mut buf) {
            Ok(_) => {}
            Err(CloudProtoError::Io { source }) => return Err(source),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unexpected error while sending Event: {}", e),
                ))
            }
        }

        this.io.start_send_unpin(CloudProtoPacket {
            magic: CloudProtoMagic::TS,
            kind: TsPacketKind::Event.into(),
            version: CloudProtoVersion::Normal,
            payload: buf,
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().io.poll_flush_unpin(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().io.poll_close_unpin(cx)
    }
}
