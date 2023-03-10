//! High-level support for the TS event server

mod acceptor;
mod event;
mod pkt_kind;
mod socket;

pub use acceptor::TsEventAcceptor;
pub use event::{Event, EventId};
pub use pkt_kind::TsPacketKind;
pub use socket::TsEventSocket;

use crate::services::{DEFAULT_BOOTID_HEX, DEFAULT_UNK0_HEX};

/// Whether the server expects the client to keep its Agent ID or be assigned a new one
#[repr(u8)]
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum AgentIdStatus {
    Unchanged = 0x1,
    Changed = 0x2,
}

/// Connection information required to open a session with the TS server
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct TsConnectInfo {
    // The CID assigned to a Crowdstrike customer (same as the CCID without the last -N number)
    // These are not random, there's a sort of checksum that must pass for a CID to be valid.
    // For TS the CID needs to be not only valid, but belong to an active customer
    pub cid: [u8; 16],
    // Unknown, but has never changed and the AID returned by TS depends on it (can also be 0)
    pub unk0: [u8; 16],
    // Agent ID. Saved in "falconstore". New values can be assigned by the TS server on connection
    pub aid: [u8; 16],
    // Per-machine value (the stable /proc/sys/kernel/random/boot_id, or a timestamp if unavailable)
    pub bootid: [u8; 16],
    // The "PT" value from "falconstore". Can be left as zeroes.
    pub pt: [u8; 8],
}

impl TsConnectInfo {
    /// Connect using the provided Crowdstrike customer ID
    /// The CID must belong to an active customer.
    /// Unlike for the LSO server and falcon-sensor it's not enough to use a structurally valid but inactive CID.
    /// Uses hardcoded default values for the other non-critical fields.
    pub fn new_simple(cid: [u8; 16]) -> Self {
        Self {
            cid,
            unk0: hex::decode(DEFAULT_UNK0_HEX).unwrap().try_into().unwrap(),
            aid: [0; 16],
            bootid: hex::decode(DEFAULT_BOOTID_HEX).unwrap().try_into().unwrap(),
            pt: [0; 8],
        }
    }

    pub fn new_custom(
        cid: [u8; 16],
        unk0: [u8; 16],
        aid: [u8; 16],
        bootid: [u8; 16],
        pt: [u8; 8],
    ) -> Self {
        Self {
            cid,
            unk0,
            aid,
            bootid,
            pt,
        }
    }
}

/// Response to a connection from the TS server
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct TsConnectResponse {
    // Whether the server expects us to keep our existing agent ID, or to update it
    pub agent_id_status: AgentIdStatus,
    // The agent ID assigned by the server
    pub aid: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{CloudProtoError, CloudProtoSocket};
    use futures_util::{SinkExt, StreamExt};
    use tokio::spawn;

    #[tokio::test]
    async fn test_simple_client_server() -> Result<(), CloudProtoError> {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let cid = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let old_aid = [4, 4, 4, 4, 2, 2, 2, 2, 8, 8, 8, 8, 1, 1, 1, 1];
        let new_aid = [9, 9, 9, 9, 0, 0, 0, 0, 9, 9, 9, 9, 0, 0, 0, 0];

        let server_task = spawn(async move {
            let (server, info) = TsEventAcceptor::listen(CloudProtoSocket::new(server)).await?;
            assert_eq!(info.cid, cid);
            assert_eq!(info.aid, old_aid);
            let mut sock = server
                .accept(TsConnectResponse {
                    agent_id_status: AgentIdStatus::Changed,
                    aid: new_aid,
                })
                .await?;
            let ev = sock.next().await.unwrap()?;
            assert_eq!(ev.event_id, Some(EventId::AgentOnline));
            sock.send(Event::new(
                EventId::LfoDownloadFromManifestRecord,
                vec![1, 2, 3],
            ))
            .await?;

            Ok::<_, CloudProtoError>(sock) // Keep sock alive!
        });

        let mut client = TsEventSocket::connect(
            CloudProtoSocket::new(client),
            TsConnectInfo::new_custom(cid, [0; 16], old_aid, [0; 16], [0; 8]),
        )
        .await?;
        client
            .send(Event::new(EventId::AgentOnline, vec![]))
            .await?;
        let ev = client.next().await.unwrap()?;
        assert_eq!(ev.event_id, Some(EventId::LfoDownloadFromManifestRecord));
        assert_eq!(ev.data, &[1, 2, 3]);
        server_task.await.expect("Server task join error!")?;
        Ok(())
    }
}
