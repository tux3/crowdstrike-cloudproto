use crate::framing::CloudProtoError;
use byteorder::{ReadBytesExt, WriteBytesExt, BE};
use std::io::{Read, Write};
use strum_macros::{AsRefStr, Display, FromRepr};

// Does not count the txid, which is handled transparently in the TsEventSocket
pub(crate) const EVT_HDR_LEN: usize = 4;

/// The `data` field usually contains a serialized Protobuf structure.
///
/// The Protobuf schema of the `data` depends entirely on `raw_event_id`,
/// and this crate does not provide deserialization for specific events.
///
/// A few event IDs do not correspond to protobuf data at all, using a variety of other simple binary formats.
///
/// The `event_id` field is `None` for values of `raw_event_id` that are not in the [`EventId`](EventId) enum.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Event {
    pub raw_event_id: u32,
    pub event_id: Option<EventId>,
    pub data: Vec<u8>,
}

impl Event {
    pub fn new(event_id: EventId, data: Vec<u8>) -> Self {
        Self {
            raw_event_id: event_id as u32,
            event_id: Some(event_id),
            data,
        }
    }

    pub fn new_raw(raw_event_id: u32, data: Vec<u8>) -> Self {
        Self {
            raw_event_id,
            event_id: None,
            data,
        }
    }

    /// Best effort text representation of the event ID using know [`EventId`][EventId] values
    pub fn ev_id_string(&self) -> String {
        if let Some(id) = self.event_id {
            id.to_string()
        } else {
            format!("{:#X}", self.raw_event_id)
        }
    }

    pub(crate) fn from_read(reader: &mut dyn Read) -> Result<Self, CloudProtoError> {
        let raw_event_id = reader.read_u32::<BE>()?;
        let event_id = EventId::from_repr(raw_event_id);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(Self {
            raw_event_id,
            event_id,
            data,
        })
    }

    pub(crate) fn into_write(self, writer: &mut dyn Write) -> Result<(), CloudProtoError> {
        writer.write_u32::<BE>(self.raw_event_id)?;
        writer.write_all(&self.data)?;
        writer.flush()?;
        Ok(())
    }
}

/// Tries to provide meaningful names for some well-known [`Event`](Event)s.
///
/// Event ID names containing `UNK` are known to exist, but were not found in the form of an immediate value in falcon-sensor,
/// so that some effort (beyond a simple lookup in the client) may be required to name them.
///
/// Some Event IDs are internal to falcon-sensor and never leave on the wire, so they are not listed.
/// Some events have not been observed yet, or may be added in later updates,
/// so this enum is only meant to document well-known values as a best-effort.
/// It won't be an exhaustive list.
#[derive(Eq, PartialEq, Debug, Copy, Clone, Display, AsRefStr, FromRepr)]
#[repr(u32)]
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[non_exhaustive]
pub enum EventId {
    ConfigurationLoaded =           0x308000AA,
    LfoDownloadFromManifestRecord = 0x308000AD,
    ChannelDownloadComplete =       0x308001D2,
    UNK_SERVER_0x30800207 =         0x30800207, // Sent by server, but no search results in sensor
    CurrentSystemTags =             0x30800208,
    CloudRequestReceived =          0x3080028E,
    UNK_0x30800296 =                0x30800296, // No search results in sensor
    IpAddressAddedForFamily2 =      0x308002e5, // I think this is IPv4, and the other IPv6?
    IpAddressAdded =                0x308002e6,
    HostnameChanged =               0x3080034D,
    CurrentUninstallTokenInfo =     0x30800457,
    ChannelRundown =                0x30800550,
    ChannelDiffDownload =           0x3080064E,
    DiskCapacity =                  0x3080069f,
    DiskUtilization =               0x30800850,
    UNK_0x31000002 =                0x31000002, // No search results in sensor
    ChannelVersionRequired =        0x310001D1,
    UNK_0x3100053f =                0x3100053f, // No search results in sensor
    SystemCapacity =                0x310005AB,
    UpdateCloudEvent =              0x318002B1,
    OsVersionInfo =                 0x3200014e,
    UNK_0x32000220 =                0x32000220, // No search results in sensor
    UNK_0x320002cf =                0x320002cf, // No search results in sensor
    ConnectionStatus =              0x32800139,
    AgentOnline =                   0x338000ac,
    UNK_0x340000ee =                0x340000ee, // No search results in sensor
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;

    #[test]
    fn test_known_id_string() {
        let ev = Event::new(EventId::AgentOnline, vec![]);
        assert_eq!(ev.ev_id_string(), "AgentOnline")
    }

    #[test]
    fn test_unknown_id_string() {
        let ev = Event::new_raw(0xAABBCCDD, vec![]);
        assert_eq!(ev.ev_id_string(), "0xAABBCCDD")
    }

    #[test]
    fn test_event_serde_rountrip() {
        let ev = Event::new_raw(0xAABBCCDD, vec![]);
        let mut buf = Vec::new();
        ev.clone().into_write(&mut buf).unwrap();
        let ev2 = Event::from_read(&mut buf.reader()).unwrap();
        assert_eq!(ev, ev2);
    }
}
