Provides async sockets and high-level objects that implement the protocol
used between Crowdstrike's Falcon Sensor and the two backend services:
- The TS event server (event collection, device monitoring, admin remote shell, ...)
- The LFO file server (downloading updates, uploading sample files for analysis, ...)

It is also possible to implement your own private TS or LFO server,
for instance if you want to receive live sensor events from the official client.

## Features

The [`CloudProtoSocket`](framing::CloudProtoSocket) implements the common low-level packet structure
used by the official client and both cloud services.    
You probably want to use the higher-level TS socket or LFO client directly;
They are both layerd over a [`CloudProtoSocket`](framing::CloudProtoSocket),
but they work with high level concepts instead of [`CloudProtoPacket`](framing::CloudProtoPacket)s.

### TS Event socket

The [`TsEventSocket`](services::ts::TsEventSocket) allows connecting to the TS service
and exchanging [`Event`](services::ts::Event)s,
which is how the `falcon-sensor` agent streams back live information to the cloud.

You must provide a valid Customer ID (CID) to connect to the official TS servers.  
See the [`TsEventSocket`](services::ts::TsEventSocket) documentation for more information.

### LFO client

The [`LfoClient`](services::lfo::LfoClient) allows you to download updates and other potentially large files used by the sensor.

The client supports LFO file GET requests with optional XZ compression.  
There is currently no immediate plan to support uploads.

You do not need to be a Crowdstrike customer to download files from LFO.  
(LFO requests contain CID/AID fields, but any values are accepted).

### Server functionality

Running a third party Crowdstrike server requires using a modified client configured
to connect to a domain you own with a valid certificate,
or disabling certificate validation in falcon-sensor.

As of version 13601, Falcon as a whole performs no integrity checks, so it happily runs with arbitrary patches applied.

### Epistemic Notice

Please note that this crate is a clean-room implementation based on observing sensor version 13601
talk to a third-party server in an isolated VM,
and on using this crate to replay a few sensor events and capturing the public TS service's replies.

As a result, you should expect that this library **may not be a 100% conforming implementation**.
It may be missing some optional parts of the protocol, some of the reverse-engineered fields that
don't affect the result may lack names, and some might be named wrong entirely.

## What is the Crowdstrike CLOUDPROTO?

The name "CLOUDPROTO" comes from a debug log message inside the falcon-sensor binary.

Internally, falcon-sensor is architectured around Actors (C++ objects) that exchange
Events (plain data) using an event bus.
The same events that falcon-sensor actors use internally are also used to communicate with the TS cloud server
by carrying serialized [events](services::ts::Event) within CLOUDPROTO [frames](framing::CloudProtoPacket).

Events for the TS server are first serialized with Protobuf and complemented by
a short header that contains the event type and a transaction ID.
This serialized event payload is sent over a CLOUDPROTO socket, which is itself wrapped
in a TLS session over TCP port 443.

The event protocol has a quirky ACK mechanism, which appears redundant with the TLS and TCP sockets
it's layered over, and does not in fact seem to be actually used to provide any backpressure
or retransmission guarantees in the official implementation.  
The `falcon-sensor` does send ACK packets, but seems to ignore incoming ACKs (or their lack of) entirely.  
(This quirk is despite much of the functionality to track ACKs and in-flight packets
being visibly present in the `falcon-sensor` binary).

The LFO server also uses CLOUDPROTO frames to carry its messages,
but instead of TS events it uses simple request/response packets,
and has no ACK mechanism at all.
