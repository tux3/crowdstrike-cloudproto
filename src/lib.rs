//! The binary protocol between Crowdstrike's Falcon Sensor and cloud servers
//!
//! Provides an async socket layer and structure definitions for the internal binary protocol used between
//! falcon-sensor and its backend cloud services.
//!
//! There are two Crowdstrike services you can talk to using this protocol, both over TLS:
//! - The TS event server (event collection, device monitoring, admin remote shell, ...)
//! - The LFO file server (downloading updates, uploading sample files for analysis, ...)
//!
//! You can also use this crate to act as a private TS (or LFO) server that receives and decodes live sensor events.
//! This requires disabling certificate validation in falcon-sensor, although as of version 13601
//! Falcon as a whole does no integrity checks, so that it happily runs with arbitrary patches applied.
//!
//! ## Notice
//!
//! Please note that this crate is a clean-room implementation based on observing sensor version 13601 talk to a private server in an isolated VM,
//! and on using this crate to replay a few sensor events and capturing the public TS service's replies.
//!
//! As a result, you should expect that this library **may not be a 100% conforming implementation**.
//! It may be missing some optional parts of the protocol, some of the reverse-engineered fields that
//! don't affect the result may lack names, and some might be named wrong entirely.
//!
//! ## What is the Crowdstrike CLOUDPROTO?
//!
//! The name "CLOUDPROTO" comes from a debug log message inside the falcon-sensor binary.
//!
//! Internally, falcon-sensor is architectured around Actors (C++ objects) that exchange Events (plain data) using an event bus.
//! The same events that falcon-sensor actors use internally are also used to communicate
//! with the TS cloud server by carrying serialized events within CLOUDPROTO frames.
//!
//! Events are first serialized with Protobuf and complemented by a short header that contains
//! the event type and a transaction ID.
//! This serialized event payload is sent over a CLOUDPROTO socket, which is itself wrapped
//! in a TLS session over TCP port 443.
//!
//! This crate provides the CLOUDPROTO socket layer that handles framing and the outer header,
//! and a higher level Event socket that takes care of ACK'ing cloud proto frames and turning them
//! into bare Event structs that contain the event type and the serialized Protobuf payload.
//!
//! We provide an EventType enum that tries to give a name to a few common events,
//! however the Protobuf schemas corresponding to the many types of event payloads are not part of this library.

pub mod framing;
pub mod services;

pub use framing::CloudProtoSocket;
