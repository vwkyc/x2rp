//! Tunnel protocol between the x2rp server and its connectors, plus the host
//! helpers both binaries share.
//!
//! - QUIC: the connector's first stream carries one `Auth` frame. The server then
//!   opens a bidi stream per tunnel: a `Connect` frame, a `ConnectOk`/`ConnectErr`
//!   frame back, then raw bytes both ways. Frames are `[u32 BE body_len][body]`.
//!   Liveness is QUIC's own keep-alive and idle timeout.
//! - WSS: every binary message is one body. Tunnels are muxed as `Data`, with
//!   per-stream `WindowUpdate` credit. Liveness is WebSocket ping/pong.
//!   `Close` from the server is request EOF (half-close the backend); from the
//!   connector it ends the stream. `Reset` aborts it at once.

use bytes::{Buf, Bytes};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

mod host;
pub mod obfs;
pub mod ssrf;

pub use host::*;

/// ALPN protocol identifier for the QUIC tunnel.
pub const ALPN: &[u8] = b"x2rp-tunnel";

/// Max concurrent tunnels per connector session.
pub const MAX_ACTIVE_STREAMS: usize = 128;

/// WSS mux per-stream flow-control window (256 KiB in flight per direction), and the
/// QUIC per-stream receive window.
pub const STREAM_RECV_WINDOW: usize = 256 * 1024;

/// Threshold to grant drained bytes back (half a window).
pub const WINDOW_UPDATE_THRESHOLD: usize = STREAM_RECV_WINDOW / 2;

/// Shared connector↔transport message channel depth.
pub const CONNECTOR_CHANNEL_CAPACITY: usize = 64;

/// Max concurrent authenticated connector sessions per transport.
pub const MAX_CONNECTOR_SESSIONS: usize = 64;

/// Read chunk size for tunnel pumps.
pub const TUNNEL_READ_CHUNK: usize = 32 * 1024;

/// Maximum allowed size for a single Data message payload.
pub const MAX_DATA_PAYLOAD_LEN: usize = 128 * 1024;

/// Max Connect `target` string.
pub const MAX_CONNECT_TARGET_LEN: usize = 2048;

/// Max ConnectErr `error` string; longer errors are truncated.
pub const MAX_CONNECT_ERR_LEN: usize = 1024;

/// Max Auth token string length (connector bearer material).
pub const MAX_AUTH_TOKEN_LEN: usize = 512;

/// WSS ping interval.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// A peer silent this long is dead (WSS read timeout, QUIC idle timeout).
pub const HEARTBEAT_READ_TIMEOUT_SECS: u64 = 30;

/// Largest WSS message body: a Data message (type + stream_id + len + payload).
pub const MAX_MESSAGE_BODY_LEN: usize = MAX_DATA_PAYLOAD_LEN + 9;

/// Largest QUIC frame body: a `Connect` at the target cap (type + stream_id + len + target).
const MAX_FRAME_BODY_LEN: usize = MAX_CONNECT_TARGET_LEN + 7;

/// Wire type byte of each [`Message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum MessageType {
    Connect = 0x01,
    ConnectOk = 0x02,
    ConnectErr = 0x03,
    Data = 0x10,
    Close = 0x20,
    Reset = 0x21,
    WindowUpdate = 0x22,
    Auth = 0x40,
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => Self::Connect,
            0x02 => Self::ConnectOk,
            0x03 => Self::ConnectErr,
            0x10 => Self::Data,
            0x20 => Self::Close,
            0x21 => Self::Reset,
            0x22 => Self::WindowUpdate,
            0x40 => Self::Auth,
            _ => return Err(bad("unknown message type")),
        })
    }
}

/// A connector protocol message (semantics: module docs).
#[derive(Clone)]
pub enum Message {
    Connect {
        stream_id: u32,
        target: String,
    },
    ConnectOk {
        stream_id: u32,
    },
    ConnectErr {
        stream_id: u32,
        error: String,
    },
    Data {
        stream_id: u32,
        payload: Bytes,
    },
    Close {
        stream_id: u32,
    },
    Reset {
        stream_id: u32,
    },
    /// Grant `bytes` more send credit for `stream_id`.
    WindowUpdate {
        stream_id: u32,
        bytes: u32,
    },
    Auth {
        token: String,
    },
}

/// Hand-written because every `Debug` line can reach a log: a derive would print
/// the bearer token and the payload bytes.
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect { stream_id, target } => {
                write!(
                    f,
                    "Connect {{ stream_id: {stream_id}, target: {target:?} }}"
                )
            }
            Self::ConnectOk { stream_id } => write!(f, "ConnectOk {{ stream_id: {stream_id} }}"),
            Self::ConnectErr { stream_id, error } => {
                write!(
                    f,
                    "ConnectErr {{ stream_id: {stream_id}, error: {error:?} }}"
                )
            }
            Self::Data { stream_id, payload } => {
                let len = payload.len();
                write!(f, "Data {{ stream_id: {stream_id}, payload_len: {len} }}")
            }
            Self::Close { stream_id } => write!(f, "Close {{ stream_id: {stream_id} }}"),
            Self::Reset { stream_id } => write!(f, "Reset {{ stream_id: {stream_id} }}"),
            Self::WindowUpdate { stream_id, bytes } => {
                write!(
                    f,
                    "WindowUpdate {{ stream_id: {stream_id}, bytes: {bytes} }}"
                )
            }
            Self::Auth { .. } => f.write_str("Auth { token: \"[redacted]\" }"),
        }
    }
}

fn bad(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// `[u16 BE len][utf-8]`, refusing anything over `max` (or empty, when `min` is 1).
fn put_str(buf: &mut Vec<u8>, s: &str, min: usize, max: usize) -> io::Result<()> {
    if !(min..=max).contains(&s.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("string length {} outside {min}..={max}", s.len()),
        ));
    }
    buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

fn get_u32(buf: &mut Bytes) -> io::Result<u32> {
    (buf.remaining() >= 4)
        .then(|| buf.get_u32())
        .ok_or_else(|| bad("message truncated"))
}

fn get_str(buf: &mut Bytes, min: usize, max: usize) -> io::Result<String> {
    if buf.remaining() < 2 {
        return Err(bad("message truncated"));
    }
    let len = buf.get_u16() as usize;
    if !(min..=max).contains(&len) || buf.remaining() < len {
        return Err(bad(format!("string length {len} invalid")));
    }
    // `Bytes → Vec` may reclaim storage; `String::from_utf8` does not copy on success.
    String::from_utf8(buf.split_to(len).into()).map_err(bad)
}

impl Message {
    fn encode_into(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        let (kind, stream_id) = match self {
            Self::Connect { stream_id, .. } => (MessageType::Connect, Some(stream_id)),
            Self::ConnectOk { stream_id } => (MessageType::ConnectOk, Some(stream_id)),
            Self::ConnectErr { stream_id, .. } => (MessageType::ConnectErr, Some(stream_id)),
            Self::Data { stream_id, .. } => (MessageType::Data, Some(stream_id)),
            Self::Close { stream_id } => (MessageType::Close, Some(stream_id)),
            Self::Reset { stream_id } => (MessageType::Reset, Some(stream_id)),
            Self::WindowUpdate { stream_id, .. } => (MessageType::WindowUpdate, Some(stream_id)),
            Self::Auth { .. } => (MessageType::Auth, None),
        };
        buf.push(kind as u8);
        if let Some(stream_id) = stream_id {
            buf.extend_from_slice(&stream_id.to_be_bytes());
        }
        match self {
            Self::Connect { target, .. } => put_str(buf, target, 0, MAX_CONNECT_TARGET_LEN),
            Self::ConnectErr { error, .. } => {
                let error = &error[..error.floor_char_boundary(MAX_CONNECT_ERR_LEN)];
                put_str(buf, error, 0, MAX_CONNECT_ERR_LEN)
            }
            Self::Auth { token } => put_str(buf, token, 1, MAX_AUTH_TOKEN_LEN),
            Self::Data { payload, .. } => {
                if payload.len() > MAX_DATA_PAYLOAD_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("data payload too large: {} bytes", payload.len()),
                    ));
                }
                buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                buf.extend_from_slice(payload);
                Ok(())
            }
            Self::WindowUpdate { bytes, .. } => {
                buf.extend_from_slice(&bytes.to_be_bytes());
                Ok(())
            }
            Self::ConnectOk { .. } | Self::Close { .. } | Self::Reset { .. } => Ok(()),
        }
    }

    /// The message body: one WebSocket binary message.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// `[u32 BE body_len][body]`: one frame on a QUIC stream.
    pub fn frame(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0; 4];
        self.encode_into(&mut buf)?;
        let body_len = (buf.len() - 4) as u32;
        buf[..4].copy_from_slice(&body_len.to_be_bytes());
        Ok(buf)
    }

    /// Decode a message body.
    pub fn decode(mut buf: Bytes) -> io::Result<Self> {
        if buf.is_empty() {
            return Err(bad("empty message"));
        }
        let msg = match MessageType::try_from(buf.get_u8())? {
            MessageType::Connect => Self::Connect {
                stream_id: get_u32(&mut buf)?,
                target: get_str(&mut buf, 0, MAX_CONNECT_TARGET_LEN)?,
            },
            MessageType::ConnectOk => Self::ConnectOk {
                stream_id: get_u32(&mut buf)?,
            },
            MessageType::ConnectErr => Self::ConnectErr {
                stream_id: get_u32(&mut buf)?,
                error: get_str(&mut buf, 0, MAX_CONNECT_ERR_LEN)?,
            },
            MessageType::Data => {
                let stream_id = get_u32(&mut buf)?;
                let len = get_u32(&mut buf)? as usize;
                if len > MAX_DATA_PAYLOAD_LEN || buf.remaining() < len {
                    return Err(bad(format!("data payload length {len} invalid")));
                }
                Self::Data {
                    stream_id,
                    payload: buf.split_to(len),
                }
            }
            MessageType::Close => Self::Close {
                stream_id: get_u32(&mut buf)?,
            },
            MessageType::Reset => Self::Reset {
                stream_id: get_u32(&mut buf)?,
            },
            MessageType::WindowUpdate => Self::WindowUpdate {
                stream_id: get_u32(&mut buf)?,
                bytes: get_u32(&mut buf)?,
            },
            MessageType::Auth => Self::Auth {
                token: get_str(&mut buf, 1, MAX_AUTH_TOKEN_LEN)?,
            },
        };
        if buf.has_remaining() {
            return Err(bad("trailing bytes after message"));
        }
        Ok(msg)
    }
}

/// Read one frame from a QUIC stream. Only control messages travel as frames, so the
/// length cap stays small even before the peer has authenticated.
pub async fn read_frame(recv: &mut quinn::RecvStream) -> io::Result<Message> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(io::Error::other)?;
    let len = u32::from_be_bytes(len) as usize;
    if !(1..=MAX_FRAME_BODY_LEN).contains(&len) {
        return Err(bad(format!("invalid frame length {len}")));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.map_err(io::Error::other)?;
    Message::decode(body.into())
}

/// QUIC transport settings both ends share.
pub fn quic_transport_config() -> quinn::TransportConfig {
    use quinn::VarInt;
    // Leave room for the obfuscation IV after Quinn sizes each packet.
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(obfs::MTU_DISCOVERY_UPPER_BOUND);
    let mut config = quinn::TransportConfig::default();
    config
        // Frequent enough to hold NAT bindings open.
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            VarInt::from_u32(HEARTBEAT_READ_TIMEOUT_SECS as u32 * 1000).into(),
        ))
        .receive_window(VarInt::from_u32(1024 * 1024))
        .stream_receive_window(VarInt::from_u32(STREAM_RECV_WINDOW as u32))
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_ACTIVE_STREAMS as u32))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .mtu_discovery_config(Some(mtu));
    config
}

/// Per-stream send-side flow-control credit for the WSS mux.
///
/// The Data sender calls [`SendCredit::acquire`] before each chunk and parks at
/// zero credit; the peer's drain loop replenishes via [`SendCredit::add`] when a
/// [`Message::WindowUpdate`] arrives. [`SendCredit::close`] wakes any parked
/// sender permanently (stream torn down) so no task can leak waiting on credit.
pub struct SendCredit {
    credit: AtomicI64,
    /// Ceiling for outstanding credit (= initial window). Caps malicious WindowUpdate grants.
    max: i64,
    closed: AtomicBool,
    notify: tokio::sync::Notify,
}

impl SendCredit {
    pub fn new(initial: usize) -> Self {
        Self {
            credit: AtomicI64::new(initial as i64),
            max: initial as i64,
            closed: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Grant `bytes` more credit and wake a parked sender.
    /// Outstanding credit never exceeds the initial window.
    pub fn add(&self, bytes: usize) {
        let _ = self
            .credit
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                let next = cur.saturating_add(bytes as i64).min(self.max);
                (next > cur).then_some(next)
            });
        self.notify.notify_waiters();
    }

    /// Permanently close: any current or future `acquire` returns `false`.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Reserve `bytes` of credit, waiting for grants if needed.
    /// Returns `false` once closed. `bytes` must be ≤ the initial window or
    /// this can park forever against an honest peer.
    pub async fn acquire(&self, bytes: usize) -> bool {
        let need = bytes as i64;
        loop {
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            if self
                .credit
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                    (cur >= need).then(|| cur - need)
                })
                .is_ok()
            {
                return true;
            }
            // Register the waiter before re-checking so an add()/close() between the
            // check and the await cannot be missed (tokio Notify contract).
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.closed.load(Ordering::Acquire) && self.credit.load(Ordering::Acquire) < need {
                notified.await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn encode_body(msg: &Message) -> Bytes {
        Bytes::from(msg.encode().expect("encode"))
    }

    #[test]
    fn every_message_roundtrips() {
        for msg in [
            Message::Connect {
                stream_id: 1,
                target: "http://127.0.0.1:9".into(),
            },
            Message::ConnectOk { stream_id: 2 },
            Message::ConnectErr {
                stream_id: 3,
                error: "refused".into(),
            },
            Message::Data {
                stream_id: 4,
                payload: Bytes::from_static(b"body"),
            },
            Message::Close { stream_id: 5 },
            Message::Reset { stream_id: 6 },
            Message::WindowUpdate {
                stream_id: 7,
                bytes: 262_144,
            },
            Message::Auth {
                token: "secret-token".into(),
            },
        ] {
            let decoded = Message::decode(encode_body(&msg)).expect("decode");
            assert_eq!(format!("{decoded:?}"), format!("{msg:?}"));
        }
    }

    #[test]
    fn frame_prefixes_the_body_length() {
        let frame = Message::Reset { stream_id: 9 }.frame().expect("frame");
        assert_eq!(&frame[..5], &[0, 0, 0, 5, MessageType::Reset as u8]);
    }

    #[test]
    fn debug_never_leaks_tokens_or_payloads() {
        let auth = format!(
            "{:?}",
            Message::Auth {
                token: "s3cret".into()
            }
        );
        let data = format!(
            "{:?}",
            Message::Data {
                stream_id: 3,
                payload: Bytes::from_static(b"s3cret")
            }
        );
        assert!(!auth.contains("s3cret"), "{auth}");
        assert!(
            !data.contains("s3cret") && data.contains("payload_len"),
            "{data}"
        );
    }

    #[test]
    fn decode_rejects_malformed_bodies() {
        let mut trailer = encode_body(&Message::Reset { stream_id: 1 }).to_vec();
        trailer.push(0);
        let err = Message::decode(Bytes::from(trailer)).expect_err("trailing bytes");
        assert!(err.to_string().contains("trailing bytes"));

        let window = encode_body(&Message::WindowUpdate {
            stream_id: 1,
            bytes: 1,
        });
        assert!(Message::decode(window.slice(..8)).is_err(), "truncated");
    }

    #[test]
    fn string_fields_are_length_capped() {
        let ok = Message::Connect {
            stream_id: 1,
            target: "a".repeat(MAX_CONNECT_TARGET_LEN),
        };
        Message::decode(encode_body(&ok)).expect("max target should decode");

        for too_long in [
            Message::Connect {
                stream_id: 1,
                target: "a".repeat(MAX_CONNECT_TARGET_LEN + 1),
            },
            Message::Auth {
                token: String::new(),
            },
        ] {
            assert!(too_long.encode().is_err(), "{too_long:?}");
        }

        // An error string is diagnostics: over-long ones are cut, never refused.
        let long_err = Message::ConnectErr {
            stream_id: 1,
            error: "é".repeat(MAX_CONNECT_ERR_LEN),
        };
        match Message::decode(encode_body(&long_err)).expect("truncated error encodes") {
            Message::ConnectErr { error, .. } => assert!(error.len() <= MAX_CONNECT_ERR_LEN),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn send_credit_parks_until_granted_and_unblocks_on_close() {
        let credit = Arc::new(SendCredit::new(10));
        credit.add(1_000_000); // must not inflate past the window
        assert!(credit.acquire(10).await, "initial window should satisfy");

        let waiter = {
            let credit = credit.clone();
            tokio::spawn(async move { credit.acquire(5).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "must park at zero credit");
        credit.add(5);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("grant must wake the waiter")
                .expect("join")
        );

        let parked = {
            let credit = credit.clone();
            tokio::spawn(async move { credit.acquire(1).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        credit.close();
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), parked)
                .await
                .expect("close must wake the waiter")
                .expect("join")
        );
        assert!(!credit.acquire(1).await);
    }
}
