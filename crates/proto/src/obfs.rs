//! ChaCha8 UDP obfuscation for QUIC (random per-packet IV).
//! Masks QUIC headers from DPI only. It is not the primary crypto (QUIC/TLS is).
//! One server-wide secret is intentional (shared camouflage key, not per-connector crypto).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use chacha20::{
    ChaCha8,
    cipher::{KeyIvInit, StreamCipher},
};
use quinn::AsyncUdpSocket;
use quinn::udp::{self, RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Random IV prepended to each obfuscated UDP segment (bytes of wire overhead).
const IV_LEN: usize = 12;

/// Quinn MTU discovery upper bound reduced by [`IV_LEN`] so QUIC payload + IV
/// stays within a typical Ethernet path (IPv6: 1500 − 40 − 8 = 1452).
pub(crate) const MTU_DISCOVERY_UPPER_BOUND: u16 = 1452 - IV_LEN as u16;

/// Obfuscated UDP socket for QUIC
pub struct ObfuscatedSocket {
    inner: UdpSocket,
    udp_state: UdpSocketState,
    secret: [u8; 32],
}

thread_local! {
    static SEND_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(2048));
}

impl ObfuscatedSocket {
    /// Create a new obfuscated socket bound to the specified address
    pub fn bind(addr: SocketAddr, secret: [u8; 32]) -> io::Result<Self> {
        let std_socket = bind_std_udp_socket(addr)?;
        let udp_state = UdpSocketState::new(UdpSockRef::from(&std_socket))?;
        let socket = UdpSocket::from_std(std_socket)?;
        Ok(Self {
            inner: socket,
            udp_state,
            secret,
        })
    }
}

fn bind_std_udp_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if let SocketAddr::V6(v6_addr) = addr
        && v6_addr.ip().is_unspecified()
    {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(std::net::UdpSocket::from(socket))
}

fn effective_segment_size(transmit: &Transmit<'_>) -> usize {
    match transmit.segment_size {
        Some(size) if size > 0 && size < transmit.contents.len() => size,
        _ => transmit.contents.len().max(1),
    }
}

fn encode_transmit<'a>(
    transmit: &Transmit<'a>,
    secret: &[u8; 32],
    out: &'a mut Vec<u8>,
) -> Transmit<'a> {
    out.clear();
    // Never 0, so `div_ceil`/`chunks` cannot panic; empty contents yield no segments.
    let segment_size = effective_segment_size(transmit);
    let segment_count = transmit.contents.len().div_ceil(segment_size);
    out.reserve(transmit.contents.len() + IV_LEN * segment_count);

    for chunk in transmit.contents.chunks(segment_size) {
        let mut iv = [0u8; IV_LEN];
        rand::rng().fill_bytes(&mut iv);
        out.extend_from_slice(&iv);

        let start = out.len();
        out.extend_from_slice(chunk);
        let mut cipher = ChaCha8::new(&(*secret).into(), &iv.into());
        cipher.apply_keystream(&mut out[start..]);
    }

    Transmit {
        destination: transmit.destination,
        ecn: transmit.ecn,
        contents: out.as_slice(),
        segment_size: if segment_count > 1 {
            Some(segment_size + IV_LEN)
        } else {
            None
        },
        src_ip: transmit.src_ip,
    }
}

fn decrypt_meta_payload(buf: &mut [u8], meta: &mut RecvMeta, secret: &[u8; 32]) -> io::Result<()> {
    if meta.len == 0 || meta.stride <= IV_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "obfuscated datagram is too small",
        ));
    }

    let encrypted_len = meta.len;
    let encrypted_stride = meta.stride;
    let mut write_offset = 0usize;
    let mut segment_start = 0usize;

    while segment_start < encrypted_len {
        let segment_end = (segment_start + encrypted_stride).min(encrypted_len);
        let segment_len = segment_end - segment_start;
        if segment_len <= IV_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "obfuscated datagram segment is too small",
            ));
        }

        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&buf[segment_start..segment_start + IV_LEN]);

        let payload_len = segment_len - IV_LEN;
        buf.copy_within(segment_start + IV_LEN..segment_end, write_offset);

        let payload = &mut buf[write_offset..write_offset + payload_len];
        let mut cipher = ChaCha8::new(&(*secret).into(), &iv.into());
        cipher.apply_keystream(payload);

        write_offset += payload_len;
        segment_start += encrypted_stride;
    }

    meta.len = write_offset;
    meta.stride = encrypted_stride - IV_LEN;
    Ok(())
}

impl std::fmt::Debug for ObfuscatedSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfuscatedSocket")
            .field("local_addr", &self.inner.local_addr())
            .finish()
    }
}

impl AsyncUdpSocket for ObfuscatedSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(ObfuscatedPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        SEND_BUFFER.with(|cell| {
            let mut buf = cell.borrow_mut();
            let encoded = encode_transmit(transmit, &self.secret, &mut buf);
            self.inner.try_io(Interest::WRITABLE, || {
                self.udp_state.send(UdpSockRef::from(&self.inner), &encoded)
            })
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let max_packets = bufs.len().min(meta.len()).min(udp::BATCH_SIZE);
        if max_packets == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut udp_meta = [RecvMeta::default(); udp::BATCH_SIZE];

        // Same shape as quinn's own tokio socket: a failed `try_io` (WouldBlock) re-polls readiness.
        loop {
            ready!(self.inner.poll_recv_ready(cx))?;
            let Ok(packet_count) = self.inner.try_io(Interest::READABLE, || {
                self.udp_state.recv(
                    UdpSockRef::from(&self.inner),
                    &mut bufs[..max_packets],
                    &mut udp_meta[..max_packets],
                )
            }) else {
                continue;
            };

            let mut valid_count = 0usize;
            for index in 0..packet_count {
                if decrypt_meta_payload(&mut bufs[index], &mut udp_meta[index], &self.secret)
                    .is_ok()
                {
                    bufs.swap(valid_count, index);
                    udp_meta.swap(valid_count, index);
                    meta[valid_count] = udp_meta[valid_count];
                    valid_count += 1;
                }
            }
            if valid_count > 0 {
                return Poll::Ready(Ok(valid_count));
            }
            // At most one batch per poll: an all-garbage flood yields to the runtime
            // instead of tight-looping decrypt work inside one poll_recv.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.udp_state.max_gso_segments()
    }

    fn may_fragment(&self) -> bool {
        self.udp_state.may_fragment()
    }

    fn max_receive_segments(&self) -> usize {
        self.udp_state.gro_segments()
    }
}

#[derive(Debug)]
struct ObfuscatedPoller {
    socket: Arc<ObfuscatedSocket>,
}

impl quinn::UdpPoller for ObfuscatedPoller {
    fn poll_writable(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.inner.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

    #[test]
    fn encode_and_decrypt_single_segment_roundtrip() {
        let payload = b"hello over quic";
        let transmit = Transmit {
            destination: "127.0.0.1:443".parse().expect("socket addr should parse"),
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: None,
        };

        let mut encoded = Vec::new();
        let encoded_transmit = encode_transmit(&transmit, &TEST_SECRET, &mut encoded);
        let mut recv_buf = encoded_transmit.contents.to_vec();
        let mut meta = RecvMeta {
            addr: transmit.destination,
            len: recv_buf.len(),
            stride: recv_buf.len(),
            ..RecvMeta::default()
        };

        decrypt_meta_payload(&mut recv_buf, &mut meta, &TEST_SECRET)
            .expect("single segment should decrypt");

        assert_eq!(&recv_buf[..meta.len], payload);
        assert_eq!(meta.len, payload.len());
        assert_eq!(meta.stride, payload.len());
    }

    #[test]
    fn encode_and_decrypt_multi_segment_roundtrip() {
        let payload = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let transmit = Transmit {
            destination: "127.0.0.1:443".parse().expect("socket addr should parse"),
            ecn: None,
            contents: payload,
            segment_size: Some(10),
            src_ip: None,
        };

        let mut encoded = Vec::new();
        let encoded_transmit = encode_transmit(&transmit, &TEST_SECRET, &mut encoded);
        let mut recv_buf = encoded_transmit.contents.to_vec();
        let mut meta = RecvMeta {
            addr: transmit.destination,
            len: recv_buf.len(),
            stride: encoded_transmit
                .segment_size
                .expect("multi-segment transmit should keep a segment size"),
            ..RecvMeta::default()
        };

        decrypt_meta_payload(&mut recv_buf, &mut meta, &TEST_SECRET)
            .expect("multi-segment payload should decrypt");

        assert_eq!(&recv_buf[..meta.len], payload);
        assert_eq!(meta.len, payload.len());
        assert_eq!(meta.stride, 10);
    }

    #[test]
    fn decrypt_rejects_too_small_segments() {
        let mut recv_buf = vec![0u8; IV_LEN];
        let mut meta = RecvMeta {
            addr: "127.0.0.1:443".parse().expect("socket addr should parse"),
            len: IV_LEN,
            stride: IV_LEN,
            ..RecvMeta::default()
        };

        assert!(decrypt_meta_payload(&mut recv_buf, &mut meta, &TEST_SECRET).is_err());
    }

    #[test]
    fn encode_empty_and_zero_segment_size_do_not_panic() {
        let empty = Transmit {
            destination: "127.0.0.1:443".parse().expect("socket addr should parse"),
            ecn: None,
            contents: b"",
            segment_size: None,
            src_ip: None,
        };
        let mut encoded = Vec::new();
        let out = encode_transmit(&empty, &TEST_SECRET, &mut encoded);
        assert!(out.contents.is_empty());
        assert!(out.segment_size.is_none());

        let zero_seg = Transmit {
            destination: empty.destination,
            ecn: None,
            contents: b"payload",
            segment_size: Some(0),
            src_ip: None,
        };
        let out = encode_transmit(&zero_seg, &TEST_SECRET, &mut encoded);
        assert_eq!(out.contents.len(), b"payload".len() + IV_LEN);
        assert!(out.segment_size.is_none());
    }
}
