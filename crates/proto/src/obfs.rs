//! ChaCha8 UDP obfuscation for QUIC (random per-packet IV).
//! Masks QUIC headers from DPI only; primary crypto is QUIC/TLS.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use chacha20::{
    ChaCha8,
    cipher::{KeyIvInit, StreamCipher},
};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};

const IV_LEN: usize = 12;

/// Quinn MTU discovery upper bound reduced by [`IV_LEN`] so QUIC + IV fits Ethernet (1452B).
pub(crate) const MTU_DISCOVERY_UPPER_BOUND: u16 = 1452 - IV_LEN as u16;

pub struct ObfuscatedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    secret: [u8; 32],
}

thread_local! {
    static SEND_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(2048));
}

impl ObfuscatedSocket {
    pub fn bind(addr: SocketAddr, secret: [u8; 32]) -> io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if let SocketAddr::V6(v6) = addr
            && v6.ip().is_unspecified()
        {
            socket.set_only_v6(false)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        Ok(Self {
            inner: TokioRuntime.wrap_udp_socket(std::net::UdpSocket::from(socket))?,
            secret,
        })
    }
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
    let segment_size = effective_segment_size(transmit);
    let segment_count = transmit.contents.len().div_ceil(segment_size);
    out.reserve(transmit.contents.len() + IV_LEN * segment_count);

    for chunk in transmit.contents.chunks(segment_size) {
        let mut iv = [0u8; IV_LEN];
        rand::rng().fill_bytes(&mut iv);
        out.extend_from_slice(&iv);

        let start = out.len();
        out.extend_from_slice(chunk);
        ChaCha8::new(&(*secret).into(), &iv.into()).apply_keystream(&mut out[start..]);
    }

    Transmit {
        destination: transmit.destination,
        ecn: transmit.ecn,
        contents: out.as_slice(),
        segment_size: (segment_count > 1).then_some(segment_size + IV_LEN),
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
        ChaCha8::new(&(*secret).into(), &iv.into())
            .apply_keystream(&mut buf[write_offset..write_offset + payload_len]);

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
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        SEND_BUFFER.with(|cell| {
            let mut buf = cell.borrow_mut();
            let encoded = encode_transmit(transmit, &self.secret, &mut buf);
            self.inner.try_send(&encoded)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let max_packets = bufs.len().min(meta.len());
        if max_packets == 0 {
            return Poll::Ready(Ok(0));
        }
        let packet_count = ready!(self.inner.poll_recv(
            cx,
            &mut bufs[..max_packets],
            &mut meta[..max_packets]
        ))?;
        let mut valid_count = 0usize;
        for index in 0..packet_count {
            if decrypt_meta_payload(&mut bufs[index], &mut meta[index], &self.secret).is_ok() {
                bufs.swap(valid_count, index);
                meta.swap(valid_count, index);
                valid_count += 1;
            }
        }
        if valid_count > 0 {
            return Poll::Ready(Ok(valid_count));
        }
        // Yield after an all-garbage batch so a flood cannot monopolize one poll.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
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
