//! Bounded MessagePack frames over Linux/Android Unix sequenced-packet sockets.
//!
//! The codec validates individual messages. Request sequencing, response correlation,
//! capability checks, and cumulative session quotas belong to the host/runner.

use serde::{Deserialize, Serialize};
use std::io::{self, Cursor};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

pub const HEADER_SIZE: usize = 16;
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
pub const MAX_SOURCE_SIZE: usize = 48 * 1024;
pub const MAX_MEMORY_TRANSFER: usize = 16 * 1024;
pub const MAX_RESULTS: usize = 1024;
const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRange {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub private: bool,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub source: String,
    pub script_name: String,
    pub timeout_ms: u64,
    pub memory_limit_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    SandboxReady { mode: String },
    Log { message: String },
    GetRanges,
    ReadMemory { address: u64, len: u32 },
    WriteMemory { address: u64, data: Vec<u8> },
    ScanI32 { value: i32 },
    RefineI32 { value: i32 },
    GetResults { limit: u32 },
    WriteResultsI32 { value: i32 },
    Finished { error: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Response {
    Ok,
    Ranges { ranges: Vec<MemoryRange> },
    Bytes { data: Vec<u8> },
    ScanCount { count: u32 },
    Results { addresses: Vec<u64> },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Bootstrap(Bootstrap),
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub request_id: u32,
    pub message: Message,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IPC I/O: {0}")]
    Io(#[from] io::Error),
    #[error("invalid frame: {0}")]
    InvalidFrame(&'static str),
    #[error("message exceeds limit: {0}")]
    LimitExceeded(&'static str),
    #[error("MessagePack encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("MessagePack decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

fn kind(message: &Message) -> u8 {
    match message {
        Message::Bootstrap(_) => 1,
        Message::Request(_) => 2,
        Message::Response(_) => 3,
    }
}

fn validate(packet: &Packet) -> Result<(), ProtocolError> {
    let limit = match &packet.message {
        Message::Bootstrap(b) if b.source.len() > MAX_SOURCE_SIZE => Some("source"),
        Message::Request(Request::ReadMemory { len, .. })
            if *len as usize > MAX_MEMORY_TRANSFER =>
        {
            Some("memory read")
        }
        Message::Request(Request::WriteMemory { data, .. }) if data.len() > MAX_MEMORY_TRANSFER => {
            Some("memory write")
        }
        Message::Request(Request::GetResults { limit }) if *limit as usize > MAX_RESULTS => {
            Some("result count")
        }
        Message::Response(Response::Bytes { data }) if data.len() > MAX_MEMORY_TRANSFER => {
            Some("memory response")
        }
        Message::Response(Response::Results { addresses }) if addresses.len() > MAX_RESULTS => {
            Some("result count")
        }
        _ => None,
    };
    if let Some(limit) = limit {
        return Err(ProtocolError::LimitExceeded(limit));
    }
    if (kind(&packet.message) == 1) != (packet.request_id == 0) {
        return Err(ProtocolError::InvalidFrame(
            "bootstrap requires ID 0; requests/responses require nonzero IDs",
        ));
    }
    Ok(())
}

/// Encode one complete frame, including its fixed little-endian header.
pub fn encode_packet(packet: &Packet) -> Result<Vec<u8>, ProtocolError> {
    validate(packet)?;
    let payload = rmp_serde::to_vec(&packet.message)?;
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ProtocolError::LimitExceeded("payload"));
    }
    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    frame.extend_from_slice(b"KSME");
    frame.extend_from_slice(&[1, kind(&packet.message), 0, 0]);
    frame.extend_from_slice(&packet.request_id.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode exactly one complete frame; extra frame or MessagePack bytes are errors.
pub fn decode_packet(frame: &[u8]) -> Result<Packet, ProtocolError> {
    if frame.len() < HEADER_SIZE {
        return Err(ProtocolError::InvalidFrame("truncated header"));
    }
    if &frame[..4] != b"KSME" {
        return Err(ProtocolError::InvalidFrame("magic"));
    }
    if frame[4] != 1 {
        return Err(ProtocolError::InvalidFrame("version"));
    }
    if !(1..=3).contains(&frame[5]) {
        return Err(ProtocolError::InvalidFrame("kind"));
    }
    if frame[6..8] != [0, 0] {
        return Err(ProtocolError::InvalidFrame("flags"));
    }
    let request_id = u32::from_le_bytes(frame[8..12].try_into().unwrap());
    let payload_len = u32::from_le_bytes(frame[12..16].try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(ProtocolError::LimitExceeded("payload"));
    }
    if frame.len() != HEADER_SIZE + payload_len {
        return Err(ProtocolError::InvalidFrame(
            "payload length or trailing frame bytes",
        ));
    }
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(&frame[HEADER_SIZE..]));
    let message = Message::deserialize(&mut deserializer)?;
    if deserializer.position() != payload_len as u64 {
        return Err(ProtocolError::InvalidFrame("trailing MessagePack bytes"));
    }
    if kind(&message) != frame[5] {
        return Err(ProtocolError::InvalidFrame("message kind mismatch"));
    }
    let packet = Packet {
        request_id,
        message,
    };
    validate(&packet)?;
    Ok(packet)
}

#[derive(Debug)]
pub struct SeqPacket {
    fd: OwnedFd,
}

impl AsRawFd for SeqPacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl SeqPacket {
    pub fn pair() -> io::Result<(Self, Self)> {
        let mut fds = [-1; 2];
        loop {
            // SAFETY: fds points to two writable descriptor slots.
            let result = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            if result == 0 {
                // SAFETY: socketpair returned two new owned descriptors.
                return Ok(unsafe {
                    (
                        Self::from_owned_fd(OwnedFd::from_raw_fd(fds[0])),
                        Self::from_owned_fd(OwnedFd::from_raw_fd(fds[1])),
                    )
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Adopt an already connected SOCK_SEQPACKET descriptor.
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    pub fn send(&self, packet: &Packet) -> Result<(), ProtocolError> {
        let frame = encode_packet(packet)?;
        loop {
            // SAFETY: frame is live and readable for its full length.
            let sent = unsafe {
                libc::send(
                    self.as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent >= 0 {
                if sent as usize != frame.len() {
                    return Err(ProtocolError::InvalidFrame("short sequenced-packet send"));
                }
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }

    pub fn recv(&self) -> Result<Option<Packet>, ProtocolError> {
        self.recv_with_control_words(32)
    }

    fn recv_with_control_words(&self, words: usize) -> Result<Option<Packet>, ProtocolError> {
        let mut frame = vec![0u8; MAX_FRAME_SIZE];
        // usize storage gives cmsghdr the alignment required by CMSG_*.
        let mut control = vec![0usize; words];
        loop {
            let mut iov = libc::iovec {
                iov_base: frame.as_mut_ptr().cast(),
                iov_len: frame.len(),
            };
            // SAFETY: zero is a valid initial msghdr (all pointers initially null).
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(control.as_slice());
            // SAFETY: all buffers referenced by msg are writable and remain live.
            let received =
                unsafe { libc::recvmsg(self.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            // Close any delivered SCM_RIGHTS descriptors even when data/control was
            // truncated. Linux closes descriptors that did not fit the control buffer.
            close_received_rights(&msg);
            if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                return Err(ProtocolError::InvalidFrame("truncated ancillary data"));
            }
            if msg.msg_controllen != 0 {
                return Err(ProtocolError::InvalidFrame("ancillary data is forbidden"));
            }
            if msg.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(ProtocolError::InvalidFrame("truncated packet"));
            }
            if received == 0 {
                return Ok(None);
            }
            return decode_packet(&frame[..received as usize]).map(Some);
        }
    }

    /// Set a positive receive timeout, rounded up to microseconds. Expiration is
    /// reported as ProtocolError::Io with WouldBlock/TimedOut from the OS.
    pub fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout must be positive",
            ));
        }
        let micros = timeout.as_micros() + u128::from(timeout.subsec_nanos() % 1000 != 0);
        let seconds = (micros / 1_000_000)
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timeout is too large"))?;
        let tv = libc::timeval {
            tv_sec: seconds,
            tv_usec: (micros % 1_000_000) as _,
        };
        loop {
            // SAFETY: tv is a valid timeval and its size is passed exactly.
            let result = unsafe {
                libc::setsockopt(
                    self.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&tv as *const libc::timeval).cast(),
                    std::mem::size_of_val(&tv) as libc::socklen_t,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn close_received_rights(msg: &libc::msghdr) {
    // SAFETY: msg came from successful recvmsg; CMSG iteration stays within its
    // kernel-populated control buffer. SCM_RIGHTS payloads are arrays of raw fds.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(msg);
        while !header.is_null() {
            let cmsg = &*header;
            if cmsg.cmsg_level == libc::SOL_SOCKET && cmsg.cmsg_type == libc::SCM_RIGHTS {
                let header_len = libc::CMSG_LEN(0) as usize;
                let count = (cmsg.cmsg_len as usize).saturating_sub(header_len)
                    / std::mem::size_of::<RawFd>();
                for index in 0..count {
                    let fd = libc::CMSG_DATA(header)
                        .cast::<RawFd>()
                        .add(index)
                        .read_unaligned();
                    // Do not retry close on EINTR: Linux has already released fd.
                    libc::close(fd);
                }
            }
            header = libc::CMSG_NXTHDR(msg, header);
        }
    }
}

#[cfg(test)]
mod tests;
