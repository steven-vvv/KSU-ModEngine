use super::*;

fn request(request: Request) -> Packet {
    Packet { request_id: 1, message: Message::Request(request) }
}

fn raw_frame(message: &Message, request_id: u32) -> Vec<u8> {
    let payload = rmp_serde::to_vec(message).unwrap();
    let mut frame = b"KSME".to_vec();
    frame.extend_from_slice(&[1, kind(message), 0, 0]);
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn send_raw(socket: &SeqPacket, bytes: &[u8]) {
    // SAFETY: bytes points to a live buffer of the given length.
    let result = unsafe {
        libc::send(socket.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL)
    };
    assert_eq!(result, bytes.len() as isize);
}

#[test]
fn all_message_variants_round_trip() {
    let requests = [
        Request::SandboxReady { mode: "development".into() },
        Request::Log { message: "你好".into() }, Request::GetRanges,
        Request::ReadMemory { address: u64::MAX, len: 16 },
        Request::WriteMemory { address: 0x123456789, data: vec![0, 255] },
        Request::ScanI32 { value: i32::MIN }, Request::RefineI32 { value: i32::MAX },
        Request::GetResults { limit: 1024 }, Request::WriteResultsI32 { value: -1 },
        Request::Finished { error: None }, Request::Finished { error: Some("failure".into()) },
    ];
    let mut packets: Vec<_> = requests.into_iter().map(request).collect();
    let responses = [
        Response::Ok,
        Response::Ranges { ranges: vec![MemoryRange { start: 0x1000, end: 0x2000,
            readable: true, writable: true, executable: false, private: true, name: None }] },
        Response::Bytes { data: vec![0, 1, 255] }, Response::ScanCount { count: 1024 },
        Response::Results { addresses: vec![u64::MAX] },
        Response::Error { code: "denied".into(), message: "no grant".into() },
    ];
    packets.extend(responses.into_iter().map(|response| Packet {
        request_id: 7, message: Message::Response(response),
    }));
    packets.push(Packet { request_id: 0, message: Message::Bootstrap(Bootstrap {
        source: "engine.log('hello')".into(), script_name: "test.lua".into(),
        timeout_ms: 2000, memory_limit_bytes: 64 * 1024 * 1024,
    }) });
    for packet in packets {
        let frame = encode_packet(&packet).unwrap();
        assert_eq!(&frame[..4], b"KSME");
        assert_eq!(decode_packet(&frame).unwrap(), packet);
    }
}

#[test]
fn rejects_header_mutations() {
    let valid = encode_packet(&request(Request::GetRanges)).unwrap();
    for (offset, value) in [(0, b'X'), (4, 0), (4, 2), (5, 0), (5, 4), (6, 1), (7, 1)] {
        let mut frame = valid.clone();
        frame[offset] = value;
        assert!(matches!(decode_packet(&frame), Err(ProtocolError::InvalidFrame(_))));
    }
    let mut mismatch = valid;
    mismatch[5] = 3;
    assert!(matches!(decode_packet(&mismatch), Err(ProtocolError::InvalidFrame("message kind mismatch"))));
}

#[test]
fn rejects_all_truncations_and_trailing_bytes() {
    let frame = encode_packet(&request(Request::ReadMemory { address: 7, len: 5 })).unwrap();
    for end in 0..frame.len() {
        assert!(decode_packet(&frame[..end]).is_err(), "accepted prefix {end}");
    }
    let mut extra = frame.clone();
    extra.push(0xc0);
    assert!(decode_packet(&extra).is_err());
    // Keep the frame length correct but append another valid MessagePack object.
    let length = (extra.len() - HEADER_SIZE) as u32;
    extra[12..16].copy_from_slice(&length.to_le_bytes());
    assert!(matches!(decode_packet(&extra), Err(ProtocolError::InvalidFrame("trailing MessagePack bytes"))));
    let mut oversize = frame;
    oversize[12..16].copy_from_slice(&((MAX_PAYLOAD_SIZE + 1) as u32).to_le_bytes());
    assert!(matches!(decode_packet(&oversize), Err(ProtocolError::LimitExceeded("payload"))));
}

#[test]
fn rejects_malformed_messagepack_and_invalid_ids() {
    let mut frame = encode_packet(&request(Request::GetRanges)).unwrap();
    frame.truncate(HEADER_SIZE);
    frame[12..16].copy_from_slice(&1u32.to_le_bytes());
    frame.push(0xc1); // Reserved MessagePack marker.
    assert!(decode_packet(&frame).is_err());
    let message = Message::Request(Request::GetRanges);
    assert!(decode_packet(&raw_frame(&message, 0)).is_err());
    assert!(encode_packet(&Packet { request_id: 0, message }).is_err());
}

#[test]
fn enforces_limits_on_encode_and_untrusted_decode() {
    let messages = [
        Message::Request(Request::ReadMemory { address: 0, len: MAX_MEMORY_TRANSFER as u32 + 1 }),
        Message::Request(Request::WriteMemory { address: 0, data: vec![0; MAX_MEMORY_TRANSFER + 1] }),
        Message::Request(Request::GetResults { limit: MAX_RESULTS as u32 + 1 }),
        Message::Response(Response::Bytes { data: vec![0; MAX_MEMORY_TRANSFER + 1] }),
        Message::Response(Response::Results { addresses: vec![0; MAX_RESULTS + 1] }),
    ];
    for message in messages {
        assert!(matches!(decode_packet(&raw_frame(&message, 1)), Err(ProtocolError::LimitExceeded(_))));
        assert!(matches!(encode_packet(&Packet { request_id: 1, message }), Err(ProtocolError::LimitExceeded(_))));
    }
    let message = Message::Bootstrap(Bootstrap { source: "x".repeat(MAX_SOURCE_SIZE + 1),
        script_name: "test".into(), timeout_ms: 2000, memory_limit_bytes: 100 });
    assert!(decode_packet(&raw_frame(&message, 0)).is_err());
    assert!(encode_packet(&Packet { request_id: 0, message }).is_err());
    assert!(encode_packet(&request(Request::Log { message: "x".repeat(MAX_PAYLOAD_SIZE) })).is_err());
    for req in [Request::ReadMemory { address: 0, len: MAX_MEMORY_TRANSFER as u32 },
        Request::WriteMemory { address: 0, data: vec![255; MAX_MEMORY_TRANSFER] },
        Request::GetResults { limit: MAX_RESULTS as u32 }] {
        let packet = request(req);
        assert_eq!(decode_packet(&encode_packet(&packet).unwrap()).unwrap(), packet);
    }
}

#[test]
fn transport_preserves_packets_and_reports_eof() {
    let (a, b) = SeqPacket::pair().unwrap();
    for socket in [&a, &b] {
        // SAFETY: querying the flags of an owned live descriptor.
        assert_ne!(unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    }
    let first = request(Request::ScanI32 { value: 1337 });
    let second = request(Request::RefineI32 { value: 7331 });
    a.send(&first).unwrap();
    a.send(&second).unwrap();
    assert_eq!(b.recv().unwrap(), Some(first));
    assert_eq!(b.recv().unwrap(), Some(second));
    drop(a);
    assert_eq!(b.recv().unwrap(), None);
    assert!(matches!(b.send(&request(Request::GetRanges)), Err(ProtocolError::Io(_))));
}

#[test]
fn receive_timeout_and_zero_timeout() {
    let (_a, b) = SeqPacket::pair().unwrap();
    assert_eq!(b.set_recv_timeout(Duration::ZERO).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    b.set_recv_timeout(Duration::from_millis(10)).unwrap();
    assert!(matches!(b.recv(), Err(ProtocolError::Io(e))
        if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)));
}

#[test]
fn transport_rejects_truncated_and_oversized_datagrams() {
    let (a, b) = SeqPacket::pair().unwrap();
    send_raw(&a, b"KSME");
    assert!(b.recv().is_err());
    send_raw(&a, &vec![0; MAX_FRAME_SIZE + 1]);
    assert!(matches!(b.recv(), Err(ProtocolError::InvalidFrame("truncated packet"))));
    a.send(&request(Request::GetRanges)).unwrap();
    assert!(b.recv().unwrap().is_some()); // The oversized packet was consumed as a unit.
}

fn send_rights(socket: &SeqPacket, bytes: &[u8], fd: RawFd, count: usize) {
    let mut iov = libc::iovec { iov_base: bytes.as_ptr().cast_mut().cast(), iov_len: bytes.len() };
    // SAFETY: CMSG_SPACE calculates required storage for the supplied payload size.
    let space = unsafe { libc::CMSG_SPACE((count * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut control = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: msg is initialized with valid buffers; header and payload fit into
    // the aligned control allocation, and every descriptor is borrowed and live.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space;
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((count * std::mem::size_of::<RawFd>()) as u32) as _;
        for i in 0..count { libc::CMSG_DATA(header).cast::<RawFd>().add(i).write(fd); }
        assert_eq!(libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL), bytes.len() as isize);
    }
}

#[test]
fn ancillary_and_control_truncation_rejected_without_fd_leaks() {
    for count in [1, 100] {
        let (a, b) = SeqPacket::pair().unwrap();
        let mut pipe = [-1; 2];
        // SAFETY: pipe points to two writable fd slots, adopted below on success.
        assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0);
        // SAFETY: pipe2 returned two fresh descriptors.
        let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        send_rights(&a, &encode_packet(&request(Request::GetRanges)).unwrap(), writer.as_raw_fd(), count);
        drop(writer);
        let error = b.recv().unwrap_err();
        if count == 1 {
            assert!(matches!(error, ProtocolError::InvalidFrame("ancillary data is forbidden")));
        } else {
            assert!(matches!(error, ProtocolError::InvalidFrame("truncated ancillary data")));
        }
        let mut byte = 0u8;
        // EOF proves that all SCM_RIGHTS duplicates were closed. A leak would
        // return EAGAIN on this nonblocking pipe instead of hanging the test.
        assert_eq!(unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) }, 0);
    }
}

#[test]
fn data_truncation_also_closes_ancillary_fds() {
    let (a, b) = SeqPacket::pair().unwrap();
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) }, 0);
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
    send_rights(&a, &vec![0; MAX_FRAME_SIZE + 1], writer.as_raw_fd(), 1);
    drop(writer);
    assert!(b.recv().is_err());
    let mut byte = 0u8;
    assert_eq!(unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) }, 0);
}
