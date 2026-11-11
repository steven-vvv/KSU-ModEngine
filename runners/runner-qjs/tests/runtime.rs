//! Each test installs seccomp only in the runner child, never the test process.
use ipc_proto::{Bootstrap, Message, Packet, Request, Response, SeqPacket};
use std::{os::{fd::AsRawFd, unix::process::CommandExt}, process::{Command, Stdio}, time::Duration};

const ADDRESS: u64 = 0x20_0000_0000_0001;

fn exercise(source: &str, expected_failure: bool) {
    let (host, runner) = SeqPacket::pair().unwrap();
    host.set_recv_timeout(Duration::from_secs(8)).unwrap();
    let raw = runner.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_runner-qjs"));
    command.args(["--ipc-fd", "3", "--sandbox", "development"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // Only async-signal-safe descriptor operations are performed after fork.
    unsafe {
        command.pre_exec(move || {
            if raw != 3 && libc::dup2(raw, 3) == -1 { return Err(std::io::Error::last_os_error()); }
            if libc::fcntl(3, libc::F_SETFD, 0) == -1 { return Err(std::io::Error::last_os_error()); }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(runner);
    host.send(&Packet { request_id: 0, message: Message::Bootstrap(Bootstrap {
        source: source.into(), script_name: "test".into(), timeout_ms: 100,
        memory_limit_bytes: 64 * 1024 * 1024,
    }) }).unwrap();
    let mut id = 1;
    let mut ready = false;
    let mut finished = false;
    // Any timeout kills and reaps the runner, preventing orphaned infinite loops.
    loop {
        let packet = match host.recv() {
            Ok(Some(p)) => p,
            result => { let _ = child.kill(); let _ = child.wait(); panic!("runner IPC ended before Finished: {result:?}"); }
        };
        assert_eq!(packet.request_id, id);
        id += 1;
        let response = match packet.message {
            Message::Request(Request::SandboxReady { mode }) => { assert_eq!(mode, "development"); assert!(!ready); ready = true; Response::Ok }
            Message::Request(request) => {
                assert!(ready);
                match request {
                    Request::ScanI32 { value: 1337 } | Request::RefineI32 { value: 1337 } | Request::WriteResultsI32 { value: 7331 } => Response::ScanCount { count: 1 },
                    Request::ScanI32 { value: -1 } => Response::Error { code: "denied".into(), message: "host rejected operation".into() },
                    Request::GetResults { limit } => { assert!(limit <= 1024); Response::Results { addresses: vec![ADDRESS] } },
                    Request::ReadMemory { address: ADDRESS, len: 4 } => Response::Bytes { data: 1337i32.to_le_bytes().to_vec() },
                    Request::WriteMemory { address: ADDRESS, data } => { assert_eq!(data, 7331i32.to_le_bytes()); Response::Ok },
                    Request::Log { message } => { assert!(message.len() <= 4096); Response::Ok },
                    Request::Finished { error } => { assert_eq!(error.is_some(), expected_failure, "{error:?}"); finished = true; Response::Ok },
                    request => panic!("unexpected request: {request:?}"),
                }
            }
            _ => panic!("expected request"),
        };
        host.send(&Packet { request_id: packet.request_id, message: Message::Response(response) }).unwrap();
        if finished { break; }
    }
    assert_eq!(child.wait().unwrap().success(), !expected_failure);
}

#[test]
fn engine_roundtrip_and_denied_libraries() {
    exercise(r#"
function check(v) { if (!v) throw Error('assertion failed'); }
check(typeof std === 'undefined' && typeof os === 'undefined');
check(typeof require === 'undefined' && typeof eval === 'undefined');
check(typeof Function === 'undefined');
check(engine.scanI32(1337) === 1);
check(engine.refineI32(1337) === 1);
const address = engine.results(1)[0];
check(address === '0x20000000000001');
check(engine.readI32(address) === 1337);
engine.writeI32(BigInt(address), 7331);
check(engine.editAll(7331) === 1);
let rejected = false;
try { engine.scanI32(2147483648); } catch (_) { rejected = true; }
check(rejected);
rejected = false;
try { engine.scanI32(-1); } catch (_) { rejected = true; }
check(rejected);
console.log('done');
"#, false);
}
#[test]
fn deadline_stops_loop() { exercise("while (true) {}", true); }
#[test]
fn heap_is_bounded() { exercise("const a = []; while (true) a.push(new Array(100000).fill(42));", true); }
