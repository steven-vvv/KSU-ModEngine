//! Each test installs seccomp only in the runner child, never the test process.
use ipc_proto::{Bootstrap, Message, Packet, Request, Response, SeqPacket};
use std::{
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const ADDRESS: u64 = 0x20_0000_0000_0001;

struct RunnerChild(Child);
impl RunnerChild {
    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = self.0.try_wait().expect("query runner status") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "runner did not exit after Finished acknowledgment"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for RunnerChild {
    fn drop(&mut self) {
        // Covers every assertion/panic/IPC failure, including a stuck post-Finished VM.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn exercise(source: &str, expected_failure: bool) {
    exercise_mode(source, expected_failure, "development");
}

fn exercise_mode(source: &str, expected_failure: bool, mode: &str) {
    exercise_detail(source, expected_failure, mode, None);
}

fn exercise_detail(source: &str, expected_failure: bool, mode: &str, expected_error: Option<&str>) {
    let (host, runner) = SeqPacket::pair().unwrap();
    host.set_recv_timeout(Duration::from_secs(8)).unwrap();
    let raw = runner.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_runner-qjs"));
    command
        .args(["--ipc-fd", "3", "--sandbox", mode])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Only async-signal-safe descriptor operations are performed after fork.
    unsafe {
        command.pre_exec(move || {
            if raw != 3 && libc::dup2(raw, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = RunnerChild(command.spawn().unwrap());
    let wall_deadline = Instant::now() + Duration::from_secs(8);
    drop(runner);
    host.send(&Packet {
        request_id: 0,
        message: Message::Bootstrap(Bootstrap {
            source: source.into(),
            script_name: "test".into(),
            timeout_ms: 100,
            memory_limit_bytes: 64 * 1024 * 1024,
        }),
    })
    .unwrap();
    let mut id = 1;
    let mut ready = false;
    let mut finished = false;
    // The RAII child guard kills and reaps on every failure path.
    for _ in 0..10002 {
        assert!(
            Instant::now() < wall_deadline,
            "runner exceeded test wall-clock limit"
        );
        let packet = match host.recv() {
            Ok(Some(p)) => p,
            result => panic!("runner IPC ended before Finished: {result:?}"),
        };
        assert_eq!(packet.request_id, id);
        id += 1;
        let response = match packet.message {
            Message::Request(Request::SandboxReady { mode: actual }) => {
                assert_eq!(
                    mode, "development",
                    "strict without empty root must fail before Ready"
                );
                assert_eq!(actual, mode);
                assert!(!ready);
                ready = true;
                Response::Ok
            }
            Message::Request(request) => {
                if mode == "strict" {
                    assert!(!ready);
                    assert!(
                        matches!(&request, Request::Finished { error: Some(message) } if message.contains("sandbox setup failed") && message.len() <= 4096)
                    );
                } else {
                    assert!(ready);
                }
                match request {
                    Request::ScanI32 { value: 1337 }
                    | Request::RefineI32 { value: 1337 }
                    | Request::WriteResultsI32 { value: 7331 } => Response::ScanCount { count: 1 },
                    Request::ScanI32 { value: -1 } => Response::Error {
                        code: "denied".into(),
                        message: "host rejected operation".into(),
                    },
                    Request::GetResults { limit } => {
                        assert!(limit <= 1024);
                        Response::Results {
                            addresses: vec![ADDRESS],
                        }
                    }
                    Request::ReadMemory {
                        address: ADDRESS,
                        len: 4,
                    } => Response::Bytes {
                        data: 1337i32.to_le_bytes().to_vec(),
                    },
                    Request::WriteMemory {
                        address: ADDRESS,
                        data,
                    } => {
                        assert_eq!(data, 7331i32.to_le_bytes());
                        Response::Ok
                    }
                    Request::Log { message } => {
                        assert!(message.len() <= 4096);
                        Response::Ok
                    }
                    Request::Finished { error } => {
                        assert_eq!(error.is_some(), expected_failure, "{error:?}");
                        if let Some(expected) = expected_error {
                            assert!(
                                error
                                    .as_deref()
                                    .is_some_and(|message| message.contains(expected)),
                                "{error:?}"
                            );
                        }
                        finished = true;
                        Response::Ok
                    }
                    request => panic!("unexpected request: {request:?}"),
                }
            }
            _ => panic!("expected request"),
        };
        host.send(&Packet {
            request_id: packet.request_id,
            message: Message::Response(response),
        })
        .unwrap();
        if finished {
            break;
        }
    }
    assert!(finished, "runner exceeded request budget without Finished");
    assert_eq!(child.wait_for_exit().success(), !expected_failure);
}

#[test]
fn engine_roundtrip_and_denied_libraries() {
    exercise(
        r#"
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
"#,
        false,
    );
}
#[test]
fn deadline_stops_loop() {
    exercise("while (true) {}", true);
}
#[test]
fn heap_is_bounded() {
    exercise(
        "const a = []; while (true) a.push(new Array(100000).fill(42));",
        true,
    );
}

#[test]
fn strict_failure_reports_reason_before_ready() {
    // Missing empty root makes strict unavailable for root too. The script must
    // never execute, including after any partial sandbox setup failure.
    exercise_mode("engine.log('source must not run')", true, "strict");
}

#[test]
fn promise_chain_is_explicitly_unsupported() {
    exercise_detail(
        "Promise.resolve().then(() => { throw Error('job must not run'); });",
        true,
        "development",
        Some("asynchronous JavaScript is unsupported"),
    );
}

#[test]
fn promise_rejection_is_explicitly_unsupported() {
    exercise_detail(
        "Promise.reject(Error('unhandled'));",
        true,
        "development",
        Some("asynchronous JavaScript is unsupported"),
    );
}

#[test]
fn async_function_invocation_is_explicitly_unsupported() {
    exercise_detail(
        "async function task() { throw Error('unhandled'); } task();",
        true,
        "development",
        Some("asynchronous JavaScript is unsupported"),
    );
}
