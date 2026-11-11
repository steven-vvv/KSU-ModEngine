//! Linux fixture-only development host. No arbitrary PID attachment interface exists.
use engine_core::memory::FIXTURE_PACKAGE;
use engine_core::{Authorization, Manifest, MemorySession, TargetIdentity, source_hash};
use ipc_proto::{
    Bootstrap, MemoryRange, Message, Packet, ProtocolError, Request, Response, SeqPacket,
};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
const SOURCE_LIMIT: u64 = 48 * 1024;
const WALL_LIMIT: Duration = Duration::from_secs(5);
const HELP: &str = "KSU ModEngine v0.1 — Linux fixture development preview\n\nUsage:\n  ksu-mod-hostd doctor [--json]\n  ksu-mod-hostd inspect-script PATH [--json]\n  ksu-mod-hostd run PATH --fixture --approve SHA256 [--development-sandbox] [--json]\n\nDefault sandbox: strict (requires root and namespace privileges). Development must\nbe selected explicitly and is for trusted local fixture scripts only. Approval\nbinds the complete source SHA-256. Android target attachment is unsupported.";

#[derive(Debug)]
enum Cli {
    Help,
    Doctor,
    Inspect(PathBuf),
    Run {
        path: PathBuf,
        approval: String,
        development: bool,
    },
}
fn parse(args: &[String]) -> Result<Cli> {
    let filtered: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|arg| *arg != "--json")
        .collect();
    if args.iter().filter(|arg| *arg == "--json").count() > 1 {
        return Err("duplicate --json".into());
    }
    match filtered.as_slice() {
        [] | ["--help"] | ["-h"] | ["help"] => Ok(Cli::Help),
        ["doctor"] => Ok(Cli::Doctor),
        ["inspect-script", path] if !path.starts_with('-') => Ok(Cli::Inspect(path.into())),
        ["run", path, rest @ ..] if !path.starts_with('-') => {
            let mut fixture = false;
            let mut approval = None;
            let mut development = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i] {
                    "--fixture" if !fixture => fixture = true,
                    "--development-sandbox" if !development => development = true,
                    "--approve" if approval.is_none() => {
                        i += 1;
                        approval =
                            Some(rest.get(i).ok_or("--approve requires SHA256")?.to_string());
                    }
                    _ => return Err(format!("unknown or duplicate run option: {}", rest[i])),
                }
                i += 1;
            }
            if !fixture {
                return Err(
                    "run requires --fixture; arbitrary application/PID targets are unsupported"
                        .into(),
                );
            }
            let approval = approval.ok_or("run requires explicit --approve SHA256")?;
            if approval.len() != 64
                || !approval
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err("approval must be 64 lowercase hexadecimal SHA256 characters".into());
            }
            Ok(Cli::Run {
                path: path.into(),
                approval,
                development,
            })
        }
        _ => Err("invalid command or arguments; use --help".into()),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["__fixture-target"] {
        if fixture_target().is_err() {
            std::process::exit(1);
        }
        return;
    }
    let json_output = args.iter().any(|arg| arg == "--json");
    let result = parse(&args).and_then(|command| match command {
        Cli::Help => Ok(json!({"ok": true, "help": HELP})),
        Cli::Doctor => doctor(),
        Cli::Inspect(path) => inspect(&path),
        Cli::Run {
            path,
            approval,
            development,
        } => run(&path, &approval, development),
    });
    match result {
        Ok(value) => {
            if json_output {
                println!("{value}");
            } else if let Some(help) = value.get("help").and_then(Value::as_str) {
                println!("{help}");
            } else {
                human(&value);
            }
        }
        Err(error) => {
            if json_output {
                println!("{}", json!({"ok": false, "error": bounded(&error, 4096)}));
            } else {
                eprintln!("Error: {}", sanitize(&bounded(&error, 4096)));
            }
            std::process::exit(1);
        }
    }
}
fn bounded(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].into()
}
fn sanitize(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn human(value: &Value) {
    if value.get("fixture").is_some() {
        println!(
            "{}: success ({}, {} sandbox)",
            sanitize(value["script_id"].as_str().unwrap_or("script")),
            value["runtime"].as_str().unwrap_or("unknown"),
            value["sandbox"].as_str().unwrap_or("unknown")
        );
        println!(
            "Fixture: {} → {}",
            value["fixture"]["initial_values"], value["fixture"]["final_values"]
        );
        if let Some(logs) = value["logs"].as_array() {
            for log in logs {
                println!("log: {}", sanitize(log.as_str().unwrap_or("")));
            }
        }
    } else if value.get("manifest").is_some() {
        println!(
            "{} ({})",
            sanitize(value["manifest"]["name"].as_str().unwrap_or("script")),
            value["runtime"].as_str().unwrap_or("unsupported")
        );
        println!("SHA256: {}", value["source_sha256"].as_str().unwrap_or(""));
        println!("Supported: {}", value["supported"]);
        if let Some(error) = value["authorization_error"].as_str() {
            println!("Authorization: {}", sanitize(error));
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "output error".into())
        );
    }
}
struct Script {
    source: String,
    manifest: Manifest,
    hash: String,
    runtime: &'static str,
}
fn runtime(path: &Path) -> Result<&'static str> {
    match path.extension().and_then(|s| s.to_str()) {
        Some("lua") => Ok("lua54"),
        Some("js") => Ok("qjs"),
        _ => Err("unsupported source extension; use .lua or .js".into()),
    }
}
fn script(path: &Path) -> Result<Script> {
    // Nonblocking open plus regular-file check prevents a FIFO/device from blocking this read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("open source: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("source must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(SOURCE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read source: {e}"))?;
    if bytes.len() as u64 > SOURCE_LIMIT {
        return Err("source exceeds 48 KiB".into());
    }
    let hash = source_hash(&bytes);
    let source = String::from_utf8(bytes).map_err(|_| "source must be UTF-8 text")?;
    let manifest = Manifest::parse(&source).map_err(|e| e.to_string())?;
    Ok(Script {
        source,
        manifest,
        hash,
        runtime: runtime(path).unwrap_or("unsupported"),
    })
}
fn runner_path(runtime: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(exe
        .parent()
        .ok_or("executable has no parent directory")?
        .join(if runtime == "lua54" {
            "runner-lua54"
        } else {
            "runner-qjs"
        }))
}
fn inspect(path: &Path) -> Result<Value> {
    let s = script(path)?;
    let authorization_error = runtime(path)
        .err()
        .or_else(|| {
            Authorization::approve(&s.manifest, s.source.as_bytes(), &s.hash)
                .err()
                .map(|e| e.to_string())
        })
        .or_else(|| {
            if s.manifest.matches.iter().any(|m| m == FIXTURE_PACKAGE) {
                None
            } else {
                Some("manifest does not match fixture package".into())
            }
        });
    Ok(
        json!({"ok": true, "manifest": s.manifest, "source_sha256": s.hash, "runtime": s.runtime, "supported": authorization_error.is_none(), "authorization_error": authorization_error, "runner_available": s.runtime != "unsupported" && runner_path(s.runtime)?.is_file()}),
    )
}
fn doctor() -> Result<Value> {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let uts = unsafe { uts.assume_init() };
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let uid = unsafe { libc::geteuid() };
    let lua = runner_path("lua54")?;
    let js = runner_path("qjs")?;
    Ok(
        json!({"ok": true, "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH, "kernel": release,
        "page_size": unsafe { libc::sysconf(libc::_SC_PAGESIZE) }, "effective_uid": uid,
        "android_supported": false, "fixture_supported": cfg!(target_os="linux"),
        "strict_sandbox": {"available": null, "root": uid == 0, "mount_namespace": Path::new("/proc/self/ns/mnt").exists(), "network_namespace": Path::new("/proc/self/ns/net").exists(), "note": "Strict availability is established only by successfully entering all isolation steps; namespaces/root flags are not a guarantee."},
        "seccomp_status": std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("Seccomp:")).map(str::to_owned)),
        "runners": {"lua54": {"path": lua, "present": lua.is_file()}, "qjs": {"path": js, "present": js.is_file()}},
        "preview": "Linux owned fixture only; Android installation and arbitrary target attachment are unsupported"}),
    )
}

/// Always reap children, including every early-return/error path.
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct EmptyRoot(PathBuf);
impl EmptyRoot {
    fn create() -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .map_err(|e| e.to_string())?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path =
            std::env::temp_dir().join(format!("ksu-modengine-{}-{suffix}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| format!("create empty root: {e}"))?;
        Ok(Self(path))
    }
}
impl Drop for EmptyRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}
fn child_setup(command: &mut Command, ipc_fd: Option<i32>) {
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            // async-signal-safe raw syscalls only; check the parent-death race before exec.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1
                || libc::getppid() != parent
            {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            let first = if let Some(fd) = ipc_fd {
                if libc::dup2(fd, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                4u32
            } else {
                3u32
            };
            // Mark, rather than close now: preserve Command's exec-failure pipe until exec.
            if libc::syscall(libc::SYS_close_range, first, u32::MAX, 4u32) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
fn deadline(start: Instant) -> Result<()> {
    if start.elapsed() >= WALL_LIMIT {
        Err("host wall-clock deadline exceeded".into())
    } else {
        Ok(())
    }
}
fn read_line_bounded(fd: i32, start: Instant) -> Result<String> {
    let mut data = Vec::new();
    loop {
        deadline(start)?;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 50) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error().to_string());
        }
        if result == 0 {
            continue;
        }
        let mut byte = 0u8;
        let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if n == 0 {
            return Err("fixture ended before its response".into());
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.to_string());
        }
        if byte == b'\n' {
            return String::from_utf8(data).map_err(|_| "invalid fixture text".into());
        }
        if data.len() >= 1024 {
            return Err("fixture response exceeds limit".into());
        }
        data.push(byte);
    }
}
fn send_timeout(socket: &SeqPacket) -> Result<()> {
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as _,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}
fn wait_success(child: &mut Child, start: Instant) -> Result<()> {
    loop {
        deadline(start)?;
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("runner exited unsuccessfully: {status}"))
            };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn run(path: &Path, approval: &str, development: bool) -> Result<Value> {
    let script = script(path)?;
    let authorization =
        Authorization::approve(&script.manifest, script.source.as_bytes(), approval)
            .map_err(|e| e.to_string())?;
    if !script.manifest.matches.iter().any(|m| m == FIXTURE_PACKAGE) {
        return Err("manifest does not match fixture package".into());
    }
    runtime(path)?;
    let runner_path = runner_path(script.runtime)?;
    if !runner_path.is_file() {
        return Err(format!(
            "missing runner: {}; build the workspace binaries first",
            runner_path.display()
        ));
    }
    let start = Instant::now();
    // Keep this guard older than the Runner: reverse drop order reaps it before directory removal.
    let empty_root = if development {
        None
    } else {
        Some(EmptyRoot::create()?)
    };
    let mut fixture_command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    fixture_command
        .arg("__fixture-target")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    child_setup(&mut fixture_command, None);
    let mut fixture = OwnedChild(
        fixture_command
            .spawn()
            .map_err(|e| format!("spawn fixture: {e}"))?,
    );
    let fixture_stdout = fixture
        .0
        .stdout
        .as_ref()
        .ok_or("fixture stdout unavailable")?
        .as_raw_fd();
    let hello: Value = serde_json::from_str(&read_line_bounded(fixture_stdout, start)?)
        .map_err(|e| format!("fixture handshake: {e}"))?;
    let address = hello["address"].as_u64().ok_or("fixture address missing")?;
    let end = hello["end"].as_u64().ok_or("fixture end missing")?;
    if hello["pid"].as_u64() != Some(fixture.0.id() as u64) {
        return Err("fixture PID mismatch".into());
    }
    let identity = TargetIdentity::capture(fixture.0.id() as i32).map_err(|e| e.to_string())?;
    let mut session = MemorySession::for_fixture(
        identity,
        MemoryRange {
            start: address,
            end,
            readable: true,
            writable: true,
            executable: false,
            private: true,
            name: None,
        },
        authorization,
    )
    .map_err(|e| e.to_string())?;
    let (socket, child_socket) = SeqPacket::pair().map_err(|e| e.to_string())?;
    socket
        .set_recv_timeout(Duration::from_millis(100))
        .map_err(|e| e.to_string())?;
    send_timeout(&socket)?;
    let mode = if development { "development" } else { "strict" };
    let mut command = Command::new(&runner_path);
    command
        .args(["--ipc-fd", "3", "--sandbox", mode])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(root) = &empty_root {
        command.arg("--empty-root").arg(&root.0);
    }
    child_setup(&mut command, Some(child_socket.as_raw_fd()));
    let mut runner = OwnedChild(command.spawn().map_err(|e| format!("spawn runner: {e}"))?);
    drop(child_socket);
    socket
        .send(&Packet {
            request_id: 0,
            message: Message::Bootstrap(Bootstrap {
                source: script.source,
                script_name: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("script")
                    .into(),
                timeout_ms: 2000,
                memory_limit_bytes: 64 * 1024 * 1024,
            }),
        })
        .map_err(|e| format!("send bootstrap: {e}"))?;
    let mut ready = false;
    let mut next_id = 1;
    let mut requests = 0u32;
    let mut logs = Vec::<String>::new();
    let mut log_bytes = 0usize;
    loop {
        deadline(start)?;
        let packet = match socket.recv() {
            Ok(Some(packet)) => packet,
            Ok(None) => return Err("runner IPC ended before Finished".into()),
            Err(ProtocolError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(format!("runner protocol: {e}")),
        };
        requests += 1;
        if requests > 10000 {
            return Err("runner request budget exceeded".into());
        }
        if packet.request_id != next_id {
            return Err("runner request IDs must increase consecutively from 1".into());
        }
        next_id += 1;
        let request = match packet.message {
            Message::Request(request) => request,
            _ => return Err("expected runner Request".into()),
        };
        let mut finished = None;
        let response = match request {
            Request::SandboxReady { mode: reported } => {
                if ready || reported != mode {
                    return Err("duplicate or incorrect SandboxReady".into());
                }
                ready = true;
                Response::Ok
            }
            // Sandbox failures may be reported before Ready, but can never succeed.
            Request::Finished { error } => {
                if !ready && error.is_none() {
                    return Err("Finished success before SandboxReady".into());
                }
                finished = Some(error);
                Response::Ok
            }
            _ if !ready => return Err("runner requested an operation before SandboxReady".into()),
            Request::Log { message } => {
                log_bytes = log_bytes
                    .checked_add(message.len())
                    .ok_or("log budget overflow")?;
                if log_bytes > 64 * 1024 {
                    return Err("runner log budget exceeded".into());
                }
                logs.push(message);
                Response::Ok
            }
            request => memory_request(&mut session, request),
        };
        deadline(start)?;
        socket
            .send(&Packet {
                request_id: packet.request_id,
                message: Message::Response(response),
            })
            .map_err(|e| format!("send response: {e}"))?;
        if let Some(error) = finished {
            if let Some(error) = error {
                return Err(format!("runner failed: {}", bounded(&error, 4096)));
            }
            wait_success(&mut runner.0, start)?;
            match socket.recv() {
                Ok(None) => {}
                Ok(Some(_)) => return Err("runner sent a packet after Finished".into()),
                Err(error) => return Err(format!("runner did not close IPC cleanly: {error}")),
            }
            break;
        }
    }
    fixture
        .0
        .stdin
        .as_mut()
        .ok_or("fixture stdin unavailable")?
        .write_all(b"values\n")
        .map_err(|e| e.to_string())?;
    let values: Value = serde_json::from_str(&read_line_bounded(fixture_stdout, start)?)
        .map_err(|e| format!("fixture values: {e}"))?;
    let final_values = values["values"]
        .as_array()
        .filter(|v| v.len() == 3)
        .ok_or("fixture final values missing")?;
    Ok(
        json!({"ok": true, "script_id": script.manifest.id, "source_sha256": script.hash, "sandbox": mode,
        "runtime": script.runtime, "logs": logs, "requests": requests, "elapsed_ms": start.elapsed().as_millis(),
        "fixture": {"pid": fixture.0.id(), "address": format!("0x{address:x}"), "initial_values": [1337,42,1337], "final_values": final_values}}),
    )
}
fn memory_request(session: &mut MemorySession, request: Request) -> Response {
    let result = match request {
        Request::GetRanges => session.maps().map(|ranges| Response::Ranges { ranges }),
        Request::ReadMemory { address, len } => session
            .read(address, len as usize)
            .map(|data| Response::Bytes { data }),
        Request::WriteMemory { address, data } => {
            session.write(address, &data).map(|_| Response::Ok)
        }
        Request::ScanI32 { value } => session.scan_i32(value).map(|count| Response::ScanCount {
            count: count as u32,
        }),
        Request::RefineI32 { value } => {
            session.refine_i32(value).map(|count| Response::ScanCount {
                count: count as u32,
            })
        }
        Request::GetResults { limit } => session
            .results(limit as usize)
            .map(|addresses| Response::Results { addresses }),
        Request::WriteResultsI32 { value } => {
            session
                .edit_all_i32(value)
                .map(|count| Response::ScanCount {
                    count: count as u32,
                })
        }
        _ => {
            return Response::Error {
                code: "protocol".into(),
                message: "invalid memory request".into(),
            };
        }
    };
    result.unwrap_or_else(|e| Response::Error {
        code: "memory_denied".into(),
        message: bounded(&e.to_string(), 4096),
    })
}
fn fixture_target() -> io::Result<()> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || page > 16 * 1024 {
        return Err(io::Error::other("unsupported fixture page size"));
    }
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let numbers = mapping.cast::<i32>();
    unsafe {
        numbers.write(1337i32.to_le());
        numbers.add(1).write(42i32.to_le());
        numbers.add(2).write(1337i32.to_le());
    }
    println!(
        "{}",
        json!({"pid": std::process::id(), "address": mapping as usize as u64, "end": mapping as usize as u64 + page as u64})
    );
    io::stdout().flush()?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = String::new();
        if input.by_ref().take(32).read_line(&mut line)? == 0 {
            break;
        }
        if line == "values\n" {
            let values = unsafe {
                [
                    i32::from_le(numbers.read_volatile()),
                    i32::from_le(numbers.add(1).read_volatile()),
                    i32::from_le(numbers.add(2).read_volatile()),
                ]
            };
            println!("{}", json!({"values": values}));
            io::stdout().flush()?;
        } else {
            break;
        }
    }
    if unsafe { libc::munmap(mapping, page as usize) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn cli_requires_fixture_approval_and_explicit_mode() {
        assert!(parse(&args(&["run", "demo.js", "--approve", &"0".repeat(64)])).is_err());
        assert!(parse(&args(&["run", "demo.js", "--fixture"])).is_err());
        assert!(
            parse(&args(&[
                "run",
                "demo.js",
                "--fixture",
                "--approve",
                &"0".repeat(64),
                "--pid",
                "1"
            ]))
            .is_err()
        );
        assert!(matches!(
            parse(&args(&[
                "run",
                "demo.js",
                "--fixture",
                "--approve",
                &"0".repeat(64)
            ]))
            .unwrap(),
            Cli::Run {
                development: false,
                ..
            }
        ));
        assert!(parse(&args(&["doctor", "--json", "--json"])).is_err());
    }
    #[test]
    fn display_escapes_terminal_controls_and_bounds_utf8() {
        assert_eq!(sanitize("ok\x1b[31m\n"), "ok\\u{1b}[31m\\n");
        assert_eq!(bounded("aéz", 2), "a");
    }
}
