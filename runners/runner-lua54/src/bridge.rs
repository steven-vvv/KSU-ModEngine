use ipc_proto::{Bootstrap, Message, Packet, Request, Response, SeqPacket};
use sandbox_common::{SandboxConfig, SandboxMode};
use std::{
    cell::RefCell,
    os::fd::{FromRawFd, OwnedFd},
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

pub type Shared = Rc<RefCell<Bridge>>;
pub struct Bridge {
    socket: SeqPacket,
    next: u32,
    logs: usize,
    pub poisoned: bool,
    pub deadline: Instant,
}

pub fn bounded(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}
pub fn bootstrap() -> Result<(Bootstrap, SandboxConfig, Shared), String> {
    let mut fd = None;
    let mut mode = None;
    let mut empty_root = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ipc-fd" if fd.is_none() => fd = Some(args.next().ok_or("missing fd")?),
            "--sandbox" if mode.is_none() => {
                mode = Some(args.next().ok_or("missing sandbox mode")?)
            }
            "--empty-root" if empty_root.is_none() => {
                empty_root = Some(PathBuf::from(args.next().ok_or("missing empty root")?))
            }
            _ => return Err("invalid runner arguments".into()),
        }
    }
    if fd.as_deref() != Some("3") {
        return Err("IPC fd must be 3".into());
    }
    let mode = match mode.as_deref() {
        Some("strict") => SandboxMode::Strict,
        Some("development") => SandboxMode::Development,
        _ => return Err("explicit sandbox mode required".into()),
    };
    // CLI transfers sole ownership of the inherited IPC descriptor to this runner.
    let socket = SeqPacket::from_owned_fd(unsafe { OwnedFd::from_raw_fd(3) });
    socket
        .set_recv_timeout(Duration::from_secs(3))
        .map_err(|e| e.to_string())?;
    let packet = socket
        .recv()
        .map_err(|e| e.to_string())?
        .ok_or("missing bootstrap")?;
    let boot = match packet {
        Packet {
            request_id: 0,
            message: Message::Bootstrap(b),
        } => b,
        _ => return Err("expected bootstrap with id 0".into()),
    };
    if boot.source.len() > 48 * 1024
        || boot.source.contains('\0')
        || boot.source.starts_with('\u{1b}')
    {
        return Err("source must be text, at most 48 KiB".into());
    }
    if boot.script_name.len() > 256 || boot.script_name.contains('\0') {
        return Err("invalid script name".into());
    }
    if !(1..=2000).contains(&boot.timeout_ms)
        || !(1024 * 1024..=64 * 1024 * 1024).contains(&boot.memory_limit_bytes)
    {
        return Err("invalid VM resource limits".into());
    }
    let config = SandboxConfig {
        mode,
        ipc_fd: 3,
        memory_limit_bytes: boot.memory_limit_bytes,
        cpu_time_seconds: 3,
        empty_root,
    };
    let shared = Rc::new(RefCell::new(Bridge {
        socket,
        next: 1,
        logs: 0,
        poisoned: false,
        deadline: Instant::now() + Duration::from_secs(60),
    }));
    Ok((boot, config, shared))
}
impl Bridge {
    pub fn request(&mut self, request: Request) -> Result<Response, String> {
        if self.poisoned {
            return Err("IPC bridge is unusable".into());
        }
        if self.next > 10000 {
            self.poisoned = true;
            return Err("request limit exceeded".into());
        }
        let id = self.next;
        self.next += 1;
        let outcome: Result<Response, String> = (|| {
            self.socket
                .send(&Packet {
                    request_id: id,
                    message: Message::Request(request),
                })
                .map_err(|e| e.to_string())?;
            match self.socket.recv().map_err(|e| e.to_string())? {
                Some(Packet {
                    request_id,
                    message: Message::Response(response),
                }) if request_id == id => Ok(response),
                _ => Err("unexpected host response or EOF".into()),
            }
        })();
        if outcome.is_err() {
            self.poisoned = true;
        }
        match outcome? {
            Response::Error { code, message } => Err(format!(
                "{}: {}",
                bounded(&code, 64),
                bounded(&message, 2048)
            )),
            response => Ok(response),
        }
    }
    pub fn ok(&mut self, request: Request) -> Result<(), String> {
        let response = self.request(request)?;
        if matches!(response, Response::Ok) {
            Ok(())
        } else {
            self.unexpected()
        }
    }
    fn unexpected<T>(&mut self) -> Result<T, String> {
        self.poisoned = true;
        Err("unexpected response variant".into())
    }
    pub fn dispatch(&mut self, op: &str, a: &str, b: &str) -> Result<String, String> {
        if Instant::now() >= self.deadline {
            return Err("execution deadline exceeded".into());
        }
        if op.len() > 32 || a.len() > 4096 || b.len() > 64 {
            return Err("argument too long".into());
        }
        let number = |s: &str| {
            s.parse::<i32>()
                .map_err(|_| "expected signed i32".to_owned())
        };
        let address = |s: &str| -> Result<u64, String> {
            let n = if let Some(s) = s.strip_prefix("0x") {
                u64::from_str_radix(s, 16)
            } else {
                s.parse::<u64>()
            }
            .map_err(|_| "invalid address".to_owned())?;
            if n == 0 {
                return Err("address must be positive".into());
            }
            n.checked_add(4).ok_or("address overflow")?;
            Ok(n)
        };
        let request = match op {
            "log" => {
                self.logs = self.logs.checked_add(a.len()).ok_or("log size overflow")?;
                if self.logs > 64 * 1024 {
                    return Err("log budget exceeded".into());
                }
                Request::Log {
                    message: a.to_owned(),
                }
            }
            "scan" => Request::ScanI32 { value: number(a)? },
            "refine" => Request::RefineI32 { value: number(a)? },
            "results" => {
                let limit = a.parse::<u32>().map_err(|_| "invalid limit")?;
                if limit > 1024 {
                    return Err("result limit exceeds 1024".into());
                }
                Request::GetResults { limit }
            }
            "read" => Request::ReadMemory {
                address: address(a)?,
                len: 4,
            },
            "write" => Request::WriteMemory {
                address: address(a)?,
                data: number(b)?.to_le_bytes().to_vec(),
            },
            "edit" => Request::WriteResultsI32 { value: number(a)? },
            _ => return Err("unknown engine operation".into()),
        };
        let response = self.request(request)?;
        match (op, response) {
            ("log" | "write", Response::Ok) => Ok(String::new()),
            ("scan" | "refine" | "edit", Response::ScanCount { count }) => Ok(count.to_string()),
            ("read", Response::Bytes { data }) if data.len() == 4 => {
                Ok(i32::from_le_bytes(data.try_into().unwrap()).to_string())
            }
            ("results", Response::Results { addresses })
                if addresses.len() <= a.parse::<usize>().unwrap_or(0)
                    && addresses.iter().all(|n| *n > 0) =>
            {
                Ok(addresses
                    .iter()
                    .map(|n| format!("0x{n:x}"))
                    .collect::<Vec<_>>()
                    .join(","))
            }
            _ => self.unexpected(),
        }
    }
}
pub fn ready(bridge: &Shared, mode: &SandboxMode, timeout_ms: u64) -> Result<Instant, String> {
    let mode = match mode {
        SandboxMode::Strict => "strict",
        SandboxMode::Development => "development",
    };
    bridge
        .borrow_mut()
        .ok(Request::SandboxReady { mode: mode.into() })?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    bridge.borrow_mut().deadline = deadline;
    Ok(deadline)
}
pub fn finish(bridge: &Shared, error: Option<String>) -> Result<(), String> {
    let error = error.map(|s| bounded(&s, 4096));
    let failed = error.is_some() || bridge.borrow().poisoned;
    bridge.borrow_mut().ok(Request::Finished { error })?;
    if failed {
        Err("script failed".into())
    } else {
        Ok(())
    }
}
