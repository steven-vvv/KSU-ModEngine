use crate::{Authorization, Capability, Error, MemoryRange, Result};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const FIXTURE_PACKAGE: &str = "com.example.ksumod.fixture";
pub const MAX_TRANSFER_BYTES: usize = 16 * 1024;
pub const MAX_RESULTS: usize = 1024;
const MAX_SCAN_BYTES: u64 = 1024 * 1024;
const SESSION_SCAN_BUDGET: u64 = 16 * 1024 * 1024;

fn target(message: &str) -> Error {
    Error::Target(message.into())
}
fn memory(message: &str) -> Error {
    Error::Memory(message.into())
}
fn proc_text(pid: i32, file: &str) -> Result<String> {
    let mut text = String::new();
    File::open(format!("/proc/{pid}/{file}"))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 4 * 1024 * 1024 {
        return Err(target("proc metadata too large"));
    }
    Ok(text)
}

#[derive(Debug, PartialEq, Eq)]
struct Stat {
    pid: i32,
    parent: i32,
    start: u64,
    state: char,
}
fn parse_stat(text: &str) -> Result<Stat> {
    let (prefix, rest) = text
        .rsplit_once(") ")
        .ok_or_else(|| target("malformed proc stat"))?;
    let pid = prefix
        .split_once(" (")
        .ok_or_else(|| target("malformed stat pid"))?
        .0
        .parse()
        .map_err(|_| target("invalid stat pid"))?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        return Err(target("short proc stat"));
    }
    let state = match fields[0] {
        "R" => 'R',
        "S" => 'S',
        "D" => 'D',
        "T" => 'T',
        "t" => 't',
        "I" => 'I',
        _ => return Err(target("target is not live")),
    };
    Ok(Stat {
        pid,
        parent: fields[1]
            .parse()
            .map_err(|_| target("invalid parent pid"))?,
        start: fields[19]
            .parse()
            .map_err(|_| target("invalid start time"))?,
        state,
    })
}
fn parse_uids(text: &str) -> Result<[u32; 4]> {
    let mut lines = text.lines().filter_map(|l| l.strip_prefix("Uid:"));
    let line = lines.next().ok_or_else(|| target("missing Uid"))?;
    if lines.next().is_some() {
        return Err(target("duplicate Uid"));
    }
    let ids: Vec<u32> = line
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| target("invalid Uid"))?;
    ids.try_into().map_err(|_| target("expected four Uids"))
}

/// Captured process identity. Construction does not grant access to a target.
/// pidfd, when available, detects exit in addition to start-time and UID checks.
#[derive(Debug)]
pub struct TargetIdentity {
    pid: i32,
    parent: i32,
    start: u64,
    uids: [u32; 4],
    pidfd: Option<OwnedFd>,
}
impl TargetIdentity {
    pub fn capture(pid: i32) -> Result<Self> {
        if pid <= 0 {
            return Err(target("pid must be positive"));
        }
        let stat = parse_stat(&proc_text(pid, "stat")?)?;
        if stat.pid != pid {
            return Err(target("pid mismatch"));
        }
        let uids = parse_uids(&proc_text(pid, "status")?)?;
        // SAFETY: pidfd_open takes a numeric pid and flags, returning an owned FD.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let pidfd = if fd >= 0 {
            // SAFETY: this successful syscall returned a fresh owned descriptor.
            Some(unsafe { OwnedFd::from_raw_fd(fd as i32) })
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES) => None,
                _ => return Err(err.into()),
            }
        };
        let result = Self {
            pid,
            parent: stat.parent,
            start: stat.start,
            uids,
            pidfd,
        };
        result.verify()?;
        Ok(result)
    }
    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn start_time(&self) -> u64 {
        self.start
    }
    pub fn uid(&self) -> u32 {
        self.uids[1]
    }
    pub fn verify(&self) -> Result<()> {
        if let Some(fd) = &self.pidfd {
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll points to one initialized pollfd for the duration of the call.
            let count = unsafe { libc::poll(&mut poll, 1, 0) };
            if count < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if count != 0 {
                return Err(target("pidfd reports exited target"));
            }
        }
        let stat = parse_stat(&proc_text(self.pid, "stat")?)?;
        if stat.pid != self.pid
            || stat.start != self.start
            || stat.parent != self.parent
            || parse_uids(&proc_text(self.pid, "status")?)? != self.uids
        {
            return Err(target("process identity changed"));
        }
        Ok(())
    }
    fn verify_owned_child(&self) -> Result<()> {
        self.verify()?;
        // SAFETY: getpid/geteuid have no memory safety preconditions.
        let (pid, uid) = unsafe { (libc::getpid(), libc::geteuid()) };
        if self.parent != pid || self.uids.iter().any(|v| *v != uid) {
            return Err(target(
                "fixture must be a direct child with all UIDs equal to host euid",
            ));
        }
        Ok(())
    }
}

/// Future Android policy building block, not package resolution or authorization.
/// The caller must obtain UID/package and launcher/manager names from trusted PM
/// state; caller-provided package names do not establish Android identity.
pub fn validate_android_target(package: &str, uid: u32, protected_packages: &[&str]) -> Result<()> {
    let app_id = uid % 100_000;
    if !(10_000..20_000).contains(&app_id) {
        return Err(target("Android appId is not an ordinary application"));
    }
    if !crate::manifest::valid_package(package) {
        return Err(target("invalid Android package"));
    }
    const DENY: &[&str] = &[
        "android",
        "com.android.systemui",
        "com.android.launcher",
        "com.android.launcher2",
        "com.android.launcher3",
        "com.google.android.apps.nexuslauncher",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
        "me.weishu.kernelsu",
        "me.weishu.kernelsu.next",
        "com.rifsxd.ksunext",
        "com.example.ksumod",
        "com.example.ksumod.manager",
    ];
    if DENY.contains(&package) || protected_packages.contains(&package) {
        return Err(target("protected package"));
    }
    Ok(())
}

struct MapEntry {
    range: MemoryRange,
    anonymous: bool,
}
fn map_entries(text: &str) -> Result<Vec<MapEntry>> {
    let mut entries = Vec::new();
    let mut last_end = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Keep the complete pathname (including spaces) after the five columns.
        let mut rest = line;
        let mut fields = Vec::new();
        for _ in 0..5 {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            if end == 0 {
                return Err(target("truncated maps entry"));
            }
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        let (start, end) = fields[0]
            .split_once('-')
            .ok_or_else(|| target("invalid map range"))?;
        let start = u64::from_str_radix(start, 16).map_err(|_| target("invalid map start"))?;
        let end = u64::from_str_radix(end, 16).map_err(|_| target("invalid map end"))?;
        if start >= end || start < last_end {
            return Err(target("overlapping or empty map"));
        }
        last_end = end;
        let p = fields[1].as_bytes();
        if p.len() != 4
            || !matches!(p[0], b'r' | b'-')
            || !matches!(p[1], b'w' | b'-')
            || !matches!(p[2], b'x' | b'-')
            || !matches!(p[3], b'p' | b's')
        {
            return Err(target("invalid map permissions"));
        }
        u64::from_str_radix(fields[2], 16).map_err(|_| target("invalid map offset"))?;
        let (major, minor) = fields[3]
            .split_once(':')
            .ok_or_else(|| target("invalid device"))?;
        let major = u64::from_str_radix(major, 16).map_err(|_| target("invalid major device"))?;
        let minor = u64::from_str_radix(minor, 16).map_err(|_| target("invalid minor device"))?;
        let inode: u64 = fields[4].parse().map_err(|_| target("invalid map inode"))?;
        let name = rest.trim();
        let anonymous = inode == 0
            && major == 0
            && minor == 0
            && (name.is_empty() || (name.starts_with("[anon:") && name.ends_with(']')));
        entries.push(MapEntry {
            range: MemoryRange {
                start,
                end,
                readable: p[0] == b'r',
                writable: p[1] == b'w',
                executable: p[2] == b'x',
                private: p[3] == b'p',
                name: if name.is_empty() {
                    None
                } else {
                    Some(name.into())
                },
            },
            anonymous,
        });
    }
    Ok(entries)
}
pub fn parse_maps(text: &str) -> Result<Vec<MemoryRange>> {
    Ok(map_entries(text)?.into_iter().map(|e| e.range).collect())
}

/// Access to one trusted host-supplied page in an owned cooperative fixture.
/// /proc checks cannot atomically pin a VMA: remap/protection races remain. This
/// facility must never be presented as safe attachment to untrusted applications.
pub struct MemorySession {
    identity: TargetIdentity,
    range: MemoryRange,
    authorization: Authorization,
    results: Vec<u64>,
    scan_budget: u64,
}
impl MemorySession {
    pub fn for_fixture(
        identity: TargetIdentity,
        range: MemoryRange,
        authorization: Authorization,
    ) -> Result<Self> {
        if !authorization.permits_target(FIXTURE_PACKAGE) {
            return Err(target("script does not match fixture package"));
        }
        // SAFETY: sysconf(_SC_PAGESIZE) has no memory safety preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0
            || page as u64 > MAX_TRANSFER_BYTES as u64
            || !range.start.is_multiple_of(page as u64)
            || range.end.checked_sub(range.start) != Some(page as u64)
        {
            return Err(target(
                "fixture range must be exactly one aligned host page within transfer limit",
            ));
        }
        if !range.readable || !range.writable || range.executable || !range.private {
            return Err(target(
                "fixture must be readable writable private and non-executable",
            ));
        }
        let session = Self {
            identity,
            range,
            authorization,
            results: Vec::new(),
            scan_budget: SESSION_SCAN_BUDGET,
        };
        session.refresh()?;
        Ok(session)
    }
    fn refresh(&self) -> Result<()> {
        self.identity.verify_owned_child()?;
        let maps = map_entries(&proc_text(self.identity.pid, "maps")?)?;
        let found = maps.iter().any(|entry| {
            let m = &entry.range;
            entry.anonymous
                && m.readable
                && m.writable
                && m.private
                && !m.executable
                && m.start <= self.range.start
                && m.end >= self.range.end
                && m.name == self.range.name
        });
        if !found {
            return Err(target(
                "fixture mapping changed or is not anonymous private writable non-executable memory",
            ));
        }
        self.identity.verify_owned_child()
    }
    fn bounds(&self, address: u64, len: usize) -> Result<()> {
        if len == 0 || len > MAX_TRANSFER_BYTES {
            return Err(memory("transfer length must be 1..=16 KiB"));
        }
        let end = address
            .checked_add(u64::try_from(len).map_err(|_| memory("length overflow"))?)
            .ok_or_else(|| memory("address overflow"))?;
        if address < self.range.start || end > self.range.end || usize::try_from(address).is_err() {
            return Err(memory("address outside approved fixture page"));
        }
        Ok(())
    }
    pub fn maps(&mut self) -> Result<Vec<MemoryRange>> {
        self.authorization.require(Capability::MemRead)?;
        self.refresh()?;
        Ok(vec![self.range.clone()])
    }
    pub fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        self.authorization.require(Capability::MemRead)?;
        self.bounds(address, len)?;
        self.refresh()?;
        let mut data = vec![0; len];
        let local = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: address as usize as *mut libc::c_void,
            iov_len: len,
        };
        // SAFETY: local points to len writable bytes; remote is interpreted only
        // by the kernel in the verified child's address space.
        let n = unsafe { libc::process_vm_readv(self.identity.pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if n as usize != len {
            return Err(Error::ShortTransfer {
                operation: "read",
                actual: n as usize,
                expected: len,
            });
        }
        self.refresh()?;
        Ok(data)
    }
    /// A successful write reports transferred bytes. Errors can follow a partial
    /// or completed write; memory writes cannot be rolled back transactionally.
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<usize> {
        self.authorization.require(Capability::MemWriteHeap)?;
        self.bounds(address, data.len())?;
        self.refresh()?;
        let local = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        let remote = libc::iovec {
            iov_base: address as usize as *mut libc::c_void,
            iov_len: data.len(),
        };
        // SAFETY: local points to data.len initialized bytes and the kernel copies
        // them into the verified child's address space, never dereferencing remote here.
        let n = unsafe { libc::process_vm_writev(self.identity.pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if n as usize != data.len() {
            return Err(Error::ShortTransfer {
                operation: "write",
                actual: n as usize,
                expected: data.len(),
            });
        }
        self.refresh()?;
        Ok(n as usize)
    }
    fn charge_scan(&mut self, bytes: u64) -> Result<()> {
        if bytes > MAX_SCAN_BYTES || bytes > self.scan_budget {
            return Err(memory("scan byte budget exceeded"));
        }
        self.scan_budget -= bytes;
        Ok(())
    }
    /// Search aligned little-endian i32 values; at most the first 1024 matches
    /// are retained. Range is one page and total session scan bytes are bounded.
    pub fn scan_i32(&mut self, value: i32) -> Result<usize> {
        self.authorization.require(Capability::MemRead)?;
        self.results.clear();
        let len = self.range.end - self.range.start;
        self.charge_scan(len)?;
        let data = self.read(self.range.start, len as usize)?;
        for (i, chunk) in data.chunks_exact(4).enumerate() {
            if chunk == value.to_le_bytes() {
                self.results.push(
                    self.range
                        .start
                        .checked_add(
                            (i as u64)
                                .checked_mul(4)
                                .ok_or_else(|| memory("scan offset overflow"))?,
                        )
                        .ok_or_else(|| memory("scan address overflow"))?,
                );
                if self.results.len() == MAX_RESULTS {
                    break;
                }
            }
        }
        Ok(self.results.len())
    }
    pub fn refine_i32(&mut self, value: i32) -> Result<usize> {
        self.authorization.require(Capability::MemRead)?;
        self.refresh()?;
        self.charge_scan((self.range.end - self.range.start).max(self.results.len() as u64 * 4))?;
        // One bounded snapshot avoids one /proc walk per candidate.
        let snapshot = self.read(
            self.range.start,
            (self.range.end - self.range.start) as usize,
        )?;
        self.results.retain(|address| {
            let Some(offset) = address
                .checked_sub(self.range.start)
                .and_then(|v| usize::try_from(v).ok())
            else {
                return false;
            };
            snapshot
                .get(offset..offset.saturating_add(4))
                .is_some_and(|bytes| bytes == value.to_le_bytes())
        });
        Ok(self.results.len())
    }
    pub fn results(&self, limit: usize) -> Result<Vec<u64>> {
        self.authorization.require(Capability::MemRead)?;
        if limit > MAX_RESULTS {
            return Err(memory("result limit exceeds 1024"));
        }
        // This is metadata, but stale identity must not look like a live session.
        self.refresh()?;
        Ok(self.results.iter().take(limit).copied().collect())
    }
    /// Returns number of edited i32 results, not bytes. Failure may leave earlier
    /// results edited. Every write independently verifies identity and mappings.
    pub fn edit_all_i32(&mut self, value: i32) -> Result<usize> {
        self.authorization.require(Capability::MemWriteHeap)?;
        self.refresh()?;
        let addresses = self.results.clone();
        let mut count = 0;
        for address in addresses {
            self.write(address, &value.to_le_bytes())?;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manifest, source_hash};
    fn auth(grants: &str) -> Authorization {
        let source = format!(
            "// ==ModScript==\n// @id com.test.memory\n// @name Memory test\n// @version 1\n// @match {FIXTURE_PACKAGE}\n{grants}// ==/ModScript==\n"
        );
        Authorization::approve(
            &Manifest::parse(&source).unwrap(),
            source.as_bytes(),
            &source_hash(source.as_bytes()),
        )
        .unwrap()
    }
    #[test]
    fn parse_linux_stat_with_hostile_command_name() {
        // comm may contain spaces and ')' so the final ') ' is the delimiter.
        let mut fields = vec!["S", "123"];
        fields.extend(std::iter::repeat_n("0", 17));
        fields.push("999");
        let parsed = parse_stat(&format!("456 (a ) tricky) {})", fields.join(" ")));
        assert!(parsed.is_err()); // malformed start-time field
        let parsed = parse_stat(&format!("456 (a ) tricky) {}", fields.join(" "))).unwrap();
        assert_eq!(parsed.pid, 456);
        assert_eq!(parsed.parent, 123);
        assert_eq!(parsed.start, 999);
        assert!(parse_stat("1 (dead) Z 1 2").is_err());
        assert!(parse_stat("not stat").is_err());
    }
    #[test]
    fn maps_preserve_names_and_reject_malformed() {
        let text = "1000-2000 rw-p 00000000 00:00 0\n2000-3000 r--p 00000000 08:01 12 /a path/deleted (deleted)\n3000-4000 rw-p 00000000 00:00 0 [anon:fixture]\n";
        let entries = map_entries(text).unwrap();
        assert!(entries[0].anonymous);
        assert!(!entries[1].anonymous);
        assert!(entries[2].anonymous);
        assert_eq!(
            parse_maps(text).unwrap()[1].name.as_deref(),
            Some("/a path/deleted (deleted)")
        );
        for text in [
            "2000-1000 rw-p 0 00:00 0",
            "1000-2000 rwxp 0 00:00",
            "1000-2000 z--p 0 00:00 0",
            "1000-3000 rw-p 0 00:00 0\n2000-4000 rw-p 0 00:00 0",
            "x-ffff rw-p 0 00:00 0",
        ] {
            assert!(parse_maps(text).is_err(), "accepted {text}");
        }
        for name in ["[heap]", "[stack]", "[vdso]", "/file", "[anon_shmem:x]"] {
            assert!(
                !map_entries(&format!("1000-2000 rw-p 0 00:00 0 {name}")).unwrap()[0].anonymous
            );
        }
        // A missing pathname cannot disguise a nonzero inode or device.
        assert!(!map_entries("1000-2000 rw-p 0 00:00 12").unwrap()[0].anonymous);
        assert!(!map_entries("1000-2000 rw-p 0 08:01 0").unwrap()[0].anonymous);
    }
    #[test]
    fn android_multi_user_and_protected_policy() {
        assert!(validate_android_target("com.example.game", 10_123, &[]).is_ok());
        assert!(validate_android_target("com.example.game", 210_123, &[]).is_ok());
        for uid in [0, 1000, 100_001, 120_000, 199_999, 299_999] {
            assert!(validate_android_target("com.example.game", uid, &[]).is_err());
        }
        for package in [
            "com.google.android.gms",
            "com.android.systemui",
            "me.weishu.kernelsu",
            "com.android.launcher3",
        ] {
            assert!(validate_android_target(package, 210_123, &[]).is_err());
        }
        assert!(
            validate_android_target("com.vendor.launcher", 10_123, &["com.vendor.launcher"])
                .is_err()
        );
    }
    #[test]
    fn current_process_is_not_an_owned_fixture_child() {
        // SAFETY: getpid has no preconditions.
        let identity = TargetIdentity::capture(unsafe { libc::getpid() }).unwrap();
        assert!(identity.verify().is_ok());
        assert!(identity.verify_owned_child().is_err());
        assert!(TargetIdentity::capture(0).is_err());
        assert!(TargetIdentity::capture(-1).is_err());
        assert!(parse_uids("Uid: 1 2 3\n").is_err());
        assert!(parse_uids("Uid: 1 2 3 4\nUid: 1 2 3 4\n").is_err());
    }

    /// Only the child branch uses async-signal-safe libc calls after fork, so
    /// this fixture can be created by the multithreaded Rust unit-test harness.
    struct ChildFixture {
        pid: i32,
        control: Option<OwnedFd>,
        range: MemoryRange,
    }
    impl ChildFixture {
        fn spawn() -> Self {
            // SAFETY: all mappings/pipe pointers are checked; child branch only
            // closes/reads descriptors and exits, without calling Rust runtime.
            unsafe {
                let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                assert!(page > 0 && page <= MAX_TRANSFER_BYTES);
                let pointer = libc::mmap(
                    std::ptr::null_mut(),
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert_ne!(pointer, libc::MAP_FAILED);
                let bytes = [
                    1337_i32.to_le_bytes(),
                    42_i32.to_le_bytes(),
                    1337_i32.to_le_bytes(),
                ]
                .concat();
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast::<u8>(), bytes.len());
                let mut pipe = [-1; 2];
                assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC), 0);
                let pid = libc::fork();
                assert!(pid >= 0);
                if pid == 0 {
                    libc::close(pipe[1]);
                    let mut byte = 0_u8;
                    loop {
                        let n = libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
                        if n >= 0 {
                            break;
                        }
                    }
                    libc::_exit(0);
                }
                libc::close(pipe[0]);
                let range = MemoryRange {
                    start: pointer as u64,
                    end: pointer as u64 + page as u64,
                    readable: true,
                    writable: true,
                    executable: false,
                    private: true,
                    name: None,
                };
                assert_eq!(libc::munmap(pointer, page), 0);
                Self {
                    pid,
                    control: Some(OwnedFd::from_raw_fd(pipe[1])),
                    range,
                }
            }
        }
        fn session(&self, grants: &str) -> MemorySession {
            MemorySession::for_fixture(
                TargetIdentity::capture(self.pid).unwrap(),
                self.range.clone(),
                auth(grants),
            )
            .unwrap()
        }
    }
    impl Drop for ChildFixture {
        fn drop(&mut self) {
            drop(self.control.take());
            // SAFETY: reap only our owned child; no borrowed pointers.
            unsafe {
                // Concurrent fork tests can inherit other fixtures' control-pipe
                // writers. Terminate this owned, unreaped child explicitly so
                // cleanup never depends on unrelated inherited descriptors.
                libc::kill(self.pid, libc::SIGTERM);
                while libc::waitpid(self.pid, std::ptr::null_mut(), 0) < 0 {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        break;
                    }
                }
            }
        }
    }
    #[test]
    fn owned_fixture_scan_refine_and_write() {
        let child = ChildFixture::spawn();
        let mut session = child.session("// @grant mem.read\n// @grant mem.write_heap\n");
        assert_eq!(session.maps().unwrap().len(), 1);
        assert_eq!(session.scan_i32(1337).unwrap(), 2);
        let addresses = session.results(1024).unwrap();
        assert_eq!(addresses, vec![child.range.start, child.range.start + 8]);
        assert_eq!(
            session.read(addresses[0], 4).unwrap(),
            1337_i32.to_le_bytes()
        );
        assert_eq!(
            session.write(addresses[0], &55_i32.to_le_bytes()).unwrap(),
            4
        );
        assert_eq!(session.refine_i32(1337).unwrap(), 1);
        assert_eq!(session.edit_all_i32(7331).unwrap(), 1);
        assert_eq!(
            session.read(child.range.start + 8, 4).unwrap(),
            7331_i32.to_le_bytes()
        );
        assert_eq!(session.scan_i32(7331).unwrap(), 1);
        assert!(session.results(MAX_RESULTS + 1).is_err());
        assert!(session.read(u64::MAX, 4).is_err());
        assert!(session.read(child.range.end - 2, 4).is_err());
        assert!(session.write(child.range.start - 1, &[0]).is_err());
        assert!(session.read(child.range.start, 0).is_err());
        assert!(
            session
                .read(child.range.start, MAX_TRANSFER_BYTES + 1)
                .is_err()
        );
    }
    #[test]
    fn fixture_permissions_range_and_budget_enforced() {
        let child = ChildFixture::spawn();
        let mut no_permissions = child.session("");
        assert!(no_permissions.maps().is_err());
        assert!(no_permissions.read(child.range.start, 4).is_err());
        assert!(no_permissions.scan_i32(1337).is_err());
        assert!(no_permissions.refine_i32(1337).is_err());
        assert!(no_permissions.results(1).is_err());
        assert!(no_permissions.edit_all_i32(5).is_err());
        let mut read_only = child.session("// @grant mem.read\n");
        assert!(
            read_only
                .write(child.range.start, &1_i32.to_le_bytes())
                .is_err()
        );
        assert_eq!(read_only.scan_i32(1337).unwrap(), 2);
        assert!(read_only.edit_all_i32(2).is_err());
        read_only.scan_budget = 0;
        assert!(read_only.scan_i32(1337).is_err());
        assert!(read_only.results(1).unwrap().is_empty());
        for permission in 0..3 {
            let mut range = child.range.clone();
            match permission {
                0 => range.executable = true,
                1 => range.private = false,
                _ => range.writable = false,
            }
            assert!(
                MemorySession::for_fixture(
                    TargetIdentity::capture(child.pid).unwrap(),
                    range,
                    auth("// @grant mem.read\n")
                )
                .is_err()
            );
        }
        let mut bad = child.range.clone();
        bad.start += 1;
        assert!(
            MemorySession::for_fixture(
                TargetIdentity::capture(child.pid).unwrap(),
                bad,
                auth("// @grant mem.read\n")
            )
            .is_err()
        );
        let mut bad = child.range.clone();
        bad.name = Some("[heap]".into());
        assert!(
            MemorySession::for_fixture(
                TargetIdentity::capture(child.pid).unwrap(),
                bad,
                auth("// @grant mem.read\n")
            )
            .is_err()
        );
    }
    #[test]
    fn exited_child_identity_never_remains_authorized() {
        let child = ChildFixture::spawn();
        let mut session = child.session("// @grant mem.read\n");
        let address = child.range.start;
        drop(child); // closes control pipe and reaps the target
        assert!(session.maps().is_err());
        assert!(session.read(address, 4).is_err());
        assert!(session.results(1).is_err());
    }
}
