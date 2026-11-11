//! A dedicated executable, never installs seccomp in cargo or its parent test process.
use sandbox_common::{SandboxConfig, SandboxMode, enter};
use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

fn main() {
    let scenario = std::env::args().nth(1);
    if let Some(scenario) = scenario {
        child(&scenario);
        return;
    }
    for scenario in ["development", "strict-unavailable", "invalid-fd"] {
        let mut sockets = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    sockets.as_mut_ptr(),
                )
            },
            0
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg(scenario)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(sockets[1], 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = command.status().unwrap();
        unsafe {
            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
        assert!(
            status.success(),
            "sandbox child {scenario} failed: {status}"
        );
    }
}
fn child(scenario: &str) {
    let config = SandboxConfig {
        mode: if scenario == "strict-unavailable" {
            SandboxMode::Strict
        } else {
            SandboxMode::Development
        },
        ipc_fd: if scenario == "invalid-fd" { 4 } else { 3 },
        memory_limit_bytes: 64 * 1024 * 1024,
        cpu_time_seconds: 2,
        empty_root: None,
    };
    if scenario != "development" {
        assert!(enter(&config).is_err());
        return;
    }
    // A high inherited writable descriptor must disappear as well as stdio.
    assert!(unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 100) } >= 100);
    let report = enter(&config).unwrap();
    let mut ok = report.seccomp && !report.namespaces && !report.dropped_privileges;
    unsafe {
        ok &= libc::close(100) == -1 && *libc::__errno_location() == libc::EBADF;
        for fd in [0, 1, 2] {
            ok &= libc::close(fd) == -1 && *libc::__errno_location() == libc::EBADF;
        }
        // No executable operation actually runs; invalid pointers/targets would be safe even absent BPF.
        for (number, args) in [
            (
                libc::SYS_openat,
                [
                    libc::AT_FDCWD as libc::c_long,
                    c"/etc/passwd".as_ptr() as libc::c_long,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            (
                libc::SYS_socket,
                [libc::AF_INET as _, libc::SOCK_STREAM as _, 0, 0, 0, 0],
            ),
            (libc::SYS_execve, [0, 0, 0, 0, 0, 0]),
            (
                libc::SYS_ptrace,
                [libc::PTRACE_PEEKDATA as _, -1, 0, 0, 0, 0],
            ),
            (libc::SYS_kill, [i32::MAX as _, 0, 0, 0, 0, 0]),
            (libc::SYS_clone, [libc::CLONE_THREAD as _, 0, 0, 0, 0, 0]),
            (libc::SYS_process_vm_readv, [i32::MAX as _, 0, 0, 0, 0, 0]),
            (libc::SYS_process_vm_writev, [i32::MAX as _, 0, 0, 0, 0, 0]),
            (
                libc::SYS_mmap,
                [
                    0,
                    4096,
                    (libc::PROT_READ | libc::PROT_EXEC) as _,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as _,
                    -1,
                    0,
                ],
            ),
            (
                libc::SYS_mmap,
                [0, 4096, libc::PROT_READ as _, libc::MAP_PRIVATE as _, 3, 0],
            ),
            (libc::SYS_mprotect, [0, 4096, libc::PROT_EXEC as _, 0, 0, 0]),
            (libc::SYS_ioctl, [3, 0, 0, 0, 0, 0]),
            (libc::SYS_fcntl, [3, libc::F_DUPFD as _, 0, 0, 0, 0]),
            (libc::SYS_write, [2, 0, 0, 0, 0, 0]),
        ] {
            ok &= libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) == -1
                && *libc::__errno_location() == libc::EPERM;
        }
        let memory = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        ok &= memory != libc::MAP_FAILED;
        if memory != libc::MAP_FAILED {
            ok &= libc::munmap(memory, 4096) == 0;
        }
        ok &= libc::send(3, c"ok".as_ptr().cast(), 2, libc::MSG_NOSIGNAL) == 2;
        // Exit directly: the helper intentionally closed harness output and imposed CPU/AS limits.
        libc::_exit(if ok { 0 } else { 1 });
    }
}
