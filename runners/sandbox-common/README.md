# Runner sandbox v0.1

`enter` is destructive and must run in a dedicated single-threaded Linux Runner
only, after VM/dynamic-loader initialization and before evaluating source. An
error is fatal even if it occurred after some process state changed. It never
falls back from strict to development. Linux `close_range` is required.

Strict requires root and mount/network namespace privileges. It makes mount
propagation private, overlays the supplied empty directory with a read-only,
noexec/nosuid/nodev empty tmpfs, chroots, clears supplementary groups, bounding
and ambient capabilities, changes real/effective/saved GID and UID to 65534,
clears effective/permitted/inheritable capabilities and disables dumpability.
Because changing UID/GID clears the Linux parent-death signal, strict entry
captures the parent PID before isolation, re-arms SIGKILL after credential drops
and fails if the parent PID changed during that window.
The parent owns creation/removal of the empty directory. Namespace or credential
failures are reported precisely. Strict success cannot be exercised by an
ordinary unprivileged account; no host configuration should be changed to hide
this limitation.

Development must be selected explicitly. It retains the caller's namespace and
credentials and provides only no_new_privs, resource limits, descriptor cleanup,
and the same seccomp policy. It is for trusted local fixture scripts only.

Both modes keep only the AF_UNIX SOCK_SEQPACKET descriptor 3; stdin, stdout,
stderr and every other descriptor are closed. The filter allows read/write,
sendto/recvfrom/recvmsg only on fd 3. All ioctl and fcntl operations are denied.
The host is trusted not to send descriptors; the IPC decoder rejects ancillary
data. No descriptor duplication, opening, networking, process creation, exec,
ptrace, process_vm access, signal sending, or executable mappings are allowed.
Seccompiler 0.5 generates the audit architecture guard (architecture mismatch
kills); unmatched native syscalls return EPERM. This also rejects x32 syscall
numbers on x86_64.

VM allocator support is deliberately small: brk, anonymous private mmap with
exact MAP_PRIVATE|MAP_ANONYMOUS flags and READ/WRITE/NONE protections, munmap,
mprotect without EXEC, and mremap with at most MAYMOVE. No file mappings, fixed
mmap, shared mappings, or DONTUNMAP. Private futex WAIT/WAKE, clock_gettime,
sched_yield, restart_syscall, close, rt_sigreturn and process exit complete the
runtime allowlist. There are no threads, post-filter module loading, OS entropy
calls or signal-handler installation. Initialize any VM facilities needing those
before calling enter. Lua and QuickJS interpreter execution does not need JIT
pages. A VM upgrade may need a reviewed policy change; errors do not relax it.

The VM separately enforces `memory_limit_bytes` as its heap budget. RLIMIT_AS
allows that budget plus 256 MiB for already loaded libraries, runtime mappings,
stack and allocator overhead; it is not a promise that all heap allocations will
succeed. RLIMIT_CPU uses the supplied seconds (whole-process CPU time, including
initialization); the host also enforces a wall deadline. Core/file size and task
creation limits are zero; descriptor limit is four. Existing stricter hard limits
are preserved. CPU exhaustion can kill the Runner without a Finished packet.

`cargo test -p sandbox-common` runs a harness-free test executable that spawns
fresh helper processes. Only those helpers install the filter. It checks
explicit development, strict rejection without its prerequisites, inherited FD
cleanup, IPC/mapping functionality and EPERM for dangerous syscalls. Strict
success requires a separate privileged integration environment and remains an
explicit limitation on ordinary developer machines.

Helper failures and panics are reported to the test parent over descriptor 3,
including failures after stdio has been closed. Thread-enumeration DirEntry
values are released before close_range: their retained directory streams must
not outlive descriptor cleanup. Strict credential-drop and parent-death behavior
still require a privileged integration environment for end-to-end validation.
