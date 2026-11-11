# engine-core v0.1

This crate implements the Linux **owned fixture** path in the frozen contract.
It does not attach to Android applications or grant a Runner authority over a PID.

`Manifest::parse` accepts an initial `// ==ModScript==` JS header or
`-- ==ModScript==` Lua header (blank leading lines permitted). Singleton fields
are required exactly once; repeated match/grant/connect entries are rejected.
Unknown fields/grants and malformed packages/domains fail parsing. Known future
permissions and wildcard targets can be inspected but cannot be authorized.
`Authorization::approve` verifies the explicit full-source SHA-256 and reparses
that exact UTF-8 source, comparing all manifest fields and its private source
binding. Mutating a public Manifest field does not create authority. Only
`mem.read` and `mem.write_heap` are implemented; writing also requires reading.

`MemorySession::for_fixture` requires a matching fixture manifest and a directly
owned child with all four Linux UIDs equal to the host effective UID. Its trusted
range must be exactly one aligned host page (at most 16 KiB), within an anonymous,
private, readable/writable, non-executable VMA with an empty or `[anon:*]` name.
No file mappings, shared mappings, heap/stack/vDSO special mappings or arbitrary
PID/range supplied by a script are accepted. A supplied page may be contained in
a larger anonymous VMA because Linux can merge adjacent anonymous allocations.
Every operation rechecks identity and mappings; results expose only the approved
page. PID start time, parent and UIDs must remain stable; pidfd is used when the
kernel permits it. There is no ptrace or `/proc/PID/mem` fallback.

Transfers are 1–16384 bytes. Scans examine aligned little-endian i32 values in a
bounded snapshot and retain the first 1024 matches. Each scan/refine has a 1 MiB
byte budget and the session has a cumulative 16 MiB scan budget. Result limits
above 1024 fail. `edit_all_i32` returns edited values, while `write` returns bytes.
Short kernel transfers are explicit errors. Any write error can follow partial
or completed modification; there is no transactional rollback.

Linux does not provide an atomic operation combining `/proc` VMA validation and
`process_vm_readv`/`process_vm_writev`. Even with a pidfd the numeric-PID transfer
and map checks have inherent TOCTOU windows, and an adversarial target can remap
memory between checks. This API is intended solely for a cooperative child whose
lifetime and page allocation the trusted host controls. Identity checks and
post-transfer checks do not turn it into a safe general app-attachment API.

`validate_android_target` is only a future policy helper: it extracts multi-user
appId with `uid % 100000`, requires ordinary app IDs 10000–19999, and rejects
known protected packages plus a caller-provided protection list. Trusted Package
Manager resolution, vendor launcher discovery, manager identity and Android
transport are not implemented. Callers must never treat arbitrary package/UID
arguments as proof of Android target identity.

Unit tests cover parser and authorization attacks, map/stat parsing, multi-user
policy, permission and address bounds, and an actual isolated direct child with
scan/refine/read/write. The fork test child executes only async-signal-safe libc
calls before `_exit`. The parent always closes its control pipe and reaps it.
