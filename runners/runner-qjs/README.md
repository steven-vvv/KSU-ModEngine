# QuickJS-ng runner

Uses the QuickJS-ng 0.11.0 C runtime bundled in `rquickjs-sys` 0.11.0.
No external JavaScript interpreter or QuickJS std/os module is used. The
synchronous engine API accepts hex string addresses (or BigInt inputs), preserving
all 64 address bits. Promise jobs are not pumped; use synchronous scripts.

`tests/runtime.rs` runs the actual binary in a development sandbox child with a
stub IPC host. It covers engine roundtrips, 64-bit addresses, denied globals,
host errors becoming exceptions, deadlines, and memory exhaustion. It must never
install seccomp in the cargo test process itself.

The private bridge is intentionally duplicated with runner-lua54 to keep the
frozen IPC crate independent of VM-specific runner policy. Changes to bridge
validation should be kept in sync between both copies.
