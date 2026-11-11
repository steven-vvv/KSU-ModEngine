# Lua 5.4 runner

Uses vendored Lua 5.4 through mlua. Only base, table, string, UTF-8 and math
libraries are initialized. Coroutine is absent so new Lua threads cannot bypass
the execution hook. Source/bytecode loaders, bytecode dumping, package, debug,
filesystem, process, and module interfaces are unavailable.

Addresses are positive signed 64-bit Lua integers. The gg compatibility surface
is limited to TYPE_DWORD, searchNumber(value, flags), getResults(limit),
editAll(value, flags), and setValues({{address, flags, value}, ...}). Extended
search arguments and other type flags raise errors. No transaction or rollback
is promised for writes.

`tests/runtime.rs` runs the actual binary in a development sandbox child with a
stub IPC host. It exercises memory roundtrips, large integer addresses, host
errors, denied libraries, deadlines and memory exhaustion. The private bridge is
intentionally duplicated with runner-qjs; keep validation changes synchronized.
