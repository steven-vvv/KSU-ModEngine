# Linux fixture host v0.1

Build the workspace binaries together, so `ksu-mod-hostd`, `runner-lua54` and
`runner-qjs` are siblings. The host never searches PATH for a Runner.

```
ksu-mod-hostd doctor --json
ksu-mod-hostd inspect-script examples/fixture.js --json
ksu-mod-hostd run examples/fixture.js --fixture --approve EXACT_SOURCE_SHA256 --development-sandbox --json
```

Use the digest printed by `inspect-script` for explicit approval. Source is read
once from a regular UTF-8 file, bounded to 48 KiB, parsed and hashed; precisely
those bytes go to the Runner. `inspect-script` assesses authorization using the
actual source digest without running anything. Unknown extensions report
unsupported; execution accepts `.lua` and `.js` only. Known unimplemented grants,
network access, wildcard targets and manifests missing the fixture package fail.

Strict is the default and never falls back to development. On an ordinary
unprivileged developer account, strict execution fails accurately. Explicit
`--development-sandbox` is for trusted local fixture scripts. Doctor reports
observed platform, namespace paths, effective UID and Runner paths; it leaves
strict availability unknown because successful entry requires more than root or
namespace files. Android attachment and installation are not implemented.

Each execution spawns its own anonymous-page fixture initialized to
`[1337,42,1337]`. No public argument selects a PID, UID or arbitrary address range.
The hidden `__fixture-target` subcommand only creates its own page, publishes its
address and waits on stdin. The host validates its identity with engine-core and
routes all script memory requests through the authorized MemorySession. The
fixture control pipe supplies final values independently of script grants.

Children receive an empty environment, controlled stdio and no inherited
nonstandard descriptors except the Runner IPC endpoint at FD 3. The pre-exec
setup handles an endpoint already numbered 3 and preserves exec-error reporting
until exec. It installs a parent-death signal with a parent PID race check. Strict
sandbox credential changes must re-arm that signal after dropping privileges.
Every return path kills and reaps both owned children; the strict empty directory
is uniquely created with mode 0700 and removed after Runner reaping.

The host requires consecutive request IDs, exactly one SandboxReady matching the
selected mode, and readiness before logs or memory requests. A pre-ready failed
Finished is accepted for reporting sandbox errors. Successful execution requires
Finished acknowledgement, zero Runner exit and clean IPC EOF without extra
packets. Limits: 10000 requests, 64 KiB logs, 2 seconds VM budget, 64 MiB VM heap,
and an independent 5 second host wall deadline. Socket receive/send timeouts are
100 ms; framing errors, early EOF, budget violations and nonzero exits fail.
Memory denials become bounded Response::Error packets and thus VM exceptions.

JSON mode writes one parseable object to stdout on success or error; failures
exit 1. Human output escapes terminal control characters in logs and other
untrusted strings. Child stdout/stderr never contaminates host JSON output.
Unit tests cover CLI authorization requirements and display escaping. Full
Runner/fixture integration tests are coordinated at workspace level.
