mod bridge;
use bridge::{bootstrap, finish, ready};
use mlua::{ChunkMode, HookTriggers, Lua, LuaOptions, StdLib, VmState};
use std::{cell::Cell, rc::Rc, time::Instant};

fn run() -> Result<(), String> {
    let (boot, config, shared) = bootstrap()?;
    let result = execute(&boot, &config, &shared);
    finish(&shared, result.err())
}

fn execute(
    boot: &ipc_proto::Bootstrap,
    config: &sandbox_common::SandboxConfig,
    shared: &bridge::Shared,
) -> Result<(), String> {
    // Excluding coroutine prevents new Lua threads bypassing the main-thread hook.
    let lua = Lua::new_with(
        StdLib::TABLE | StdLib::STRING | StdLib::UTF8 | StdLib::MATH,
        LuaOptions::default(),
    )
    .map_err(|e| e.to_string())?;
    lua.set_memory_limit(boot.memory_limit_bytes as usize)
        .map_err(|e| e.to_string())?;
    let host = shared.clone();
    lua.globals()
        .set(
            "_host",
            lua.create_function(move |_, (op, a, b): (String, String, String)| {
                host.borrow_mut()
                    .dispatch(&op, &a, &b)
                    .map_err(mlua::Error::runtime)
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    lua.load(include_str!("api.lua"))
        .set_mode(ChunkMode::Text)
        .exec()
        .map_err(|e| e.to_string())?;
    let deadline = Rc::new(Cell::new(Instant::now()));
    let hook_deadline = deadline.clone();
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(1000),
        move |_, _| {
            if Instant::now() >= hook_deadline.get() {
                Err(mlua::Error::runtime("execution deadline exceeded"))
            } else {
                Ok(VmState::Continue)
            }
        },
    )
    .map_err(|e| e.to_string())?;
    // Instantiate all host/VM state before seccomp; no VM execution until ready is acknowledged.
    sandbox_common::enter(config).map_err(|e| format!("sandbox setup failed: {e}"))?;
    deadline.set(ready(shared, &config.mode, boot.timeout_ms)?);
    let result = lua
        .load(&boot.source)
        .set_name(&boot.script_name)
        .set_mode(ChunkMode::Text)
        .exec();
    let mut error = result.err().map(|e| e.to_string());
    if Instant::now() >= deadline.get() {
        error = Some("execution deadline exceeded".into());
    }
    error.map_or(Ok(()), Err)
}
fn main() {
    if let Err(error) = run() {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "runner-lua54: {}",
            bridge::bounded(&error, 4096)
        );
        std::process::exit(1);
    }
}
