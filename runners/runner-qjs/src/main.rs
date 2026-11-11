mod bridge;
use bridge::{bootstrap, finish, ready};
use rquickjs::{Context, Ctx, Exception, Function, Runtime};
use std::{cell::Cell, rc::Rc, time::Instant};

fn run() -> Result<(), String> {
    let (boot, config, shared) = bootstrap()?;
    // rquickjs-sys 0.11.0 embeds QuickJS-ng 0.11.0, not an external process.
    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    runtime.set_memory_limit(boot.memory_limit_bytes as usize);
    runtime.set_max_stack_size(512 * 1024);
    let context = Context::full(&runtime).map_err(|e| e.to_string())?;
    let host = shared.clone();
    context.with(|ctx| -> rquickjs::Result<()> {
        let callback = Function::new(ctx.clone(), move |ctx: Ctx<'_>, op: String, a: String, b: String| -> rquickjs::Result<String> {
            host.borrow_mut().dispatch(&op, &a, &b).map_err(|e| Exception::throw_message(&ctx, &e))
        })?;
        ctx.globals().set("_host", callback)?;
        ctx.eval::<(), _>(include_str!("api.js"))
    }).map_err(|e| e.to_string())?;
    let deadline = Rc::new(Cell::new(Instant::now()));
    let interrupt_deadline = deadline.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= interrupt_deadline.get())));
    sandbox_common::enter(&config).map_err(|e| e.to_string())?;
    deadline.set(ready(&shared, &config.mode, boot.timeout_ms)?);
    let mut error = context.with(|ctx| {
        match ctx.eval::<(), _>(boot.source.as_bytes()) {
            Ok(()) => None,
            Err(e) if e.is_exception() => {
                // The deadline interrupt remains armed while retrieving an exception message.
                let caught = ctx.catch();
                if let Some(s) = caught.as_string() { Some(s.to_string().unwrap_or_else(|_| "JavaScript exception".into())) }
                else if let Some(exception) = caught.as_exception() { Some(exception.message().unwrap_or_else(|| "JavaScript exception".into())) }
                else { Some("JavaScript exception".into()) }
            }
            Err(e) => Some(e.to_string()),
        }
    });
    if Instant::now() >= deadline.get() { error = Some("execution deadline exceeded".into()); }
    finish(&shared, error)
}
fn main() {
    if let Err(error) = run() {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "runner-qjs: {}", bridge::bounded(&error, 4096));
        std::process::exit(1);
    }
}
