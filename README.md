# KSU ModEngine

**v0.1.0 Linux 开发预览**。已打通脚本清单 → 全文 SHA-256 授权 → 独立 Lua / JavaScript Runner → IPC → 宿主内存操作的完整流程。演示只访问宿主自己创建的测试进程，将 `[1337, 42, 1337]` 修改为 `[7331, 42, 7331]`。

这是向 [原始方案](KSU-ModEngine-Plan.md) 推进的第一个可运行版本。Android KernelSU 模块安装、任意应用接入、绘制和触控、eBPF/perf、MCP 尚未实现。WebUI 目前提供脚本审阅和 CLI 命令生成。

## 快速开始

需要 Linux、Rust/Cargo 1.92+、C 编译器和 make。Lua 5.4.8、QuickJS-ng 0.11.0 随 Cargo 依赖源码编译，无需系统安装 Lua 或 QuickJS。首次构建需要联网。

```bash
cargo build --workspace --locked
./target/debug/ksu-mod-hostd doctor --json
./target/debug/ksu-mod-hostd inspect-script examples/demo.lua --json
```

检查自带示例后，批准这份文件的全文摘要并运行：

```bash
KSU_APPROVAL=$(sha256sum examples/demo.lua | cut -d ' ' -f 1)
./target/debug/ksu-mod-hostd run examples/demo.lua \
  --fixture --approve "$KSU_APPROVAL" --development-sandbox
```

将 `examples/demo.lua` 换成 `examples/demo.js` 可运行 JavaScript。输出会展示真实 fixture 的修改前后数值。修改源码后需重新检查并批准摘要；授权不会持久保存。

默认使用 **strict** 沙箱，需要 root 和 namespace 权限，无法进入时明确报错。上面的 `--development-sandbox` 是普通 Linux 用户运行自有测试脚本的显式选项，保留当前 UID 和 namespace，仅启用资源限制、FD 清理、no_new_privs 和 seccomp。请只用它运行可信的本地 fixture 脚本。strict 的完整降权与隔离路径尚未在特权环境中验证。

## 管理界面

需要 Node.js 22.12+ 和项目指定的 pnpm；本机已验证 Node 26.7 / pnpm 12.9.1。

```bash
pnpm --dir webui install --frozen-lockfile
pnpm --dir webui run dev
```

访问终端给出的本地地址。支持导入、编辑、保存脚本，预览清单/权限/全文摘要，并复制带明确授权的 CLI 命令。请先将当前源码保存到命令指定的文件，再用宿主检查。浏览器解析是预览，最终授权由宿主执行；页面尚未连接可直接运行脚本的后端。

## 模块与边界

| 目录 | 当前职责 |
| --- | --- |
| `hostd` | CLI、自建 fixture、权限批准、子进程管理、IPC 请求预算和执行监督 |
| `engine-core` | 严格清单解析、源码绑定、目标身份与映射复验、i32 搜索/过滤/读写 |
| `ipc-proto` | SOCK_SEQPACKET、16 字节帧头、MessagePack、有界编解码与 FD 拒收 |
| `runners/sandbox-common` | strict / development 隔离、资源限制、系统调用白名单 |
| `runners/runner-lua54` | Lua 5.4、engine API、基础 GG DWORD 子集 |
| `runners/runner-qjs` | QuickJS-ng、engine API、64 位地址字符串 |
| `webui` | 中文脚本审阅与命令生成界面 |

v0.1 只批准 `mem.read` / `mem.write_heap`；写权限需要同时申请读权限。目标必须包含 `com.example.ksumod.fixture`，无任意 PID 参数。每次内存访问限于该直接子进程的一页匿名私有可写非执行内存，复验进程身份与映射。内存写入可能部分完成，不能回滚。

源码 ≤48 KiB，IPC 载荷 ≤64 KiB，单次内存传输 ≤16 KiB，结果 ≤1024 条。默认 VM 堆上限 64 MiB、脚本预算 2 秒；宿主独立监督运行阶段，预算 5 秒、10000 个请求、64 KiB 日志。启动前的文件读取及系统调用受系统调度和存储状态影响，5 秒不构成整个命令的硬实时保证。

JavaScript 首版为同步执行：创建或使用 Promise、调用 async 函数会令本次执行失败，不提供定时器或异步 I/O。Lua 不提供 io/os/package/debug、动态加载、协程或 bytecode 加载。GG 仅实现 DWORD 基础操作；不承诺完整 GG 或 Frida API 兼容。

## 验证与打包

完整检查需要 rustfmt、clippy、Python 3、Node 和 pnpm：

```bash
bash scripts/check.sh
bash scripts/package-preview.sh
```

检查包括格式、clippy、Rust 单元/子进程测试、真实 CLI 端到端测试、Web 测试和生产构建。Python 测试用 `KSU_HOSTD=/绝对路径/ksu-mod-hostd` 可验证另一组同目录下的宿主与 Runner。

预览包输出到 `dist/`，包含三个原生二进制、示例、Web 静态文件、文档、锁文件及 SHA-256 校验文件。解压后在目录内运行 `./bin/ksu-mod-hostd doctor --json`，示例命令的程序路径相应改为 `./bin/ksu-mod-hostd`。包依赖构建主机兼容的 Linux/glibc，不是 Android 模块 ZIP。

架构约定见 [V0.1-CONTRACT.md](docs/V0.1-CONTRACT.md)，方案评价与推进顺序见 [开发简报](docs/DEVELOPMENT-BRIEF.md)，环境和依赖检查见 [依赖报告](docs/DEPENDENCIES.md)，本轮结果见 [验证记录](docs/VALIDATION.md)。
