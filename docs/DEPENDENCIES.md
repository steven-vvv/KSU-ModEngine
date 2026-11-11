# 依赖检查（2026-11-11）

## 已验证的 Linux 开发环境

AlmaLinux 10.2 / x86_64，Linux 6.12，4 KiB 页，普通用户 UID 1001。Rust/Cargo 1.92.0、GCC 14.3.1、Node 26.7.0、pnpm 12.9.1 已用于构建。构建并行度限制为 2。Rust 格式化和 clippy 使用相同版本的官方工具链，不修改系统 Rust。本机补齐的工具链位于 Git 忽略的 `.tools/rust`，检查/打包脚本会优先使用；其他机器需要自行提供 Rust、rustfmt 和 clippy。

| 依赖 | 锁定版本 | 用途 |
| --- | --- | --- |
| mlua | 0.11.6 | Lua 5.4 接口，启用 `lua54,vendored` |
| Lua | 5.4.8 | `lua-src 550.0.0` 中实际选择的源码；包名不代表使用 Lua 5.5 |
| rquickjs / rquickjs-sys | 0.11.0 | 内嵌 QuickJS-ng 0.11.0 |
| seccompiler | 0.5.0 | seccomp BPF 过滤器 |
| libc | 0.2.191 | Linux 进程、内存、FD 与隔离接口 |
| serde / serde_json | 1.0.229 / 1.0.154 | 消息与 CLI JSON |
| rmp-serde | 1.3.1 | MessagePack |
| sha2 | 0.10.9 | 全文 SHA-256 |
| thiserror | 2.0.21 | 核心错误类型 |
| TypeScript / Vite | 5.9.3 / 7.3.8 | Web 静态构建 |

Rust 元数据包含 57 个外部包，最高声明的依赖 MSRV 为 1.85；项目要求 Rust 1.92。Cargo.lock 与 pnpm-lock.yaml 已提交。`luajit-src` 是 mlua-sys 的构建依赖之一；本项目启用的是 Lua 5.4，未启用 LuaJIT 或 JIT 执行页。

`pnpm audit --json` 在本次检查中报告 0 项已知漏洞。Rust 依赖已经锁定、编译和测试，但当前未安装 cargo-audit，因此没有完成 RustSec 数据库审计；不能据此宣称全部依赖无漏洞。

## Android 阶段仍缺少的工具和验证

当前 PATH 中没有 ADB、Clang、CMake、Ninja；未配置 Android NDK 和 Android Rust 目标。Linux 预览使用 GCC 构建内嵌 C 源码，不依赖这些 Android 工具。未为首版下载完整 Android SDK，避免占用有限磁盘空间。

后续需补齐 NDK/ADB、Android Rust target，并核实 libc/seccomp/降权代码的 Bionic 兼容、16 KiB 页、KernelSU 接口及设备 SELinux 策略。仓库已为 Android 目标预设 16 KiB 链接页参数，该配置尚未经过交叉编译和设备运行验证。

## 运行时依赖

宿主和 Runner 必须放在同一目录。Linux 需提供 `/proc`、`process_vm_readv/writev`、Unix SEQPACKET、seccomp、no_new_privs 和 close_range；strict 另需 root 与 mount/network namespace 权限。doctor 报告环境事实，strict 可用性只有成功完成隔离后才能确认。

Lua 与 QuickJS 以源码形式随二进制构建，无需外置解释器。原生预览包仍依赖 Linux 系统动态链接库；发行包兼容性以构建平台和实际 `ldd` 结果为准，不承诺在任意 Linux 或 Android 上运行。
