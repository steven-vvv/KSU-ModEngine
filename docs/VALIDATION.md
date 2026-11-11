# v0.1 验证记录

日期：2026-11-11。平台：AlmaLinux 10.2 / x86_64 / Linux 6.12 / 4 KiB 页，普通用户运行。

## 已通过

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 通过 |
| `cargo test --workspace --locked` | 36 项测试通过，另有独立进程沙箱测试的 3 个场景通过 |
| `python3 tests/e2e.py` | 11 项真实 CLI 端到端测试通过 |
| `pnpm --dir webui run test` | 5 项测试通过 |
| `pnpm --dir webui run build` | TypeScript 检查和 Vite 生产构建通过 |
| headless Chromium 交互验证 | 9 项检查通过，桌面和移动布局已查看 |
| `pnpm --dir webui audit --json` | 当次报告 0 项已知漏洞 |
| `cargo build --workspace --release --locked` | 通过 |
| 解压预览包后以其宿主/Runner 再跑 E2E | 11 项通过，包外和包内 SHA-256 校验通过 |

Rust 测试包括清单与授权绑定、未知/未实现权限拒绝、Android 多用户策略辅助函数、目标身份与映射、fixture 搜索/过滤/写入、IPC 截断/畸形帧/FD 拒收，以及两个 VM 的真实进程 IPC、64 位地址、禁用 API、内存限额和超时。strict 缺少条件时，Runner 必须在 Ready 前报告原因并失败。

E2E 验证 Lua 和 JavaScript 都将自建子进程的 `[1337,42,1337]` 改为 `[7331,42,7331]`，并回收子进程。还覆盖源码变更后旧摘要失效、权限拒绝、越界、目标不匹配、默认 strict 失败且不降级、死循环、异步脚本明确失败、非法 UTF-8、超大源码和 FIFO 输入。

浏览器交互检查包括真实 WebCrypto 摘要与独立 Node SHA-256 比对、strict 默认/开发开关、无效权限阻断、源码变化、异步摘要完成顺序反转、HTML 注入防护、shell 引号、文件导入和示例切换。浏览器解析仍是预览，宿主是最终授权方。

## 本机 Release 大小与依赖

| 二进制 | 字节数 |
| --- | ---: |
| ksu-mod-hostd | 898832 |
| runner-lua54 | 1127752 |
| runner-qjs | 1811928 |

`ldd` 未发现缺失库。宿主依赖 `libgcc_s`、`libc` 和 Linux 动态加载器；两个 Runner 另外依赖 `libm`。体积与兼容性仅适用于本次 Linux x86_64 构建。

## 尚未验证

- root/namespace 权限齐备时的完整 strict 成功路径、降权和父进程退出行为。
- Android/Bionic 交叉编译、4/16 KiB 设备、KernelSU 安装、SELinux 与实际 App 目标。
- RustSec 漏洞数据库审计（当前没有 cargo-audit）。
- 性能、截图行为、绘制、触控、eBPF/perf、MCP 与完整 GG/Frida 兼容。

本轮没有修改系统安全策略、以 root 运行或安装 Android SDK。临时浏览器与开发服务已停止；Rust 工具链和构建缓存保留在忽略目录，供后续开发复用。
