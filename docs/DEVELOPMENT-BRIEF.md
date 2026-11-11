# 开发简报：v0.1

## 方案判断

保留原方案的三个边界：特权宿主负责授权与内存操作，脚本在独立进程执行，绘制和管理界面单独接入。这个方向可落地。先完成可验证的执行与权限流程，再接 Android 和绘制，便于把平台问题与引擎问题分开处理。

需要修正的预期：`process_vm_readv/writev` 不进行 ptrace attach，但仍受 ptrace 访问检查与 SELinux 等策略约束。RW 私有映射也不能单独证明某次写入不会改变程序控制流。不可在缺少设备实测时承诺“完全隐形”、截图不可见、固定 120Hz 或固定二进制体积。

Android 目标身份需要同时处理 Package Manager、Android 多用户 appId、受保护包、进程启动时间/pidfd、映射变化和目标退出。16 KiB 页兼容需要交叉编译、ELF 检查和实机验证，增加链接参数只是其中一步。

## 本轮实现

- Rust workspace、固定依赖图和六个组件：宿主、核心、协议、沙箱与两个 Runner。
- 严格脚本清单、全文 SHA-256 批准、最小 capability 校验。
- SOCK_SEQPACKET/MessagePack 有界 IPC，连续请求 ID、Ready/Finished 握手、超时和日志预算。
- 自建 fixture 子进程的一页匿名内存，真实 process_vm 搜索/过滤/读写。
- Lua 5.4 与 QuickJS-ng VM、执行/内存预算、受控 engine API 和基础 GG DWORD 兼容。
- explicit development 沙箱，以及失败即终止的 strict 隔离实现。
- 中文 WebUI、示例、检查脚本、端到端回归与 Linux 预览包。

主代理负责架构、接口冻结、集成、检查和交付。GPT-6.1 Sol 子代理分别实现协议、核心、沙箱、Runner、宿主和 WebUI，并交叉审查。各任务使用隔离 Git worktree，统一目标目录和 Cargo 两个构建任务上限，避免在 4 vCPU 主机上重复编译。已完成的提交整合进主工作区，未推送到远端。

## 下一阶段

1. 补齐 Android NDK/ADB，交叉编译 aarch64，验证 Bionic 接口与 4/16 KiB ELF 对齐。
2. 在受控 root/KernelSU 测试设备验证完整 strict 路径、SELinux、capability/FD 清理、父进程退出和异常回收。
3. 实现 Package Manager 身份解析和受保护目标策略，再以设备上自有测试 App 替换 Linux fixture。
4. 接入 Android 管理 transport、模块安装生命周期与持久授权，再扩展绘制。eBPF/perf/MCP 按依赖和实测结果推进。

首版保留的边界：strict 成功路径未在当前普通用户环境验证；没有 Android 可安装模块；没有任意目标进程接口；没有全量 GG/Frida 兼容。fixture 的进程身份和映射检查仍有系统调用之间的竞态，当前安全范围依赖宿主自建、未回收、协作式且映射固定的子进程。
