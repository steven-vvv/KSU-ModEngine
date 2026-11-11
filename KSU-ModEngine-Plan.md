# KernelSU 下一代外置内存分析与托管绘制引擎技术计划书

> **项目定位**：面向 Android 14–16（重点适配 Android 16 / GKI 6.12 / ARM64）的 **微内核（Capability Microkernel）+ 沙箱脚本化** 外部动态分析、内存修改与无痕矢量绘制工具模块。  
> **核心理念**：内核/系统调用级无痕分析（免 `ptrace`、免注入） + 进程级防格机沙箱（`Lua 5.4` / `QuickJS-ng` 双运行时） + 托管式反截图 SVG/UI 渲染（`ThorVG` + `Dear ImGui`） + 脚本化远程 AI 逆向工作站（`MCP Streamable HTTP` / `REST`）。

---

## 1. 背景与解决痛点

1. **传统附加工具失效**：Google Play 自动完整性保护（`PairIP` / `libpairipcore.so`）及现代反调试普遍检查 `TracerPid`（拦截 GG/GDB `ptrace`）、扫描 `/proc/self/maps`（拦截 Frida/Zygisk 注入）并周期校验 `.text` 段哈希（拦截 Inline Hook 与部分软断点）。
2. **常规悬浮窗易被风控标记**：Google Play Integrity API 的 `appAccessRiskVerdict` 会在系统层检测用户态 `SYSTEM_ALERT_WINDOW` 悬浮窗与非白名单无障碍服务；同时 Android 15/16 已封死纯 `app_process` 免安装调用 `WindowManager.addView` 的旧路径。
3. **第三方脚本安全隐患（恶意格机/盗号）**：传统 Root 脚本生态缺乏内核级隔离，恶意混淆脚本极易通过残留命令接口或跨进程写 Shellcode（“借刀杀人”）损毁分区或窃取账号凭证。
4. **AI 辅助逆向断层**：缺乏将手机端无痕内存扫描、硬件断点与桌面端 LLM Agent（通过最新 MCP 协议）无缝打通且支持一键沉淀为独立安全脚本的闭环工具。

---

## 2. 总体微内核架构

采用 **“特权能力宿主 + 渲染隔离进程 + 零信任脚本沙箱池”** 三分离架构。包括 MCP/REST 远程服务在内的高阶工具均作为**受权限清单管控的特权脚本**运行，保持底层宿主最小化。

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                   KernelSU 模块管理端 (内置 WebUI: HTML/TS)                  │
│   目标应用选择 │ 脚本导入与权限审批(Diff确认) │ MCP密钥/mTLS管理 │ 运行日志    │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ 抽象域套接字控制流
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                核心微内核宿主守护进程 ksu-mod-hostd (Rust, uid=0)             │
│                                                                            │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌───────────────────┐  │
│  │  分层内存与扫描引擎   │  │  无痕断点与 eBPF 引擎  │  │  受控安全网络网关   │  │
│  │ - process_vm_rw     │  │ - perf HW_BREAKPOINT │  │ - axum + rmcp     │  │
│  │ - NEON SIMD 分块扫描 │  │ - aya eBPF (CO-RE)   │  │ - rustls (mTLS)   │  │
│  │ - VMA 权限边界守卫   │  │ - Il2Cpp/ELF 符号解析│  │ - UID 端口隐身防火墙│  │
│  └─────────────────────┘  └──────────────────────┘  └───────────────────┘  │
│             ▲                        ▲                        ▲            │
│             └────────────────────────┼────────────────────────┘            │
│                         Capability 令牌路由与边界审计                        │
└──────────────────┬───────────────────────────────────────┬─────────────────┘
                   │ socketpair + memfd                    │ socketpair + memfd
                   ▼                                       ▼
┌──────────────────────────────────────┐ ┌───────────────────────────────────┐
│   无痕托管绘制进程 ksu-overlayd (C++)  │ │  不可信脚本沙箱池 runner-* (隔离态)  │
│  - SurfaceComposerClient (A11-A16)   │ │  - uid=nobody + CLONE_NEWNET/NS   │
│  - skipScreenshot 原生无痕防截屏/录屏 │ │  - seccomp 系统调用严格白名单       │
│  - EGL / OpenGL ES 3.0 共享上下文    │ │  - runner-lua54 (含 gg.* 兼容层)   │
│  - 底层: ThorVG (SVG级几何/骨骼/矩阵) │ │  - runner-qjs   (Frida风格/MCP服务)│
│  - 顶层: Dear ImGui (菜单/虚拟小键盘) │ │  - 内存配额限制 + 死循环指令中断     │
│  - epoll 事件驱动动态帧率 (0~120 FPS) │ │                                   │
└──────────────────────────────────────┘ └───────────────────────────────────┘
```

---

## 3. Android 16 (GKI 6.12) 核心技术路线与硬边界对策

| 底层约束点 | Android 16 / Linux 6.12 现状 | 本项目工程对策 |
| :--- | :--- | :--- |
| **`/proc/pid/mem` 写入封锁** | GKI 合入 `CONFIG_PROC_MEM_FORCE_PTRACE`，无活跃 `ptrace` 会话时内核拒绝写 `/proc/pid/mem` | 主力读写走无需 `ptrace` 的 `process_vm_readv` / `process_vm_writev`（且避免打开 `mem` fd 触发 `inotify`）；断点内走 `bpf_probe_write_user`；预留可选 KPM/LKM 插件接口处理只读代码页 Patch 与 `-w-p` 页读取。 |
| **代码段 CRC 自校验与断点可见性** | `PairIP` 等保护后台校验 `.text` 段哈希；eBPF `uprobe` 会插入 `BRK` 指令并产生 `[uprobes]` 映射 | 将 **`perf_event_open` 硬件断点/观察点（`HW_BREAKPOINT_X/W/RW`）** 作为一等公民（0 内存修改，用户态 100% 不可见）；Android 15/16 (6.6/6.12) 已修复 ARM64 `hw_breakpoint` + `bpf_overflow_handler` 单步兼容，支持直接挂载 BPF 过滤，同时保留纯 Perf 环形缓冲兼容旧内核。 |
| **eBPF 无法直接改写寄存器** | 标准 GKI 禁止 BPF 程序篡改 `pt_regs` 中的 `X0~X30`/`PC` | 断点触发时读取寄存器获取对象基址（如 `X0`），通过 `bpf_probe_write_user` 或 `process_vm_writev` 直接修改 `X0 + offset` 指向的堆结构体字段。 |
| **截屏/录屏与悬浮窗检测** | `FLAG_SECURE` 会导致黑屏自爆；Java `SYSTEM_ALERT_WINDOW` 会触发 GMS `OVERLAYS` 风险 | 使用 `SurfaceComposerClient` 创建脱离 `WindowManager` 树的独立顶层图层，开启 `skipScreenshot = true` 且不挂载 `mirrorSurface`：截屏/录屏画面完全正常且自动剔除悬浮层，GMS 亦无法感知。 |
| **本地网络端口探测** | 游戏虽无法读 `/proc/net/tcp`，但可遍历 `127.0.0.1` 发起 `connect()` 试探开放端口 | ADB 模式下仅监听抽象域套接字（**0 TCP 端口**，配合 `adb forward`）；局域网 Wi-Fi 模式下自动下发 `iptables -m owner --uid-owner 10000:99999 -j REJECT`（或 eBPF `cgroup/connect4`），使本机所有普通 App 探测该端口均秒回 `ECONNREFUSED`。 |

---

## 4. 模块选型与开源底座复用清单（拒绝重造底层轮子）

### 4.1 核心宿主与内存/eBPF 侧（Rust 静态编译：`aarch64-linux-android`）
* **异步运行时**：`tokio`
* **eBPF 加载器**：`aya`（纯 Rust 实现 BTF CO-RE 加载，零 `libbpf`/`elfutils` 动态库依赖，直接读取 `/sys/kernel/btf/vmlinux`）
* **硬件断点与调试参考**：复用/参考 `ShinoLeah/eDBG` 与 `Satar07/edbgserver` 的 `perf_event` 线程枚举、寄存器采样与混合断点调度逻辑；参考 `SeeFlowerX/stackplz` 的参数解包思路
* **扫描与二进制解析**：自研 `process_vm_readv` 2MB 分块 + `core::arch::aarch64` NEON SIMD 扫描器；`goblin` 解析 ELF 符号表；`capstone` 提供 ARM64 反汇编；内置内存态 **Unity `Il2Cpp` 元数据/类字段偏移自动解析器**
* **远程网关栈**：`axum` + 官方 MCP SDK `rmcp`（`transport-streamable-http-server` 特性）+ `rustls` + `rcgen`（自动签发自签/mTLS 证书）

### 4.2 托管绘制守护进程侧（C++23 独立二进制）
* **跨版本原生窗口**：采用 `mohamad-aljeiawi/android-native-window-symbol-patcher` (`a_native_window_creator.h`) 或 `Bzi-Han/AndroidSurfaceImgui` 的符号适配表（覆盖 Android 11–16 `libgui.so` 符号差异）
* **图形上下文**：`EGL` + `OpenGL ES 3.0`（旋转重建比 Vulkan 更轻量稳定）
* **底层 SVG 矢量图层**：**`ThorVG` v1.1+**（核心仅 ~170KB，MIT 协议，启用 `GL` OpenGL ES 3.0 后端，原生支持 SVG Tiny 1.2 `<path>`、骨骼多段折线、圆角/虚线 BBox、渐变、裁剪遮罩与 2D 变换矩阵树）
* **顶层交互控件层**：**`Dear ImGui`**（负责折叠悬浮球、修改器表单菜单、Toast 队列，并内置**轻量虚拟九宫格数字/十六进制软键盘**解决无系统输入法问题）
* **事件与功耗控制**：非独占 `epoll` 监听 `/dev/input/event*` 触摸设备（自动适配屏幕旋转矩阵）+ **按需唤醒渲染循环**（仅显示静态悬浮球/收起状态时 0 FPS 休眠，触摸交互或开启实时画布时动态升至 30/60/120 FPS）

### 4.3 沙箱脚本运行时侧（C / Rust 极小静态二进制）
* **Lua 运行时（`runner-lua54`）**：原生 **Lua 5.4**（支持原生 64 位整数 `int64_t` 与位运算，禁用预编译二进制字节码加载，内置 **`gg.*` API 兼容层** 以无缝运行未加密的传统 GG 单机脚本）
* **JS 运行时（`runner-qjs`）**：**`QuickJS-ng`**（支持原生 `BigInt` 与 `ArrayBuffer`/`DataView`，提供类 Frida `NativePointer` 链式 API，参考 `berkedel/quickmem`，同时作为内置 `mcp-server.js` 的宿主）

---

## 5. 类 Tampermonkey 权限清单与防格机安全设计

### 5.1 统一清单头规范（兼容 JS `//` 与 Lua `--`）

```javascript
// ==ModScript==
// @id           com.author.clicker-helper
// @name         单机通用属性修改器
// @version      1.0.0
// @match        com.example.game
// @grant        mem.read
// @grant        mem.write_heap
// @grant        debug.hw_watchpoint
// @grant        ui.menu
// @grant        ui.canvas
// @grant        storage.kv
// ==/ModScript==
```

### 5.2 权限矩阵与边界强控

所有权限均由 `ksu-mod-hostd` 在解析头部并经用户在 KernelSU WebUI 授权后，转化为绑定在对应 `socketpair` 会话上的不可伪造位掩码（`CapabilityFlags`），**绝不依赖脚本进程自律**：

| 权限标识 | 级别 | 宿主侧硬边界检查规则 |
| :--- | :---: | :--- |
| `@match <pkg>` | 🟢 基础 | 解析目标包名对应 UID，**强制要求 `UID >= 10000`**（硬编码拒绝 `init`、`system_server`、桌面、GMS 及管理器自身，彻底阻断“借刀杀人”写 Root 进程内存） |
| `ui.menu` / `ui.canvas` | 🟢 安全 | 隔离各脚本独立的 UI 窗口与 ThorVG 场景子树，脚本退出自动销毁全部图元 |
| `storage.kv` | 🟢 安全 | 单脚本独立 JSON KV 存储（上限 1MB），不暴露任何真实文件系统路径 |
| `mem.read` | 🟡 敏感 | 允许枚举 `@match` 进程的 VMA 映射、模块符号及读取内存 |
| `mem.write_heap` | 🟡 敏感 | **仅允许写入无执行权限（`!VM_EXEC`）且排除 `.got`/`.plt` 的可写数据/堆段（`rw-p`）**，防止通过写 Shellcode 劫持游戏进程偷发网络请求 |
| `debug.hw_watchpoint` | 🟡 敏感 | 允许在目标进程注册 ARM64 硬件执行/读写观察点（上限配额管理）并订阅寄存器上下文 |
| `debug.uprobe` | 🟡 敏感 | 允许挂载只读/受限 eBPF `uprobe`（UI 自动提示可能触发目标 `.text` 完整性检测） |
| `ui.touch_observe` | 🟡 敏感 | 允许获取菜单区域外的全局触摸事件（防密码键盘侧信道推算） |
| `net.fetch` + `@connect` | 🟠 高危 | 仅允许由宿主代发白名单域名 HTTP 请求；**若与 `mem.read` 同时出现，审批界面强制标红提示“存在盗号/外传内存数据风险”** |
| `mem.write_code` | 🔴 极危 | 允许修改代码页或分配可执行页（默认对第三方普通脚本关闭） |
| `@match *` / `host.target_switch` | 🔴 极危 | 允许枚举普通应用并动态切换目标进程（仅授予内置 `mcp-server.js` 等工作台脚本） |
| `net.serve` / `script.manage` | 🔴 极危 | 允许挂载宿主 HTTPS/MCP 路由及动态增删子脚本（仅授予内置远程服务脚本） |

### 5.3 四重防格机纵深防线
1. **OS 进程铁笼子**：脚本 Runner 启动流程固定为：预建 `socketpair` & `memfd` -> `fork()` -> `unshare(CLONE_NEWNET | CLONE_NEWNS)` 断网与清空挂载 -> 切换空根目录 -> `setresuid/gid(nobody)` 降权 -> 加载 `seccomp-bpf` 严格白名单（仅放行 `read/write/mmap/munmap/mprotect(无EXEC)/brk/futex/clock_gettime/exit_group`，直接阻断 `openat/execve/socket/ptrace/kill`）。
2. **资源配额熔断**：自定义 `lua_Alloc` 与 `JS_SetMemoryLimit` 限制单脚本堆上限（默认 64MB）；挂载 VM 指令计数中断钩子，单次同步回调超 2000ms 自动中断报错，防止死循环卡死宿主。
3. **版本升级哈希锁**：授权记录绑定 `SHA-256(脚本权限清单)`（或全文哈希），脚本更新一旦扩大权限范围立即挂起并要求用户在 WebUI 重新确认 Diff。
4. **单机安全断网模式（可选开关）**：针对单机游戏提供一键开启“运行第三方脚本时利用 eBPF 临时阻断目标游戏自身联网”，彻底杜绝任何潜在的数据外带。

---

## 6. 核心子系统接口与高性能数据流设计

### 6.1 双通道 IPC 协议（控制流 + 零拷贝数据流）
* **控制通道（`socketpair`，`SOCK_SEQPACKET`）**：采用 `16-byte 定长帧头 (magic, version, cmd, flags, req_id, payload_len) + MessagePack 载荷`，天然保留消息边界、无需粘包拆包。
* **高速数据通道（`memfd_create` + `F_ADD_SEALS` 共享内存）**：
  * **扫描结果集映射**：千万级候选地址保留在宿主侧内存池，仅将分页视图或结构体批量读取缓冲写入只读/双缓冲 `memfd` 供脚本使用。
  * **托管绘制同步**：脚本通过控制通道创建保留式 `ThorVG` / `ImGui` 节点；对于骨骼/BBox 等高频叠加绘制，提供**“原生矩阵绑定（Native Data-Binding）”接口**——脚本仅提交一次相机 `ViewMatrix` 地址与实体数组指针链偏移描述，由宿主与绘制端在每次 VSync 刷新的同一毫秒内通过 `process_vm_readv` + ARM NEON 完成 `WorldToScreen` 投影并直接送入 `ThorVG` 渲染，实现 **0 脚本轮询开销与 120Hz 零拖影**。

### 6.2 脚本化 MCP / REST 服务（`mcp-server.js`）工具集规划
内置特权脚本 `mcp-server.js` 通过宿主 `axum + rmcp` 网关对外暴露 `/mcp`（Streamable HTTP）与 `/api/v1/*`：
* **鉴权机制**：
  * 默认模式：`rustls` 自签 HTTPS + 256-bit 随机 Bearer Token（完美兼容 Claude Code、Cursor、Cherry Studio 等所有主流 MCP 客户端 Header 配置，常量时间校验 + 爆破封禁）；
  * 高敏模式：WebUI 一键切换强制 **mTLS 双向证书鉴权**，并支持一键导出客户端 `.p12`/`.pem` 证书包。
* **标准 MCP Tools 清单**：
  * 进程与映射：`list_user_apps`、`attach_target`、`get_memory_maps`、`find_module_exports`、`il2cpp_inspect_class`
  * 扫描与读写：`scan_value`、`scan_pattern_aob`、`refine_scan`、`read_memory`、`write_heap_memory`、`freeze_address`
  * 动态追踪与反汇编：`disassemble_arm64`、`set_hw_watchpoint`、`poll_watchpoint_hits`、`set_uprobe_trace`
  * 视觉验证与脚本产出：`overlay_draw_svg_debug`（AI 直接在手机屏幕上框出疑似目标验证坐标是否正确）、`deploy_sandbox_script`、`export_standalone_script`

---

## 7. 仓库与 KernelSU 模块产物目录规划

### 7.1 源码工程结构（Monorepo）
```text
ksu-mod-engine/
├── Cargo.toml                  # Rust Workspace (hostd, ipc-proto, runner-qjs, runner-lua)
├── ebpf-probes/                # aya-ebpf 内核态探针源码 (CO-RE)
├── hostd/                      # 核心微内核守护进程 (Rust: mem, perf, aya, axum+rmcp, sandbox)
├── ipc-proto/                  # 跨语言协议定义与共享内存环形缓冲结构
├── runners/
│   ├── sandbox-common/         # Linux namespaces + uid drop + seccomp 沙箱初始化器
│   ├── runner-lua54/           # Lua 5.4 运行时 + gg.* API 兼容层
│   └── runner-qjs/             # QuickJS-ng 运行时 + Frida 风格 API + MCP 路由桥接
├── overlayd/                   # C++23 独立无痕绘制进程 (CMake + NDK r27+)
│   ├── third_party/            # ANativeWindowCreator(A16), ThorVG, Dear ImGui
│   └── src/                    # EGL上下文, SceneGraph托管器, epoll输入与虚拟小键盘
├── builtin-scripts/
│   └── mcp-server.js           # 内置特权 MCP & REST 远程逆向工作站脚本
├── webui/                      # KernelSU 模块管理界面 (Vite + TypeScript)
└── module-template/            # KernelSU 模块打包模板 (module.prop, service.sh, action.sh)
```

### 7.2 手机端模块安装目录（`/data/adb/modules/ksu_mod_engine/`）
```text
/data/adb/modules/ksu_mod_engine/
├── module.prop
├── service.sh                  # 开机拉起 ksu-mod-hostd
├── action.sh                   # 管理器内一键呼出/隐藏悬浮球开关
├── bin/
│   ├── ksu-mod-hostd           # ~4.5 MB (Rust 静态编译，内嵌 eBPF 字节码)
│   ├── ksu-overlayd            # ~1.2 MB (C++ 含 ImGui + ThorVG GLES3)
│   ├── runner-lua54            # ~350 KB
│   └── runner-qjs              # ~850 KB
├── scripts/
│   ├── system/mcp-server.js    # 内置远程服务脚本
│   └── user/                   # 用户导入与导出的 .lua / .js 脚本
└── webroot/                    # KernelSU WebUI 编译产物
```
*(持久化配置、证书、脚本哈希授权表与沙箱 KV 数据统一存放于 `/data/adb/ksu_mod_engine_data/`，权限 `0700`)*

---

## 8. 分阶段落地里程碑（Roadmap）

### Milestone 1：微内核骨架 + 防格机沙箱 + 免附加搜改闭环（MVP）
* 完成 `ipc-proto` 协议与 `sandbox-common`（`CLONE_NEWNET` + `nobody` + `seccomp`）隔离验证（编写恶意逃逸测试用例验证拦截）。
* 实现 `ksu-mod-hostd` 的 `==ModScript==` 解析器、目标 `UID >= 10000` 强校验、VMA 权限守卫及 `process_vm_readv/writev` + NEON 扫描器。
* 打通 `runner-qjs` 与 `runner-lua54`（含基础 `gg.searchNumber` / `gg.editAll` 兼容），配合基础 KernelSU WebUI 实现脚本导入、授权审批与运行。

### Milestone 2：Android 16 无痕托管绘制（ImGui 菜单 + ThorVG 矢量层）
* 完成 `ksu-overlayd` 在 Android 16 实机上的 `SurfaceComposerClient` 图层创建，实测验证系统截屏、录屏及 `scrcpy` 下的 `skipScreenshot` 无痕隐身效果。
* 接入 `Dear ImGui` 保留模式菜单控件树、内置虚拟数字/Hex 小键盘，以及 `epoll` 0 FPS 空闲休眠机制。
* 接入 `ThorVG` OpenGL ES 3.0 画布，实现 SVG `<path>` / BBox / 骨骼折线托管接口与 VSync 原生矩阵数据绑定。

### Milestone 3：硬件断点 + eBPF 动态追踪 + Unity Il2Cpp 套件
* 在 `hostd` 集成 `perf_event_open` ARM64 硬件执行断点与读写观察点（`HW_BREAKPOINT`），并适配 `aya` eBPF `uprobe` / `bpf_probe_write_user`。
* 内置内存态 `Il2Cpp` 符号与类字段偏移实时解析模块，暴露给 JS/Lua 脚本直接按类名/字段名读写。

### Milestone 4：受控网络网关 + `mcp-server.js` 远程 AI 逆向闭环
* 在 `hostd` 实现 `axum` + `rmcp` Streamable HTTP 网关、`rustls`（Bearer Token + 可选 mTLS）及本机 App UID 端口隐身规则（`adb forward localabstract` 与局域网 `iptables/eBPF` 双模式）。
* 编写内置 `mcp-server.js`，打通桌面端 AI Agent（Claude Code / Cursor）远程连接手机 -> 动态扫描与硬件断点分析 -> 屏幕 SVG 标注验证 -> 自动生成并部署受限用户脚本的完整工作流。
