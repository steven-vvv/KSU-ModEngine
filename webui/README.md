# KSU ModEngine WebUI 开发预览

浏览器内的中文脚本工作台。支持 Lua / JavaScript 源码导入或编辑、清单与权限预览、全文 SHA-256 摘要、CLI 检查与显式授权命令。没有后端请求、脚本执行接口或 Android 安装能力；不需要桌面会话。

使用 Node.js 22.12+（建议 Node.js 26）及项目指定的 pnpm 12.9.1：

```sh
cd webui
pnpm install --ignore-scripts
pnpm run dev
```

通过 `http://localhost:5173` 打开。Web Crypto 摘要与剪贴板需要 localhost 或 HTTPS 安全上下文；远程开发使用 SSH 端口转发。`pnpm run build` 执行 TypeScript 检查并生成 `dist/`，`pnpm run preview` 预览构建。`pnpm test` 使用 Node.js 内置测试运行器验证预览解析、权限限制与 shell 引号；测试导入 TypeScript，需要 Node.js 22.18+ 的原生类型擦除支持。

## 从审阅到运行

1. 加载示例、选择本地 `.lua` / `.js` 文件，或粘贴含 `ModScript` 清单的源码。文件不上传，页面不请求外部字体或服务。
2. 核对名称、目标、权限及摘要。只有 `mem.read` / `mem.write_heap` 可用于当前 fixture 预览，写权限同时需要读权限。浏览器检查仅供参考，宿主 `engine-core` 解析与授权为准。
3. 将当前完整源码保存到「本地脚本路径」。浏览器无法知道导入文件的真实绝对路径，默认路径只是建议。可用「保存当前源码」下载；如修改过源码，务必更新终端使用的文件。
4. 在仓库根目录构建宿主和 Runner，复制「检查清单」命令到终端核对，再审阅并复制授权命令。文件摘要改变后，旧授权会失败。
5. 默认生成 strict 沙箱命令，隔离不可用时失败。仅对可信的自有 fixture 脚本显式选择 Development 沙箱，不会自动降级。

摘要基于 UTF-8 全文（导入时保留 CRLF 和 BOM；编辑器发生编辑后以当前编辑内容为准）。摘要计算及文件读取都防止过期异步结果覆盖新输入。导入仅接受有效 UTF-8 文本且上限 48 KiB；保存后的字节应与审阅版本完全一致。

全部导入内容、元数据与错误使用 `textContent` 或原生输入框渲染；命令路径使用 POSIX 单引号转义，拒绝控制字符，防止文件名被解释为 shell 命令或 CLI 选项。不持久化源码。
