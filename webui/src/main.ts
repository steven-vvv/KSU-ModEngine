import './style.css';
import { analyze, commands, supportedGrants } from './manifest';
import type { Analysis } from './manifest';
import { lua, js } from './samples';

function el<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing interface element: ${id}`);
  return node as T;
}
const editor = el<HTMLTextAreaElement>('source-editor');
const path = el<HTMLInputElement>('script-path');
const development = el<HTMLInputElement>('development-toggle');
const fileInput = el<HTMLInputElement>('file-import');
let source = lua;
let hash = '';
let revision = 0;
let fileRevision = 0;
let analysis: Analysis;
let currentCommands = { inspect: '', run: '' };
let feedbackTimer = 0;

function feedback(message: string) {
  const target = el('feedback');
  target.textContent = message;
  target.hidden = false;
  window.clearTimeout(feedbackTimer);
  feedbackTimer = window.setTimeout(() => { target.hidden = true; }, 5000);
}

function renderCommands() {
  currentCommands = commands(path.value, hash, development.checked);
  if (analysis.errors.length || analysis.authorizationErrors.length) currentCommands.run = '';
  el('inspect-command').textContent = currentCommands.inspect || '请输入有效的本地脚本路径（不可包含控制字符）。';
  el('run-command').textContent = currentCommands.run || (analysis.errors.length || analysis.authorizationErrors.length
    ? '请先解决清单或授权问题，再生成 fixture 运行命令。' : '等待源码摘要与有效路径…');
  el<HTMLButtonElement>('copy-inspect').disabled = !currentCommands.inspect;
  el<HTMLButtonElement>('copy-run').disabled = !currentCommands.run;
  el('sandbox-description').textContent = development.checked
    ? '已显式选择 development：保留当前 UID，仅限可信的自有 fixture 脚本。'
    : '默认 strict：隔离不可用时直接失败，不会自动降级。';
}

function renderAnalysis() {
  const { manifest, errors, authorizationErrors } = analysis;
  const status = el('manifest-status');
  status.className = `analysis-status ${errors.length || authorizationErrors.length ? 'issue' : 'valid'}`;
  status.textContent = errors.length ? '需修正清单' : authorizationErrors.length ? '存在不支持的授权' : '✓ 清单预览通过';
  const fields = el('manifest-fields');
  fields.replaceChildren();
  for (const [label, value] of [
    ['名称', manifest.name], ['标识', manifest.id], ['版本', manifest.version],
    ['目标', manifest.matches.join('\n')], ['连接', manifest.connect.join('\n') || '未声明'],
  ]) {
    const term = document.createElement('dt');
    term.textContent = label;
    const definition = document.createElement('dd');
    definition.textContent = value || '—';
    fields.append(term, definition);
  }
  el('grant-count').textContent = String(manifest.grants.length).padStart(2, '0');
  const capabilities = el('capabilities');
  capabilities.replaceChildren();
  if (!manifest.grants.length) capabilities.textContent = '未声明权限';
  for (const grant of manifest.grants) {
    const card = document.createElement('div');
    card.className = `capability ${supportedGrants.has(grant) ? '' : 'unsupported'}`;
    const name = document.createElement('code');
    name.textContent = grant;
    const description = document.createElement('span');
    description.textContent = grant === 'mem.read' ? '读取与扫描 fixture 内存'
      : grant === 'mem.write_heap' ? '写入非执行、私有可写测试页' : 'v0.1 无法批准此权限';
    card.append(name, description);
    capabilities.append(card);
  }
  const issues = el('validation-errors');
  issues.replaceChildren();
  if (errors.length || authorizationErrors.length) {
    const list = document.createElement('ul');
    list.className = 'issues';
    for (const error of [...errors, ...authorizationErrors]) {
      const item = document.createElement('li');
      item.textContent = error;
      list.append(item);
    }
    issues.append(list);
  }
}

async function update(value: string) {
  source = value;
  const current = ++revision;
  hash = '';
  analysis = analyze(source);
  renderAnalysis();
  renderCommands();
  const bytes = new TextEncoder().encode(source);
  el('source-size').textContent = `${bytes.length.toLocaleString('zh-CN')} B / 48 KiB`;
  el('source-hash').textContent = '正在计算全文摘要…';
  el('hash-state').textContent = 'CALCULATING';
  try {
    if (!globalThis.crypto?.subtle) throw new Error('当前环境不支持安全摘要；请通过 localhost 或 HTTPS 打开页面。');
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    if (current !== revision) return;
    hash = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    el('source-hash').textContent = hash;
    el('hash-state').textContent = 'SHA-256 · READY';
  } catch (error) {
    if (current !== revision) return;
    el('source-hash').textContent = error instanceof Error ? error.message : '摘要计算失败。';
    el('hash-state').textContent = 'UNAVAILABLE';
  }
  renderCommands();
}

function loadSample(language: 'lua' | 'js') {
  ++fileRevision;
  editor.value = language === 'lua' ? lua : js;
  path.value = `examples/demo.${language}`;
  el('sample-lua').classList.toggle('active', language === 'lua');
  el('sample-js').classList.toggle('active', language === 'js');
  void update(editor.value);
}
editor.addEventListener('input', () => {
  ++fileRevision;
  el('sample-lua').classList.remove('active');
  el('sample-js').classList.remove('active');
  void update(editor.value);
});
el('sample-lua').addEventListener('click', () => loadSample('lua'));
el('sample-js').addEventListener('click', () => loadSample('js'));
path.addEventListener('input', renderCommands);
development.addEventListener('change', renderCommands);

fileInput.addEventListener('change', async () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  const current = ++fileRevision;
  try {
    if (file.size > 48 * 1024) throw new Error('文件超过 48 KiB 上限。');
    if (!/\.(lua|js)$/i.test(file.name)) throw new Error('请选择 .lua 或 .js 文本脚本。');
    const bytes = await file.arrayBuffer();
    if (current !== fileRevision) return;
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.includes('\0')) throw new Error('脚本包含 NUL 字节；只支持文本源码。');
    editor.value = text;
    path.value = `examples/${file.name}`;
    el('sample-lua').classList.remove('active');
    el('sample-js').classList.remove('active');
    // Hash original decoded bytes, preserving imported CRLF until the first edit.
    void update(text);
    feedback(`已在本地读取 ${file.name}；请核对实际保存路径。`);
  } catch (error) {
    if (current === fileRevision) feedback(error instanceof Error ? error.message : '读取文件失败。');
  } finally {
    if (current === fileRevision) fileInput.value = '';
  }
});

el('download-source').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([source], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = path.value.split('/').pop() || 'demo.lua';
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  feedback('已请求保存源码；请确认文件内容与 CLI 路径一致。');
});
for (const type of ['inspect', 'run'] as const) {
  el(`copy-${type}`).addEventListener('click', async () => {
    const command = currentCommands[type];
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command);
      feedback('命令已复制。请在本地终端审阅后执行。');
    } catch {
      feedback('无法访问剪贴板。请手动选择并复制命令文本。');
    }
  });
}
loadSample('lua');
