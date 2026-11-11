export const knownGrants = new Set([
  'mem.read', 'mem.write_heap', 'debug.hw_watchpoint', 'debug.uprobe', 'ui.menu',
  'ui.canvas', 'storage.kv', 'ui.touch_observe', 'net.fetch', 'mem.write_code',
  'host.target_switch', 'net.serve', 'script.manage',
]);
export const supportedGrants = new Set(['mem.read', 'mem.write_heap']);
export interface Manifest {
  id: string;
  name: string;
  version: string;
  matches: string[];
  grants: string[];
  connect: string[];
}
export interface Analysis {
  manifest: Manifest;
  errors: string[];
  authorizationErrors: string[];
}

/** Advisory browser preview. engine-core remains the authoritative parser. */
export function analyze(source: string): Analysis {
  const manifest: Manifest = { id: '', name: '', version: '', matches: [], grants: [], connect: [] };
  const errors: string[] = [];
  const authorizationErrors: string[] = [];
  const seen = new Set<string>();
  let inHeader = false;
  let opened = false;
  let closed = false;
  for (const raw of source.split(/\r?\n/)) {
    const comment = raw.trim().match(/^(?:\/\/|--)\s?(.*)$/);
    const line = comment?.[1]?.trim() ?? '';
    if (line === '==ModScript==') {
      if (opened) errors.push('清单头重复。');
      opened = true;
      inHeader = true;
      continue;
    }
    if (line === '==/ModScript==') {
      if (!inHeader) errors.push('清单结束标记没有对应的开始标记。');
      inHeader = false;
      closed = true;
      continue;
    }
    if (!inHeader) continue;
    if (!comment) {
      errors.push('清单头内只允许注释字段。');
      continue;
    }
    if (!line) continue;
    const field = line.match(/^@(\S+)\s+(.+)$/);
    if (!field) { errors.push(`无法识别清单行：${line}`); continue; }
    const [, key, value] = field;
    if (['id', 'name', 'version'].includes(key)) {
      if (seen.has(key)) errors.push(`字段 @${key} 不可重复。`);
      seen.add(key);
      manifest[key as 'id' | 'name' | 'version'] = value.trim();
    } else if (key === 'match') manifest.matches.push(value.trim());
    else if (key === 'grant') manifest.grants.push(value.trim());
    else if (key === 'connect') manifest.connect.push(value.trim());
    else errors.push(`未知清单字段：@${key}`);
  }
  if (!opened || !closed || inHeader) errors.push('需要完整的 ==ModScript== / ==/ModScript== 清单头。');
  for (const key of ['id', 'name', 'version'] as const) {
    if (!manifest[key]) errors.push(`缺少必填字段 @${key}。`);
  }
  if (!manifest.matches.length) errors.push('至少需要一条 @match。');
  manifest.grants = [...new Set(manifest.grants)];
  for (const grant of manifest.grants) {
    if (!knownGrants.has(grant)) errors.push(`未知权限：${grant}`);
    else if (!supportedGrants.has(grant)) authorizationErrors.push(`v0.1 尚未实现授权：${grant}`);
  }
  if (!manifest.matches.includes('com.example.ksumod.fixture')) {
    authorizationErrors.push('fixture 预览需要 @match com.example.ksumod.fixture。');
  }
  if (manifest.matches.some(value => value.includes('*'))) {
    authorizationErrors.push('v0.1 不支持通配目标授权。');
  }
  if (manifest.grants.includes('mem.write_heap') && !manifest.grants.includes('mem.read')) {
    authorizationErrors.push('mem.write_heap 必须同时声明 mem.read。');
  }
  if (manifest.connect.length) authorizationErrors.push('v0.1 不支持网络连接授权（@connect）。');
  if (new TextEncoder().encode(source).byteLength > 48 * 1024) errors.push('源码超过 48 KiB 上限。');
  return { manifest, errors: [...new Set(errors)], authorizationErrors };
}

/** POSIX shell single-argument quoting, including embedded quotes. */
export function shellQuote(value: string): string {
  return "'" + value.replaceAll("'", "'\"'\"'") + "'";
}

export function commands(path: string, hash: string, development: boolean) {
  const validPath = path.trim().length > 0 && !/[\x00-\x1f\x7f]/.test(path);
  // A ./ prefix keeps a relative filename beginning with '-' out of option parsing.
  const safePath = path.startsWith('-') ? `./${path}` : path;
  const base = './target/debug/ksu-mod-hostd';
  return {
    inspect: validPath ? `${base} inspect-script ${shellQuote(safePath)}` : '',
    run: validPath && /^[a-f0-9]{64}$/.test(hash)
      ? `${base} run ${shellQuote(safePath)} --fixture --approve ${hash}${development ? ' --development-sandbox' : ''}` : '',
  };
}
