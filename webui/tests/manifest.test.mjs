import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, shellQuote, commands } from '../src/manifest.ts';
import { lua, js } from '../src/samples.ts';

test('both samples declare supported fixture capabilities', () => {
  for (const source of [lua, js, lua.replaceAll('\n', '\r\n')]) {
    const result = analyze(source);
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.authorizationErrors, []);
    assert.equal(result.manifest.name, 'Fixture 内存读写演示');
  }
});
test('unknown fields and permissions fail preview validation', () => {
  assert.ok(analyze(lua.replace('@grant   mem.read', '@grant   invented.grant')).errors.length);
  assert.ok(analyze(lua.replace('@version', '@invented')).errors.length);
  assert.ok(analyze(lua.replace('==/ModScript==', 'missing')).errors.length);
  assert.ok(analyze(lua + 'x'.repeat(48 * 1024)).errors.some(e => e.includes('48 KiB')));
});
test('known unsupported grants, target mismatch and write dependency block authorization', () => {
  for (const source of [lua.replace('mem.read', 'net.fetch'), lua.replace('mem.read', 'ui.canvas'),
    lua.replace('com.example.ksumod.fixture', 'com.other.app'), lua.replace('-- @grant   mem.read\n', ''),
    lua.replace('-- ==/ModScript==', '-- @connect example.com\n-- ==/ModScript==')]) {
    assert.ok(analyze(source).authorizationErrors.length);
  }
});
test('metadata remains literal text for safe DOM rendering', () => {
  assert.equal(analyze(lua.replace('Fixture 内存读写演示', '<img src=x onerror=alert(1)>')).manifest.name,
    '<img src=x onerror=alert(1)>');
});
test('shell arguments retain literal special characters', () => {
  assert.equal(shellQuote("demo's $(id); `cmd`.lua"), "'demo'\"'\"'s $(id); `cmd`.lua'");
  const hash = 'a'.repeat(64);
  const strict = commands("a'b.lua", hash, false);
  assert.equal(strict.run, "./target/debug/ksu-mod-hostd run 'a'\"'\"'b.lua' --fixture --approve " + hash);
  assert.ok(commands('-danger.lua', hash, false).inspect.includes("'./-danger.lua'"));
  assert.ok(commands('demo.lua', hash, true).run.endsWith('--development-sandbox'));
  assert.equal(commands('demo.lua', '', false).run, '');
  assert.equal(commands('demo.lua', 'x'.repeat(64), false).run, '');
  assert.equal(commands('bad\npath', hash, false).run, '');
  assert.equal(commands(' ', hash, false).inspect, '');
});
