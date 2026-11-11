export const lua = `-- ==ModScript==
-- @id      com.example.fixture-demo
-- @name    Fixture 内存读写演示
-- @version 0.1.0
-- @match   com.example.ksumod.fixture
-- @grant   mem.read
-- @grant   mem.write_heap
-- ==/ModScript==

-- 仅操作宿主创建的 fixture 内存页
local count = engine.scanI32(1337)
engine.log("找到候选：" .. tostring(count))
local addresses = engine.results(16)
assert(#addresses > 0, "未找到 1337")
engine.writeI32(addresses[1], 7331)
assert(engine.readI32(addresses[1]) == 7331)
engine.log("已验证：1337 → 7331")
`;
export const js = `// ==ModScript==
// @id      com.example.fixture-demo
// @name    Fixture 内存读写演示
// @version 0.1.0
// @match   com.example.ksumod.fixture
// @grant   mem.read
// @grant   mem.write_heap
// ==/ModScript==

// 地址由 engine.results 返回十六进制字符串
const count = engine.scanI32(1337);
engine.log("找到候选：" + count);
const addresses = engine.results(16);
if (!addresses.length) throw new Error("未找到 1337");
engine.writeI32(addresses[0], 7331);
if (engine.readI32(addresses[0]) !== 7331) {
  throw new Error("写入验证失败");
}
console.log("已验证：1337 → 7331");
`;
