-- ==ModScript==
-- @id com.example.ksumod.demo-lua
-- @name Fixture DWORD 演示（Lua）
-- @version 0.1.0
-- @match com.example.ksumod.fixture
-- @grant mem.read
-- @grant mem.write_heap
-- ==/ModScript==

assert(gg.searchNumber('1337', gg.TYPE_DWORD) == 2)
local values = gg.getResults(2)
assert(#values == 2 and values[1].value == 1337)
assert(gg.editAll('7331', gg.TYPE_DWORD) == 2)
assert(engine.readI32(values[1].address) == 7331)
print('Lua fixture: 1337 -> 7331')
