// ==ModScript==
// @id com.example.ksumod.demo-js
// @name Fixture DWORD 演示（JavaScript）
// @version 0.1.0
// @match com.example.ksumod.fixture
// @grant mem.read
// @grant mem.write_heap
// ==/ModScript==

function check(value) {
    if (!value) throw new Error('fixture assertion failed');
}
check(engine.scanI32(1337) === 2);
const addresses = engine.results(2);
check(addresses.length === 2 && engine.readI32(addresses[0]) === 1337);
check(engine.refineI32(1337) === 2);
check(engine.editAll(7331) === 2);
check(engine.readI32(addresses[0]) === 7331);
console.log('JavaScript fixture: 1337 -> 7331');
