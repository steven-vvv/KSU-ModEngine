(() => {
    'use strict';
    const host = globalThis._host;
    delete globalThis._host;
    // QuickJS has no std/os modules or module loader installed. Only text eval
    // from the runner is used; no bytecode deserialization API is exposed.
    Math.random();
    const integer = (v, lo, hi, name) => {
        if (typeof v !== 'number' || !Number.isInteger(v) || v < lo || v > hi)
            throw new TypeError(name);
        return String(v);
    };
    const i32 = v => integer(v, -2147483648, 2147483647, 'expected signed i32');
    const address = v => {
        if (typeof v === 'bigint') v = '0x' + v.toString(16);
        if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{1,16}$/.test(v))
            throw new TypeError('address must be a hexadecimal string or BigInt');
        return v;
    };
    const log = text => {
        if (typeof text !== 'string') throw new TypeError('log expects a string');
        host('log', text, '');
    };
    globalThis.engine = Object.freeze({
        scanI32: v => Number(host('scan', i32(v), '')),
        refineI32: v => Number(host('refine', i32(v), '')),
        results: (limit = 1024) => {
            const raw = host('results', integer(limit, 0, 1024, 'limit must be 0..1024'), '');
            return raw === '' ? [] : raw.split(',');
        },
        readI32: a => Number(host('read', address(a), '')),
        writeI32: (a, v) => { host('write', address(a), i32(v)); },
        editAll: v => Number(host('edit', i32(v), '')),
        log,
    });
    globalThis.console = Object.freeze({log: (...values) => {
        const parts = values.map(v => {
            const s = String(v);
            if (s.length > 4096) throw new RangeError('log argument too long');
            return s;
        });
        log(parts.join(' '));
    }});
    globalThis.eval = undefined;
    // Prevent alternate access via (() => {}).constructor.
    Object.defineProperty(Function.prototype, 'constructor', {value: undefined, writable: false, configurable: false});
    globalThis.Function = undefined;
})();
