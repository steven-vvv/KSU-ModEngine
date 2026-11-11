local host = _host
local tonumber, tostring, type, select, ipairs, error = tonumber, tostring, type, select, ipairs, error
local math_type, maxinteger, concat = math.type, math.maxinteger, table.concat
_host = nil
-- No source loading, bytecode generation, filesystem, subprocess or module APIs.
io, os, package, debug, require, dofile, loadfile, load, collectgarbage = nil, nil, nil, nil, nil, nil, nil, nil, nil
string.dump = nil
math.random() -- initialize the VM's random state before sandbox installation
local function integer(value, lo, hi, label)
    if math_type(value) ~= 'integer' or value < lo or value > hi then
        error(label or 'integer out of range', 3)
    end
    return tostring(value)
end
local function i32(value)
    return integer(value, -2147483648, 2147483647, 'expected signed i32 integer')
end
local function address(value)
    return integer(value, 1, maxinteger - 4, 'expected positive 64-bit integer address')
end
local function log(text)
    if type(text) ~= 'string' then error('log expects a string', 2) end
    host('log', text, '')
end
engine = {
    scanI32 = function(value) return tonumber(host('scan', i32(value), '')) end,
    refineI32 = function(value) return tonumber(host('refine', i32(value), '')) end,
    results = function(limit)
        if limit == nil then limit = 1024 end
        local raw = host('results', integer(limit, 0, 1024, 'limit must be 0..1024'), '')
        local result = {}
        for item in raw:gmatch('[^,]+') do
            local n = tonumber(item)
            if math_type(n) ~= 'integer' or n <= 0 then error('host returned unrepresentable address') end
            result[#result + 1] = n
        end
        return result
    end,
    readI32 = function(a) return tonumber(host('read', address(a), '')) end,
    writeI32 = function(a, value) host('write', address(a), i32(value)) end,
    editAll = function(value) return tonumber(host('edit', i32(value), '')) end,
    log = log,
}
print = function(...)
    local values = {}
    for n = 1, select('#', ...) do
        local s = tostring(select(n, ...))
        if #s > 4096 then error('print argument too long') end
        values[n] = s
    end
    log(concat(values, '\t'))
end
local function flags(f)
    if f ~= 4 then error('only gg.TYPE_DWORD is supported', 3) end
end
local function ggvalue(v)
    if type(v) == 'string' then
        if #v > 16 or not v:match('^%-?%d+$') then error('expected decimal DWORD value', 3) end
        v = tonumber(v)
    end
    i32(v)
    return v
end
gg = {
    TYPE_DWORD = 4,
    searchNumber = function(value, f, ...)
        flags(f)
        if select('#', ...) ~= 0 then error('extended GG search arguments unsupported') end
        return engine.scanI32(ggvalue(value))
    end,
    getResults = function(limit)
        local result = {}
        for _, a in ipairs(engine.results(limit)) do
            result[#result + 1] = {address = a, flags = 4, value = engine.readI32(a)}
        end
        return result
    end,
    editAll = function(value, f) flags(f); return engine.editAll(ggvalue(value)) end,
    setValues = function(values)
        if type(values) ~= 'table' or #values > 1024 then error('expected at most 1024 values') end
        -- Validate all entries before the first write; writes themselves are not transactional.
        for _, v in ipairs(values) do
            if type(v) ~= 'table' then error('expected value table') end
            flags(v.flags); address(v.address); ggvalue(v.value)
        end
        for _, v in ipairs(values) do engine.writeI32(v.address, ggvalue(v.value)) end
        return true
    end,
}
