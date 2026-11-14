import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function triggerHarness(available = true) {
    const timers = new Map();
    const callbacks = [];
    let nextTimer = 0;
    const controller = { data: null, anisetteDataWithError_() { return this.data; } };
    const context = vm.createContext({
        rpc: {}, Date, Set, Promise,
        Process: {pointerSize:8}, Memory: {alloc: () => ({writePointer() {}})}, ptr: n => n,
        setTimeout(fn) { timers.set(++nextTimer, fn); return nextTimer; },
        clearTimeout(id) { timers.delete(id); },
        Module: { getGlobalExportByName: name => name },
        NativeFunction: function (name) {
            return name === 'dispatch_async' ? (_, block) => callbacks.push(block) : () => 1;
        },
        ObjC: {
            classes: available ? { AKAnisetteProvisioningController: {
                '- anisetteDataWithError:': true,
                alloc: () => ({ init: () => controller }),
            } } : {},
            Block: function (args) { Object.assign(this, args); this.handle = this; },
            Object: function (value) { return value; },
        },
        Interceptor: { attach() {} },
    });
    const source = readFileSync(new URL('adi_anisette_call.js', import.meta.url), 'utf8');
    vm.runInContext(source.replace("import ObjC from 'frida-objc-bridge';", ''), context);
    return { context, timers, callbacks, controller, request: context.rpc.exports.requestGsa };
}

test('GSA requests are single-flight and late native callbacks remain alive after timeout', async () => {
    const h = triggerHarness();
    const first = h.request();
    assert.equal(h.request(), first);
    assert.equal(h.callbacks.length, 1);
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 1);
    for (const timer of [...h.timers.values()]) timer();
    assert.match((await first).error, /exceeded 15s/);
    assert.equal(h.request(), first);
    assert.equal(h.callbacks.length, 1);
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 1);
    h.callbacks[0].implementation();
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 0);
});

test('GSA completion cancels its timer and returns headers without logging them', async () => {
    const h = triggerHarness();
    const result = h.request();
    h.controller.data = {
        handle: { isNull: () => false }, oneTimePassword: () => 'otp',
        machineID: () => 'mid', routingInfo: () => 'routing',
    };
    h.callbacks[0].implementation();
    assert.equal((await result).otpB64, 'otp');
    assert.equal(h.timers.size, 0);
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 0);
});

test('missing AuthKit fails immediately without native requests', async () => {
    const h = triggerHarness(false);
    assert.equal((await h.request()).unavailable, true);
    assert.equal(h.callbacks.length, 0);
    assert.equal(h.timers.size, 0);
});

test('AMD uses the native Store type once without account credentials', async () => {
    const h = triggerHarness();
    const calls = [];
    h.context.ObjC.classes.NSURL = {URLWithString_: url => url};
    h.context.ObjC.classes.NSURLRequest = {requestWithURL_: url => ({url})};
    h.context.ObjC.classes.AMSAnisette = {
        '+ _headersForRequest:account:type:': (request, account, type) => {
            calls.push({request, account, type});
            return {objectForKey_: key => ({'X-Apple-AMD':'amd', 'X-Apple-AMD-M':'mid'})[key]};
        },
    };
    const request = h.context.rpc.exports.requestAmd;
    const first = request();
    assert.equal(request(), first);
    assert.equal(h.callbacks.length, 1);
    h.callbacks[0].implementation();
    assert.equal((await first).amdB64, 'amd');
    assert.equal((await first).amdMidB64, 'mid');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].type, 2);
    assert.equal(calls[0].account, 0);
    assert.equal(calls[0].request.url, 'https://auth.itunes.apple.com/auth/v1/native');
    assert.equal(h.timers.size, 0);
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 0);
});

test('AMD timeout retains native block and never starts a second request', async () => {
    const h = triggerHarness();
    h.context.ObjC.classes.AMSAnisette = {'+ _headersForRequest:account:type:': () => null};
    const request = h.context.rpc.exports.requestAmd;
    const first = request();
    for (const timer of [...h.timers.values()]) timer();
    assert.match((await first).error, /exceeded 15s/);
    assert.equal(request(), first);
    assert.equal(h.callbacks.length, 1);
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 1);
    h.callbacks[0].implementation();
    assert.equal(vm.runInContext('activeBlocks.size', h.context), 0);
});

test('static metadata reads local getters and never returns captured auth tokens', () => {
    const h = triggerHarness();
    const values = {
        'X-Mme-Device-Id':'device', 'X-MMe-Client-Info':'client',
        'X-Apple-I-SRL-NO':'serial', 'X-Apple-I-Locale':'en_US', 'X-Apple-I-TimeZone':'UTC',
        'Cookie':'secret', 'X-Apple-I-MD':'otp', 'X-Apple-AMD':'amd',
    };
    h.context.ObjC.classes.AKAppleIDSession = {
        '- _genericAppleIDHeadersDictionaryForRequest:': true,
        alloc: () => ({initWithIdentifier_: () => ({
            '- _genericAppleIDHeadersDictionaryForRequest:': () => ({objectForKey_: key => values[key] ?? null}),
        })}),
    };
    h.context.ObjC.classes.NSURL = {URLWithString_: value => value};
    h.context.ObjC.classes.NSURLRequest = {requestWithURL_: url => ({url})};
    const headers = h.context.rpc.exports.staticHeaders();
    assert.equal(headers['X-Apple-Locale'],'en_US');
    assert.equal(headers['X-Mme-Device-Id'],'device');
    assert.equal(Object.keys(headers).length,5);
    assert.equal(h.callbacks.length,0,'must not launch an anisette request');
});

test('binary frozen transfer crosses 64KiB boundaries and rejects missing/short storage', () => {
    const source = readFileSync(new URL('adi_dump.js', import.meta.url), 'utf8');
    const bytes = Uint8Array.from({ length: 300000 }, (_, i) => i % 251);
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 65536) chunks.push(bytes.slice(i, i + 65536).buffer);
    const context = vm.createContext({ rpc: {}, locked: true, captured: {
        frozen: { contiguous: bytes.buffer, chunked: chunks },
    } });
    vm.runInContext(source.slice(source.indexOf('rpc.exports =')), context);
    const read = context.rpc.exports.readFrozenBytes;
    for (const base of ['contiguous', 'chunked']) {
        assert.deepEqual(Buffer.from(read(base, 32761, 262144)), Buffer.from(bytes.slice(32761, 294905)));
        assert.equal(read(base, 299999, 2), null);
        assert.equal(read(base, 0, 262145), null);
        assert.equal(read(base, -1, 2), null);
    }
    assert.equal(read('missing', 0, 1), null);
});

test('capture is armed only after ranges are prepared; unrelated requests never freeze memory', () => {
    const hooks = new Map();
    let request = Uint8Array.from([0,0,0,1, 12,34,56,78, 0,0,0,1, 255,255,255,255,255,255,255,254]);
    class Pointer {
        constructor(n) { this.n = Number(n); }
        add(n) { return new Pointer(this.n + n); }
        sub(n) { return new Pointer(this.n - n); }
        compare(p) { return this.n - p.n; }
        toString() { return '0x' + this.n.toString(16); }
        isNull() { return this.n === 0; }
        readByteArray(size) { return size === 20 ? request.slice().buffer : new ArrayBuffer(size); }
    }
    const context = vm.createContext({
        Process: { enumerateModules: () => [{name:'adid',base:new Pointer(0x1000),size:0x2000}] },
        Module: { findGlobalExportByName: name => name },
        NativeFunction: function () { return () => 0; },
        NativeCallback: function (fn) { return fn; },
        Interceptor: {attach: (address, callbacks) => hooks.set(address.toString(), callbacks)},
        ptr: n => new Pointer(n), rpc: {}, send() {},
        // Any symbolication in the dump process makes this regression test fail.
        DebugSymbol: new Proxy({}, {get() {throw new Error('unsafe symbolication');}}),
    });
    vm.runInContext(readFileSync(new URL('adi_dump.js', import.meta.url), 'utf8'), context);
    assert.deepEqual([...hooks.keys()].filter(k => !k.startsWith('0x')),
                     ['xpc_dictionary_set_data']);
    const handler = hooks.get('0x1181e8');
    const frame = {threadId:17, context:{}};
    for (const name of [...Array.from({length:29}, (_,i) => 'x'+i), 'fp','lr','sp','pc']) {
        frame.context[name] = new Pointer(0x3000);
    }
    handler.onEnter.call(frame);
    assert.equal(vm.runInContext('captured', context), null);
    const api = context.rpc.exports;
    api.prepare(JSON.stringify([{base:'0x2000',size:64}]));
    request[3] = 2;
    handler.onEnter.call(frame);
    assert.equal(api.status().skippedRequests, 1);
    assert.equal(api.status().frozenRangeCount, 0);
    request[3] = 1;
    handler.onEnter.call(frame);
    assert.equal(api.status().frozenRangeCount, 1);
    assert.equal(vm.runInContext('captured.threadId', context), 17);
    const firstID = vm.runInContext('captured.captureId', context);
    // A sync/provisioning call can be followed by the actual OTP invocation
    // before the mid-handler onLeave fires. It must replace the first context.
    const nextFrame = {threadId:17, context:frame.context};
    handler.onEnter.call(nextFrame);
    assert.equal(vm.runInContext('captured.captureId', context), firstID + 1);
    assert.equal(handler.onLeave, undefined, 'mid-handler hook must not rewrite the return address');
    assert.equal(vm.runInContext('tracing', context), true);
});
