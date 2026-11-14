const main = Process.enumerateModules().find((m) => m.name === 'adid') || Process.enumerateModules()[0];
const importNames = [
    'gettimeofday', 'time', 'malloc', 'malloc_zone_malloc', 'malloc_type_malloc',
    'malloc_type_calloc', 'malloc_type_realloc', 'malloc_type_free', 'free', 'calloc', 'realloc',
    'memcpy', 'memset', 'memcmp', 'mmap', 'munmap', '__stack_chk_fail', '__chkstk_darwin',
    'xpc_dictionary_get_data', 'xpc_dictionary_set_data', 'xpc_dictionary_create_reply',
    'xpc_dictionary_send_reply', 'pthread_once', 'dispatch_once', 'SecTaskCopyValueForEntitlement',
    'CFGetTypeID', 'CFStringGetTypeID', 'CFNumberGetTypeID', 'CFStringGetCString',
    '__CFTSDGetTable', 'strtoul',
    'lstat', 'lstat64', 'stat', 'stat64', 'mach_absolute_time', 'IOConnectCallStructMethod',
    'IOServiceOpen', '__stack_chk_guard',
];

function resolveExport(name) {
    if (typeof Module.findGlobalExportByName === 'function') {
        const address = Module.findGlobalExportByName(name);
        if (address !== null) return address;
    }
    for (const module of Process.enumerateModules()) {
        try {
            const address = module.findExportByName(name);
            if (address !== null) return address;
        } catch (e) {}
    }
    return null;
}

function base64(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
        const a = bytes[i];
        const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
        const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
        out += alphabet[a >> 2] + alphabet[((a & 3) << 4) | (b >> 4)];
        out += i + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        out += i + 2 < bytes.length ? alphabet[c & 63] : '=';
    }
    return out;
}

let captured = null;
let armed = false;
let locked = false;
let tracing = false;
let replyTracing = false;
let importTrace = [];
let localImports = {};
let targetType = 5;
let selectedRanges = [];
let captureSequence = 0;
let transactionHeld = false;
let handlerCalls = 0;
let replyCalls = 0;
const observedReplyTypes = new Set();
const requestKinds = {};
const replyKinds = {};
let skippedRequests = 0;
const listeners = [];

function isGSARequest(bytes) {
    return bytes.length === 20 && bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 1 &&
        bytes[8] === 0 && bytes[9] === 0 && bytes[10] === 0 && bytes[11] === 1 &&
        bytes.slice(12, 19).every(value => value === 255) && bytes[19] === 254;
}

function setAdidTransaction(hold) {
    const address = resolveExport(hold ? 'xpc_transaction_begin' : 'xpc_transaction_end');
    if (address === null) return;
    new NativeFunction(address, 'void', [])();
    transactionHeld = hold;
}

function liftAdidJetsamLimit() {
    const control = resolveExport('memorystatus_control');
    const getpid = resolveExport('getpid');
    if (control === null || getpid === null) {
        send({ event: 'adid-jetsam', result: -1, errno: -1 });
        return;
    }
    const pid = new NativeFunction(getpid, 'int', [])();
    const result = new NativeFunction(control, 'int', ['uint32', 'int', 'uint32', 'pointer', 'size_t'])(
        6, pid, 0, ptr(0), 0);
    let errno = 0;
    if (result !== 0) {
        const errorAddress = resolveExport('__error');
        if (errorAddress !== null) errno = new NativeFunction(errorAddress, 'pointer', [])().readInt();
    }
    send({ event: 'adid-jetsam', result, errno });
}

let exitBlocked = false;
let blockedExitAddresses = [];
const adidSleep = new NativeFunction(resolveExport('sleep'), 'uint', ['uint']);
const adidExitHandler = new NativeCallback(function (code) {
    exitBlocked = true;
    send({ event: 'adid-exit', code });
    while (exitBlocked) adidSleep(1);
}, 'void', ['int']);

function blockAdidExit() {
    for (const name of ['exit', '_exit']) {
        const address = resolveExport(name);
        if (address === null) continue;
        try {
            Interceptor.replace(address, adidExitHandler);
            blockedExitAddresses.push(address);
        } catch (e) {}
    }
}

function unblockAdidExit() {
    exitBlocked = false;
    for (const address of blockedExitAddresses) Interceptor.revert(address);
    blockedExitAddresses = [];
}

const handlerAddress = main.base.add(0x1171e8);
let handlerBytes = null;
try { handlerBytes = base64(new Uint8Array(handlerAddress.readByteArray(16))); } catch (e) {}

// Emulator stubs need the addresses in info(), not hooks on every import.
// Only the reply needs interception; allocator hooks perturb runtime locks.
for (const name of ['xpc_dictionary_set_data']) {
    const address = resolveExport(name);
    if (address === null || name === '__stack_chk_guard') continue;
    try {
        listeners.push(Interceptor.attach(address, {
            onEnter(args) {
                if (armed && name === 'xpc_dictionary_set_data') {
                    try {
                        const length = args[3].toInt32();
                        let type = 'none';
                        if (length === 100 || length === 96) {
                            const offset = 72;
                            const header = new Uint8Array(args[2].add(offset).readByteArray(8));
                            if (header[0] === 0 && header[1] === 0 && header[2] === 0 &&
                                header[4] === 0 && header[5] === 0 && header[6] === 0 && header[7] === 16)
                                type = String(header[3]);
                        }
                        const kind = `${length}:type=${type}:tracing=${tracing}:sameThread=${!!captured && this.threadId === captured.threadId}`;
                        if (Object.keys(replyKinds).length < 64) replyKinds[kind] = (replyKinds[kind] || 0) + 1;
                    } catch (e) {}
                }
                if (targetType !== 4 && (!captured || this.threadId !== captured.threadId)) return;
                if (name === 'xpc_dictionary_set_data') {
                    if (targetType === 4 ? !replyTracing : !tracing) return;
                } else if (!tracing) return;
                importTrace.push({ name, caller: this.returnAddress.toString() });
                if (name !== 'xpc_dictionary_set_data') return;
                replyCalls++;
                let matched = false;
                try {
                    const length = args[3].toInt32();
                    const bytes = new Uint8Array(args[2].readByteArray(length));
                    for (let i = 0; i + 24 <= bytes.length; i++) {
                        if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 &&
                            bytes[i + 4] === 0 && bytes[i + 5] === 0 && bytes[i + 6] === 0 && bytes[i + 7] === 16) {
                            observedReplyTypes.add(bytes[i + 3]);
                        }
                    }
                    for (let i = 0; i + 24 <= bytes.length; i++) {
                        if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 &&
                            bytes[i + 3] === targetType && bytes[i + 4] === 0 && bytes[i + 5] === 0 &&
                            bytes[i + 6] === 0 && bytes[i + 7] === 0x10) {
                            matched = true;
                            if (captured) {
                                locked = true;
                                captured.importTrace = importTrace.slice();
                                captured.replyLen = length;
                                if (targetType === 4 || i + 28 <= bytes.length) {
                                    send({ event: 'adid-locked', captureId: captured.captureId,
                                        replyLen: length, importTrace: captured.importTrace, localImports,
                                        epoch30: captured.epoch30,
                                        ...(length >= 68 && bytes[0] === 0 && bytes[1] === 0 &&
                                            bytes[2] === 0 && bytes[3] === 0 && bytes[4] === 0 &&
                                            bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 60
                                            ? { midB64: base64(bytes.slice(8, 68)) } : {}),
                                        ...(targetType === 4
                                            ? { amdB64: base64(bytes.slice(i, i + 24)) }
                                            : { otpB64: base64(bytes.slice(i, i + 28)) }) });
                                }
                            }
                            break;
                        }
                    }
                } catch (e) {}
                if (matched) {
                    replyTracing = false;
                    if (targetType !== 4) tracing = false;
                }
            },
        }));
    } catch (e) {}
}

function freezeSelectedRanges() {
    for (const range of selectedRanges) {
        try {
            const data = ptr(range.base).readByteArray(range.size);
            if (data === null) throw new Error('readByteArray returned null');
            captured.frozen[range.base] = data;
        } catch (wholeError) {
            const chunks = [];
            let failed = null;
            for (let offset = 0; offset < range.size; offset += 0x10000) {
                const size = Math.min(0x10000, range.size - offset);
                try {
                    const data = ptr(range.base).add(offset).readByteArray(size);
                    if (data === null) throw new Error('readByteArray returned null');
                    chunks.push(data);
                } catch (chunkError) {
                    failed = `${range.base}+0x${offset.toString(16)}: ${chunkError}`;
                    break;
                }
            }
            if (failed === null) captured.frozen[range.base] = chunks;
            else {
                captured.frozen[range.base] = null;
                captured.frozenErrors[range.base] = failed;
            }
        }
    }
}

// This is an instruction inside the handler, not its ABI entry. An onLeave
// hook here rewrites LR and may keep the native request/unload from returning.
listeners.push(Interceptor.attach(handlerAddress, {
    onEnter() {
        handlerCalls++;
        if (!armed || locked) return;
        if (targetType !== 4) {
            let request;
            try { request = new Uint8Array(this.context.x0.readByteArray(20)); } catch (e) { skippedRequests++; return; }
            const kind = `${request[0]}.${request[1]}.${request[2]}.${request[3]}:${isGSARequest(request) ? 'GSA' : 'other'}`;
            requestKinds[kind] = (requestKinds[kind] || 0) + 1;
            // Provisioning/other operations are not OTP snapshots. Do not copy
            // tens of MiB on every unrelated invocation before the GSA request.
            if (!isGSARequest(request)) { skippedRequests++; return; }
        }
        const context = this.context;
        const regs = {};
        for (let i = 0; i <= 28; i++) regs['x' + i] = context['x' + i].toString();
        regs.fp = context.fp.toString();
        regs.lr = context.lr.toString();
        regs.sp = context.sp.toString();
        regs.pc = context.pc.toString();
        let stack = null;
        let used = 0;
        for (const size of [0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x1000]) {
            try {
                const data = context.sp.readByteArray(size);
                if (data) {
                    stack = Array.from(new Uint8Array(data));
                    used = size;
                    break;
                }
            } catch (e) {}
        }
        let input = null;
        try { input = base64(new Uint8Array(context.x0.readByteArray(20))); } catch (e) {}
        captured = {
            epoch30: Math.floor(Date.now() / 30000),
            threadId: this.threadId,
            regs,
            stackLo: context.sp.toString(),
            stackSize: used,
            stack,
            x0: context.x0.toString(),
            input,
            frozen: {},
            frozenErrors: {},
        };
        if (targetType !== 4) freezeSelectedRanges();
        captured.captureId = ++captureSequence;
        importTrace = [];
        if (targetType === 4) replyTracing = true;
        if (targetType !== 4) tracing = true;
    },
}));

rpc.exports = {
    status() {
        return { handlerCalls, replyCalls, locked, armed, targetType, skippedRequests, requestKinds, replyKinds,
            selectedRangeCount: selectedRanges.length,
            frozenRangeCount: captured ? Object.keys(captured.frozen).length : 0,
            observedReplyTypes: Array.from(observedReplyTypes) };
    },
    info() {
        const imports = {};
        for (const name of importNames) {
            const address = resolveExport(name);
            imports[name] = address ? address.toString() : null;
        }
        let stackGuard = null;
        const guard = imports.__stack_chk_guard;
        if (guard) {
            try { stackGuard = { address: guard, value: ptr(guard).readPointer().toString() }; } catch (e) {}
        }
        delete imports.__stack_chk_guard;
        return {
            base: main.base.toString(), size: main.size, path: main.path, imports, stackGuard,
            handlerAddress: handlerAddress.toString(), handlerBytes,
        };
    },
    ranges() {
        const out = [];
        for (const range of Process.enumerateRanges('r--')) {
            let file = null;
            try { file = range.file ? range.file.path : null; } catch (e) {}
            out.push({ base: range.base.toString(), size: range.size, prot: range.protection, file });
        }
        return out;
    },
    prepare(selectionJson) {
        selectedRanges = JSON.parse(selectionJson);
        if (targetType === 4) setAdidTransaction(true);
        if (targetType === 4) blockAdidExit();
        armed = true;
        return selectedRanges.length;
    },
    freeze() {
        if (!locked || !captured) return false;
        freezeSelectedRanges();
        return true;
    },
    localImports() { return localImports; },
    target(type) { targetType = type; },
    context() {
        if (!locked || !captured) return null;
        const result = Object.assign({}, captured);
        delete result.frozen;
        return result;
    },
    readFrozen(base, offset, size) {
        if (!locked || !captured) return null;
        const data = captured.frozen[base];
        if (!data) return null;
        try {
            if (Array.isArray(data)) {
                const chunk = data[Math.floor(offset / 0x10000)];
                return base64(new Uint8Array(chunk, offset % 0x10000, size));
            }
            return base64(new Uint8Array(data, offset, size));
        } catch (e) { return null; }
    },
    readLive(address, size) {
        try { return base64(new Uint8Array(ptr(address).readByteArray(size))); } catch (e) { return null; }
    },
    readFrozenBytes(base, offset, size) {
        if (!locked || !captured || offset < 0 || size <= 0 || size > 0x40000) return null;
        const data = captured.frozen[base];
        if (!data) return null;
        if (!Array.isArray(data)) {
            if (offset + size > data.byteLength) return null;
            return data.slice(offset, offset + size);
        }
        const out = new Uint8Array(size);
        for (let copied = 0; copied < size;) {
            const position = offset + copied;
            const chunk = data[Math.floor(position / 0x10000)];
            if (!chunk) return null;
            const start = position % 0x10000;
            const count = Math.min(size - copied, chunk.byteLength - start);
            if (count <= 0) return null;
            out.set(new Uint8Array(chunk, start, count), copied);
            copied += count;
        }
        return out.buffer;
    },
    readLiveBytes(address, size) {
        if (size <= 0 || size > 0x40000) return null;
        try { return ptr(address).readByteArray(size); } catch (e) { return null; }
    },
    finish() {
        armed = false;
        for (const listener of listeners.splice(0)) listener.detach();
        if (transactionHeld) setAdidTransaction(false);
        if (targetType === 4) unblockAdidExit();
    },
};
