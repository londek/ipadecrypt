📦
13559 /adi_dump.js
10295 /adi_dump.js.map
✄
// adi_dump.js
var main = Process.enumerateModules().find((m) => m.name === "adid") || Process.enumerateModules()[0];
var importNames = [
  "gettimeofday",
  "time",
  "malloc",
  "malloc_zone_malloc",
  "malloc_type_malloc",
  "malloc_type_calloc",
  "malloc_type_realloc",
  "malloc_type_free",
  "free",
  "calloc",
  "realloc",
  "memcpy",
  "memset",
  "memcmp",
  "mmap",
  "munmap",
  "__stack_chk_fail",
  "__chkstk_darwin",
  "xpc_dictionary_get_data",
  "xpc_dictionary_set_data",
  "xpc_dictionary_create_reply",
  "xpc_dictionary_send_reply",
  "pthread_once",
  "dispatch_once",
  "SecTaskCopyValueForEntitlement",
  "CFGetTypeID",
  "CFStringGetTypeID",
  "CFNumberGetTypeID",
  "CFStringGetCString",
  "__CFTSDGetTable",
  "strtoul",
  "lstat",
  "lstat64",
  "stat",
  "stat64",
  "mach_absolute_time",
  "IOConnectCallStructMethod",
  "IOServiceOpen",
  "__stack_chk_guard"
];
function resolveExport(name) {
  if (typeof Module.findGlobalExportByName === "function") {
    const address = Module.findGlobalExportByName(name);
    if (address !== null) return address;
  }
  for (const module of Process.enumerateModules()) {
    try {
      const address = module.findExportByName(name);
      if (address !== null) return address;
    } catch (e) {
    }
  }
  return null;
}
function base64(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += alphabet[a >> 2] + alphabet[(a & 3) << 4 | b >> 4];
    out += i + 1 < bytes.length ? alphabet[(b & 15) << 2 | c >> 6] : "=";
    out += i + 2 < bytes.length ? alphabet[c & 63] : "=";
  }
  return out;
}
var captured = null;
var armed = false;
var locked = false;
var tracing = false;
var replyTracing = false;
var importTrace = [];
var localImports = {};
var targetType = 5;
var selectedRanges = [];
var captureSequence = 0;
var transactionHeld = false;
var handlerCalls = 0;
var replyCalls = 0;
var observedReplyTypes = /* @__PURE__ */ new Set();
var requestKinds = {};
var replyKinds = {};
var skippedRequests = 0;
var listeners = [];
function isGSARequest(bytes) {
  return bytes.length === 20 && bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 1 && bytes[8] === 0 && bytes[9] === 0 && bytes[10] === 0 && bytes[11] === 1 && bytes.slice(12, 19).every((value) => value === 255) && bytes[19] === 254;
}
function setAdidTransaction(hold) {
  const address = resolveExport(hold ? "xpc_transaction_begin" : "xpc_transaction_end");
  if (address === null) return;
  new NativeFunction(address, "void", [])();
  transactionHeld = hold;
}
var exitBlocked = false;
var blockedExitAddresses = [];
var adidSleep = new NativeFunction(resolveExport("sleep"), "uint", ["uint"]);
var adidExitHandler = new NativeCallback(function(code) {
  exitBlocked = true;
  send({ event: "adid-exit", code });
  while (exitBlocked) adidSleep(1);
}, "void", ["int"]);
function blockAdidExit() {
  for (const name of ["exit", "_exit"]) {
    const address = resolveExport(name);
    if (address === null) continue;
    try {
      Interceptor.replace(address, adidExitHandler);
      blockedExitAddresses.push(address);
    } catch (e) {
    }
  }
}
function unblockAdidExit() {
  exitBlocked = false;
  for (const address of blockedExitAddresses) Interceptor.revert(address);
  blockedExitAddresses = [];
}
var handlerAddress = main.base.add(1143272);
var handlerBytes = null;
try {
  handlerBytes = base64(new Uint8Array(handlerAddress.readByteArray(16)));
} catch (e) {
}
for (const name of ["xpc_dictionary_set_data"]) {
  const address = resolveExport(name);
  if (address === null || name === "__stack_chk_guard") continue;
  try {
    listeners.push(Interceptor.attach(address, {
      onEnter(args) {
        if (armed && name === "xpc_dictionary_set_data") {
          try {
            const length = args[3].toInt32();
            let type = "none";
            if (length === 100 || length === 96) {
              const offset = 72;
              const header = new Uint8Array(args[2].add(offset).readByteArray(8));
              if (header[0] === 0 && header[1] === 0 && header[2] === 0 && header[4] === 0 && header[5] === 0 && header[6] === 0 && header[7] === 16)
                type = String(header[3]);
            }
            const kind = `${length}:type=${type}:tracing=${tracing}:sameThread=${!!captured && this.threadId === captured.threadId}`;
            if (Object.keys(replyKinds).length < 64) replyKinds[kind] = (replyKinds[kind] || 0) + 1;
          } catch (e) {
          }
        }
        if (targetType !== 4 && (!captured || this.threadId !== captured.threadId)) return;
        if (name === "xpc_dictionary_set_data") {
          if (targetType === 4 ? !replyTracing : !tracing) return;
        } else if (!tracing) return;
        importTrace.push({ name, caller: this.returnAddress.toString() });
        if (name !== "xpc_dictionary_set_data") return;
        replyCalls++;
        let matched = false;
        try {
          const length = args[3].toInt32();
          const bytes = new Uint8Array(args[2].readByteArray(length));
          for (let i = 0; i + 24 <= bytes.length; i++) {
            if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 && bytes[i + 4] === 0 && bytes[i + 5] === 0 && bytes[i + 6] === 0 && bytes[i + 7] === 16) {
              observedReplyTypes.add(bytes[i + 3]);
            }
          }
          for (let i = 0; i + 24 <= bytes.length; i++) {
            if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 && bytes[i + 3] === targetType && bytes[i + 4] === 0 && bytes[i + 5] === 0 && bytes[i + 6] === 0 && bytes[i + 7] === 16) {
              matched = true;
              if (captured) {
                locked = true;
                captured.importTrace = importTrace.slice();
                captured.replyLen = length;
                if (targetType === 4 || i + 28 <= bytes.length) {
                  send({
                    event: "adid-locked",
                    captureId: captured.captureId,
                    replyLen: length,
                    importTrace: captured.importTrace,
                    localImports,
                    epoch30: captured.epoch30,
                    ...length >= 68 && bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 0 && bytes[4] === 0 && bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 60 ? { midB64: base64(bytes.slice(8, 68)) } : {},
                    ...targetType === 4 ? { amdB64: base64(bytes.slice(i, i + 24)) } : { otpB64: base64(bytes.slice(i, i + 28)) }
                  });
                }
              }
              break;
            }
          }
        } catch (e) {
        }
        if (matched) {
          replyTracing = false;
          if (targetType !== 4) tracing = false;
        }
      }
    }));
  } catch (e) {
  }
}
function freezeSelectedRanges() {
  for (const range of selectedRanges) {
    try {
      const data = ptr(range.base).readByteArray(range.size);
      if (data === null) throw new Error("readByteArray returned null");
      captured.frozen[range.base] = data;
    } catch (wholeError) {
      const chunks = [];
      let failed = null;
      for (let offset = 0; offset < range.size; offset += 65536) {
        const size = Math.min(65536, range.size - offset);
        try {
          const data = ptr(range.base).add(offset).readByteArray(size);
          if (data === null) throw new Error("readByteArray returned null");
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
listeners.push(Interceptor.attach(handlerAddress, {
  onEnter() {
    handlerCalls++;
    if (!armed || locked) return;
    if (targetType !== 4) {
      let request;
      try {
        request = new Uint8Array(this.context.x0.readByteArray(20));
      } catch (e) {
        skippedRequests++;
        return;
      }
      const kind = `${request[0]}.${request[1]}.${request[2]}.${request[3]}:${isGSARequest(request) ? "GSA" : "other"}`;
      requestKinds[kind] = (requestKinds[kind] || 0) + 1;
      if (!isGSARequest(request)) {
        skippedRequests++;
        return;
      }
    }
    const context = this.context;
    const regs = {};
    for (let i = 0; i <= 28; i++) regs["x" + i] = context["x" + i].toString();
    regs.fp = context.fp.toString();
    regs.lr = context.lr.toString();
    regs.sp = context.sp.toString();
    regs.pc = context.pc.toString();
    let stack = null;
    let used = 0;
    for (const size of [262144, 131072, 65536, 32768, 16384, 4096]) {
      try {
        const data = context.sp.readByteArray(size);
        if (data) {
          stack = Array.from(new Uint8Array(data));
          used = size;
          break;
        }
      } catch (e) {
      }
    }
    let input = null;
    try {
      input = base64(new Uint8Array(context.x0.readByteArray(20)));
    } catch (e) {
    }
    captured = {
      epoch30: Math.floor(Date.now() / 3e4),
      threadId: this.threadId,
      regs,
      stackLo: context.sp.toString(),
      stackSize: used,
      stack,
      x0: context.x0.toString(),
      input,
      frozen: {},
      frozenErrors: {}
    };
    if (targetType !== 4) freezeSelectedRanges();
    captured.captureId = ++captureSequence;
    importTrace = [];
    if (targetType === 4) replyTracing = true;
    if (targetType !== 4) tracing = true;
  }
}));
rpc.exports = {
  status() {
    return {
      handlerCalls,
      replyCalls,
      locked,
      armed,
      targetType,
      skippedRequests,
      requestKinds,
      replyKinds,
      selectedRangeCount: selectedRanges.length,
      frozenRangeCount: captured ? Object.keys(captured.frozen).length : 0,
      observedReplyTypes: Array.from(observedReplyTypes)
    };
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
      try {
        stackGuard = { address: guard, value: ptr(guard).readPointer().toString() };
      } catch (e) {
      }
    }
    delete imports.__stack_chk_guard;
    return {
      base: main.base.toString(),
      size: main.size,
      path: main.path,
      imports,
      stackGuard,
      handlerAddress: handlerAddress.toString(),
      handlerBytes
    };
  },
  ranges() {
    const out = [];
    for (const range of Process.enumerateRanges("r--")) {
      let file = null;
      try {
        file = range.file ? range.file.path : null;
      } catch (e) {
      }
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
  localImports() {
    return localImports;
  },
  target(type) {
    targetType = type;
  },
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
        const chunk = data[Math.floor(offset / 65536)];
        return base64(new Uint8Array(chunk, offset % 65536, size));
      }
      return base64(new Uint8Array(data, offset, size));
    } catch (e) {
      return null;
    }
  },
  readLive(address, size) {
    try {
      return base64(new Uint8Array(ptr(address).readByteArray(size)));
    } catch (e) {
      return null;
    }
  },
  readFrozenBytes(base, offset, size) {
    if (!locked || !captured || offset < 0 || size <= 0 || size > 262144) return null;
    const data = captured.frozen[base];
    if (!data) return null;
    if (!Array.isArray(data)) {
      if (offset + size > data.byteLength) return null;
      return data.slice(offset, offset + size);
    }
    const out = new Uint8Array(size);
    for (let copied = 0; copied < size; ) {
      const position = offset + copied;
      const chunk = data[Math.floor(position / 65536)];
      if (!chunk) return null;
      const start = position % 65536;
      const count = Math.min(size - copied, chunk.byteLength - start);
      if (count <= 0) return null;
      out.set(new Uint8Array(chunk, start, count), copied);
      copied += count;
    }
    return out.buffer;
  },
  readLiveBytes(address, size) {
    if (size <= 0 || size > 262144) return null;
    try {
      return ptr(address).readByteArray(size);
    } catch (e) {
      return null;
    }
  },
  finish() {
    armed = false;
    for (const listener of listeners.splice(0)) listener.detach();
    if (transactionHeld) setAdidTransaction(false);
    if (targetType === 4) unblockAdidExit();
  }
};

✄
{
  "version": 3,
  "sources": ["adi_dump.js"],
  "mappings": "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",
  "names": []
}
