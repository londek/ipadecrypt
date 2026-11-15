import ObjC from 'frida-objc-bridge';

// Collect only the purchase response consumed by the Go client.
var states = /* @__PURE__ */ new Map();
const maxBodyLength = 16 * 1024 * 1024;
function taskKey(task) {
  return task.handle.toString();
}
function taskRequest(task) {
  let request = task.currentRequest();
  if (request === null) {
    request = task.originalRequest();
  }
  return request;
}
function urlString(url) {
  return url === null ? "" : url.absoluteString().toString();
}
function interestingURL(url) {
  if (url === null || url.host() === null || url.path() === null) return false;
  const host = url.host().toString().toLowerCase();
  return (host === 'itunes.apple.com' || host.endsWith('.itunes.apple.com')) &&
    url.path().toString().endsWith('/buyProduct');
}
function readData(data) {
  if (data === null) {
    return null;
  }
  const length = data.length();
  if (length === 0) {
    return new ArrayBuffer(0);
  }
  return data.bytes().readByteArray(length);
}
function stateForTask(task) {
  const key = taskKey(task);
  let state = states.get(key);
  if (!state) {
    state = { chunks: [], bodyLength: 0, truncated: false };
    states.set(key, state);
  }
  return state;
}
function receiveData(task, data) {
  const request = taskRequest(task);
  if (request === null || !interestingURL(request.URL()) || data === null) {
    return;
  }
  const state = stateForTask(task);
  const length = data.length();
  if (state.bodyLength + length > maxBodyLength) {
    state.truncated = true;
    state.chunks = [];
    state.bodyLength = 0;
    return;
  }
  if (state.truncated || length === 0) {
    return;
  }
  state.chunks.push(new Uint8Array(readData(data)));
  state.bodyLength += length;
}
function responseBody(state) {
  if (state.truncated || state.bodyLength === 0) {
    return null;
  }
  const result = new Uint8Array(state.bodyLength);
  let offset = 0;
  for (const chunk of state.chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result.buffer;
}
function logResponse(task, error) {
  const request = taskRequest(task);
  if (request === null || !interestingURL(request.URL())) {
    return;
  }
  const key = taskKey(task);
  const state = stateForTask(task);
  const response = task.response();
  const entry = {
    event: "response",
    pid: Process.id,
    task: key,
    url: urlString(response !== null && response.URL() !== null ? response.URL() : request.URL()),
    bodyTruncated: state.truncated
  };
  if (error !== null) {
    entry.errorDomain = error.domain().toString();
    entry.errorCode = error.code();
  }
  send(entry, responseBody(state));
  states.delete(key);
}
function attach(className, selector, onEnter) {
  const cls = ObjC.classes[className];
  if (!cls || !cls[selector]) {
    send({ event: "hookMissing", className, selector: selector });
    return;
  }
  Interceptor.attach(cls[selector].implementation, { onEnter });
  send({ event: "hookReady", className, selector: selector });
}
attach("__NSCFLocalSessionTask", "- connection:didReceiveData:completion:", function(args) {
  try {
    receiveData(new ObjC.Object(args[0]), args[3].isNull() ? null : new ObjC.Object(args[3]));
  } catch (error) {
    send({ event: "hookError", hook: "receiveData", message: String(error) });
  }
});
attach("__NSCFLocalSessionTask", "- _onqueue_didFinishWithError:", function(args) {
  try {
    logResponse(new ObjC.Object(args[0]), args[2].isNull() ? null : new ObjC.Object(args[2]));
  } catch (error) {
    send({ event: "hookError", hook: "finish", message: String(error) });
  }
});
send({ event: "loaded", pid: Process.id });

// Native Store purchase and its confirmation callbacks.
var activePurchase = null;
function errorDetails(error) {
  if (error === null || error === void 0 || error.isNull()) {
    return null;
  }
  return {
    class: error.$className,
    domain: error.domain().UTF8String(),
    code: error.code(),
    description: error.localizedDescription().UTF8String()
  };
}
function createPurchase(parameters) {
  if (typeof parameters !== "string" || parameters.length === 0) {
    throw new Error("purchase parameters are required");
  }
  const purchase = ObjC.classes.SSPurchase.purchaseWithBuyParameters_(
    ObjC.classes.NSString.stringWithUTF8String_(
      Memory.allocUtf8String(parameters)
    )
  );
  if (purchase === null || purchase.isNull()) {
    throw new Error("SSPurchase returned null");
  }
  purchase.setCreatesDownloads_(false);
  purchase.setCreatesJobs_(false);
  purchase.setCreatesInstallJobs_(false);
  return purchase;
}
function auditTokenDataForPid(pid) {
  const kernel = Process.getModuleByName("libsystem_kernel.dylib");
  const taskInfo = new NativeFunction(kernel.getExportByName("task_info"), "int", ["uint", "int", "pointer", "pointer"]);
  const taskForPid = new NativeFunction(kernel.getExportByName("task_for_pid"), "int", ["uint", "int", "pointer"]);
  const currentTask = kernel.getExportByName("mach_task_self_").readU32();
  let targetTask = currentTask;
  const targetTaskPointer = Memory.alloc(4);
  if (pid !== Process.id) {
    const status2 = taskForPid(currentTask, pid, targetTaskPointer);
    if (status2 !== 0) {
      throw new Error(`task_for_pid(${pid}) failed: ${status2}`);
    }
    targetTask = targetTaskPointer.readU32();
  }
  const token = Memory.alloc(32);
  const count = Memory.alloc(4);
  count.writeU32(8);
  const status = taskInfo(targetTask, 16, token, count);
  if (status !== 0) {
    throw new Error(`task_info(TASK_AUDIT_TOKEN) failed: ${status}`);
  }
  return ObjC.classes.NSData.dataWithBytes_length_(token, 32);
}
var activeDialogHooks = [];
var msgSendBool = new NativeFunction(
  Module.getGlobalExportByName("objc_msgSend"),
  "bool",
  ["pointer", "pointer"]
);
function invokePurchaseCompletion(blockPointer, result) {
  const completion = new ObjC.Block(blockPointer);
  const argumentCount = completion._signature.argTypes.length - 1;
  send({ event: "purchaseDialogStage", stage: "invokeCompletion", argumentCount });
  if (argumentCount === 1) {
    completion.implementation(result);
  } else if (argumentCount === 2) {
    completion.implementation(result, NULL);
  } else {
    throw new Error("unexpected purchase completion signature: " + completion.types);
  }
  send({ event: "purchaseDialogStage", stage: "completed" });
}
function installPaymentSheetHook() {
  const cls = ObjC.classes.AMSPurchaseQueue;
  if (!cls) {
    return;
  }
  const selector = "purchase:handlePaymentSheetRequest:completion:";
  const method = ObjC.api.class_getInstanceMethod(cls.handle, ObjC.selector(selector));
  if (method.isNull()) {
    return;
  }
  const implementation = ObjC.api.method_getImplementation(method);
  const replacement = new NativeCallback(function (self, selector, purchase, request, completion) {
    send({ event: "purchasePaymentSheet", confirmed: true });
    const result = ObjC.classes.AMSPaymentSheetResult.alloc().init();
    invokePurchaseCompletion(completion, result);
  }, "void", ["pointer", "pointer", "pointer", "pointer", "pointer"]);
  activeDialogHooks.push(replacement);
  Interceptor.replace(implementation, replacement);
}
function installDirectPaymentSheetHook() {
  const cls = ObjC.classes.AMSPaymentSheetTask;
  if (!cls) {
    return;
  }
  const selector = "_presentPaymentSheetWithPaymentRequest:";
  const method = ObjC.api.class_getInstanceMethod(cls.handle, ObjC.selector(selector));
  if (method.isNull()) {
    return;
  }
  const implementation = ObjC.api.method_getImplementation(method);
  const replacement = new NativeCallback(function(self) {
    const task = new ObjC.Object(self);
    const promise = task.paymentSheetPromise();
    const result = ObjC.classes.AMSPaymentSheetResult.alloc().init();
    if (!promise.isFinished()) {
      promise.finishWithResult_(result);
    }
    send({ event: "purchasePaymentSheet", confirmed: true });
    return promise.handle;
  }, "pointer", ["pointer", "pointer", "pointer"]);
  activeDialogHooks.push(replacement);
  Interceptor.replace(implementation, replacement);
}
function installAuthenticateObserver(className) {
  const cls = ObjC.classes[className];
  if (!cls) {
    return;
  }
  const selector = "purchase:handleAuthenticateRequest:completion:";
  const method = ObjC.api.class_getInstanceMethod(cls.handle, ObjC.selector(selector));
  if (method.isNull()) {
    return;
  }
  const implementation = ObjC.api.method_getImplementation(method);
  activeDialogHooks.push(Interceptor.attach(implementation, {
    onEnter(args) {
      const request = new ObjC.Object(args[3]);
      const completion = new ObjC.Block(args[4]);
      let serverRequested = null;
      try {
        serverRequested = request.isServerRequested();
      } catch (_) {
      }
      send({
        event: "purchaseAuthenticate",
        className,
        requestClass: request.$className,
        serverRequested,
        completionTypes: completion.types
      });
    }
  }));
}
function installPurchaseDialogHook(className, selector) {
  const cls = ObjC.classes[className];
  if (!cls) {
    return;
  }
  const method = ObjC.api.class_getInstanceMethod(cls.handle, ObjC.selector(selector));
  if (method.isNull()) {
    return;
  }
  const implementation = ObjC.api.method_getImplementation(method);
  const original = new NativeFunction(implementation, "void", ["pointer", "pointer", "pointer", "pointer", "pointer"]);
  const replacement = new NativeCallback(function (self, selector, purchase, requestPointer, completion) {
      const request = new ObjC.Object(requestPointer);
      const textFields = request.textFields();
      const textFieldCount = textFields === null || textFields.isNull() ? 0 : textFields.count();
      let action = request.defaultAction();
      const preferred = request.preferredButtonActionIdentifier();
      if (preferred !== null && !preferred.isNull() && preferred.length() > 0) {
        const preferredAction = request.locateActionWithIdentifier_(preferred);
        if (preferredAction !== null && !preferredAction.isNull()) {
          action = preferredAction;
        }
      }
      let tidContinue = false;
      let identifier = null;
      if (action !== null && !action.isNull()) {
        tidContinue = msgSendBool(action.handle, ObjC.selector("ams_tidContinue"));
        identifier = action.identifier();
      }
      const shouldConfirm = textFieldCount === 0 && tidContinue && identifier !== null && !identifier.isNull();
      send({
        event: "purchaseDialog",
        className,
        textFieldCount,
        tidContinue,
        actionIdentifier: identifier === null || identifier.isNull() ? null : identifier.toString(),
        confirmed: shouldConfirm
      });
      if (!shouldConfirm) {
        original(self, selector, purchase, requestPointer, completion);
        return;
      }
      send({ event: "purchaseDialogStage", stage: "createResult" });
      const result = ObjC.classes.AMSDialogResult.alloc().initWithOriginalRequest_selectedActionIdentifier_(request, identifier);
      invokePurchaseCompletion(completion, result);
  }, "void", ["pointer", "pointer", "pointer", "pointer", "pointer"]);
  activeDialogHooks.push(replacement);
  Interceptor.replace(implementation, replacement);
}
function installPurchaseDialogHooks() {
  if (activeDialogHooks.length > 0) {
    return;
  }
  installPurchaseDialogHook("AMSPurchaseShim", "purchase:handleDialogRequest:completion:");
  installPurchaseDialogHook("AMSPurchaseTask", "authenticateTask:handleDialogRequest:completion:");
  installPaymentSheetHook();
  installDirectPaymentSheetHook();
  installAuthenticateObserver("AMSPurchaseShim");
  installAuthenticateObserver("AMSPurchaseQueue");
}
function purchaseWithShim(auditPid, clientIdentifier, parameters) {
  installPurchaseDialogHooks();
  send({ event: "purchaseStage", stage: "createPurchase" });
  activePurchase = createPurchase(parameters);
  send({ event: "purchaseStage", stage: "createShim", auditPid, clientIdentifier });
  if (!ObjC.classes.AMSPurchaseShim) {
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(ObjC.classes.NSString.stringWithUTF8String_(
      Memory.allocUtf8String("/System/Library/PrivateFrameworks/AppleMediaServices.framework")
    ));
    if (bundle !== null && !bundle.isNull()) {
      bundle.load();
    }
  }
  const shim = ObjC.classes.AMSPurchaseShim.alloc().initWithPurchase_auditTokenData_clientIdentifier_(
    activePurchase,
    auditTokenDataForPid(auditPid),
    ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(clientIdentifier))
  );
  if (shim === null || shim.isNull()) {
    throw new Error("AMSPurchaseShim returned null");
  }
  const errorPointer = Memory.alloc(Process.pointerSize);
  errorPointer.writePointer(NULL);
  send({ event: "purchaseStage", stage: "runPurchase" });
  const output = shim.runPurchase_(errorPointer);
  const errorHandle = errorPointer.readPointer();
  const error = errorHandle.isNull() ? null : new ObjC.Object(errorHandle);
  const details = errorDetails(error);
  const rawOutput = output !== null && !output.isNull() ? output : shim.rawOutput();
  const result = {
    completed: true,
    error: details,
    outputClass: rawOutput === null || rawOutput.isNull() ? null : rawOutput.$className,
    outputCount: rawOutput !== null && !rawOutput.isNull() && rawOutput.isKindOfClass_(ObjC.classes.NSDictionary) ? rawOutput.count() : null
  };
  if (rawOutput !== null && !rawOutput.isNull()) {
    const data = ObjC.classes.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
      rawOutput,
      200,
      0,
      NULL
    );
    if (data !== null && !data.isNull()) {
      const bytes = data.bytes().readByteArray(data.length());
      send({ event: "purchaseOutput", length: data.length() }, bytes);
    }
  }
  send({ event: "purchaseComplete", result });
  return result;
}
rpc.exports = {
  purchaseShim(auditPid, clientIdentifier, parameters) {
    return purchaseWithShim(auditPid, clientIdentifier, parameters);
  }
};
