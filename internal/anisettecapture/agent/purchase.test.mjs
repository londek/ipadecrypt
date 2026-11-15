import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function harness() {
  const replacements = new Map();
  const listeners = new Map();
  const originalCalls = [];
  const events = [];
  const context = vm.createContext({
    rpc: {}, Process: { id: 1 }, NULL: null,
    send: event => events.push(event),
    Module: { getGlobalExportByName: name => name },
    NativeFunction: function (address) {
      return address === 'objc_msgSend' ? () => true : (...args) => originalCalls.push(args);
    },
    NativeCallback: function (callback) { return callback; },
    ObjC: {
      classes: {}, selector: name => name,
      api: {
        class_getInstanceMethod: (cls, selector) => ({ cls, selector, isNull: () => false }),
        method_getImplementation: method => `${method.cls}:${method.selector}`,
      },
      Object: function (value) { return value; },
      Block: function (value) { return value; },
    },
    Interceptor: {
      attach: (address, callbacks) => listeners.set(address, callbacks),
      replace: (address, replacement) => replacements.set(address, replacement),
    },
  });
  const source = readFileSync(new URL('native_purchase.src.js', import.meta.url), 'utf8');
  vm.runInContext(source.replace("import ObjC from 'frida-objc-bridge';", ''), context);
  function invoke(address, ...args) {
    if (replacements.has(address)) return replacements.get(address)(...args);
    listeners.get(address)?.onEnter(args);
    // attach observes; Frida continues the real implementation afterwards.
    originalCalls.push(args);
  }
  return { context, originalCalls, events, invoke };
}

test('authentication observer leaves the native method to run exactly once', () => {
  const h = harness();
  h.context.ObjC.classes.AMSPurchaseShim = { handle: 'shim' };
  h.context.installAuthenticateObserver('AMSPurchaseShim');
  h.invoke('shim:purchase:handleAuthenticateRequest:completion:', 1, 2, 3,
    { isServerRequested: () => true }, { types: 'signature' });
  assert.equal(h.originalCalls.length, 1);
  assert.equal(h.events.filter(e => e.event === 'purchaseAuthenticate').length, 1);
});

test('dialog replacement either completes TID confirmation or calls the original once', () => {
  for (const textFieldCount of [0, 1]) {
    const h = harness();
    let completions = 0;
    h.context.ObjC.classes.AMSPurchaseShim = { handle: 'shim' };
    h.context.ObjC.classes.AMSDialogResult = { alloc: () => ({
      initWithOriginalRequest_selectedActionIdentifier_: () => ({ result: true }),
    }) };
    h.context.installPurchaseDialogHook('AMSPurchaseShim', 'dialog');
    const identifier = { isNull: () => false, toString: () => 'continue' };
    const action = { isNull: () => false, identifier: () => identifier };
    const request = {
      textFields: () => ({ isNull: () => false, count: () => textFieldCount }),
      defaultAction: () => action, preferredButtonActionIdentifier: () => null,
    };
    const completion = { _signature: { argTypes: ['block', 'result'] },
      implementation: () => completions++ };
    h.invoke('shim:dialog', 1, 2, 3, request, completion);
    assert.equal(completions, textFieldCount === 0 ? 1 : 0);
    assert.equal(h.originalCalls.length, textFieldCount === 0 ? 0 : 1);
  }
});

test('payment sheet replacement invokes completion once without entering the native method', () => {
  const h = harness();
  let completions = 0;
  h.context.ObjC.classes.AMSPurchaseQueue = { handle: 'queue' };
  h.context.ObjC.classes.AMSPaymentSheetResult = { alloc: () => ({ init: () => ({}) }) };
  h.context.installPaymentSheetHook();
  h.invoke('queue:purchase:handlePaymentSheetRequest:completion:', 1, 2, 3, 4,
    { _signature: { argTypes: ['block', 'result', 'error'] }, implementation: () => completions++ });
  assert.equal(completions, 1);
  assert.equal(h.originalCalls.length, 0);
});

test('response capture excludes authentication and unrelated hosts', () => {
  const h = harness();
  const url = (host, path) => ({ host: () => host, path: () => path });
  assert.equal(h.context.interestingURL(url('p25-buy.itunes.apple.com', '/WebObjects/MZBuy.woa/wa/buyProduct')), true);
  assert.equal(h.context.interestingURL(url('gsa.apple.com', '/grandslam/GsService2')), false);
  assert.equal(h.context.interestingURL(url('auth.itunes.apple.com', '/auth/v1/native')), false);
  assert.equal(h.context.interestingURL(url('itunes.apple.com.invalid', '/buyProduct')), false);
  assert.throws(() => h.context.createPurchase(''), /parameters are required/);
});
