import ObjC from 'frida-objc-bridge';

const TRIGGER_TIMEOUT_MS = 15000;
const activeBlocks = new Set();
let gsaRequest = null;
let amdRequest = null;
const dispatchAsync = new NativeFunction(
    Module.getGlobalExportByName('dispatch_async'), 'void', ['pointer', 'pointer']);
const dispatchGetGlobalQueue = new NativeFunction(
    Module.getGlobalExportByName('dispatch_get_global_queue'), 'pointer', ['long', 'ulong']);

// One active request per agent. A timeout does not cancel AuthKit's native
// operation, so never launch another one on a later poll.
function requestGSA() {
    if (gsaRequest !== null) return gsaRequest;
    gsaRequest = new Promise((resolve) => {
        const Controller = ObjC.classes.AKAnisetteProvisioningController;
        if (!Controller || !Controller['- anisetteDataWithError:']) {
            resolve({ error: 'AuthKit anisette controller unavailable', unavailable: true });
            return;
        }
        let done = false;
        let timer;
        const state = { controller: Controller.alloc().init(), work: null };
        activeBlocks.add(state);
        const finish = result => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            resolve(result);
        };
        state.work = new ObjC.Block({
            retType: 'void', argTypes: [],
            implementation: () => {
                try {
                    const error = Memory.alloc(Process.pointerSize);
                    error.writePointer(ptr(0));
                    const data = state.controller.anisetteDataWithError_(error);
                    if (data === null || data.handle.isNull()) {
                        finish({ error: 'AuthKit did not return anisette data' });
                    } else {
                        const d = new ObjC.Object(data);
                        const otp = d.oneTimePassword();
                        const mid = d.machineID();
                        const routing = d.routingInfo();
                        finish({
                            epoch30: Math.floor(Date.now() / 30000),
                            otpB64: otp === null ? null : otp.toString(),
                            midB64: mid === null ? null : mid.toString(),
                            routingInfo: routing === null ? null : routing.toString(),
                        });
                    }
                } catch (e) { finish({ error: 'AuthKit request failed' }); }
                finally { activeBlocks.delete(state); }
            },
        });
        timer = setTimeout(() => finish({ error: 'AuthKit anisette getter exceeded 15s' }), TRIGGER_TIMEOUT_MS);
        // The synchronous getter runs on a background queue, never the RPC thread.
        // Retain its block even after timeout; a native call may return late.
        dispatchAsync(dispatchGetGlobalQueue(0, 0), state.work.handle);
    });
    return gsaRequest;
}

function requestAMD() {
    if (amdRequest !== null) return amdRequest;
    amdRequest = new Promise(resolve => {
        const cls = ObjC.classes.AMSAnisette;
        const selector = '+ _headersForRequest:account:type:';
        if (!cls || !cls[selector]) {
            resolve({error:'Store anisette getter unavailable',unavailable:true});
            return;
        }
        let done = false;
        let timer;
        const state = {work:null};
        activeBlocks.add(state);
        const finish = result => {
            if (done) return;
            done = true; clearTimeout(timer); resolve(result);
        };
        state.work = new ObjC.Block({retType:'void',argTypes:[],implementation:() => {
            try {
                const url = ObjC.classes.NSURL.URLWithString_('https://auth.itunes.apple.com/auth/v1/native');
                const request = ObjC.classes.NSURLRequest.requestWithURL_(url);
                // Native Store type-2 proof. No account password, purchase or
                // synthetic provisioning request is supplied by this agent.
                const headers = cls[selector](request, ptr(0), 2);
                if (headers === null) { finish({error:'Store anisette returned no headers'}); return; }
                const amd = headers.objectForKey_('X-Apple-AMD');
                const mid = headers.objectForKey_('X-Apple-AMD-M');
                if (amd === null || mid === null) {
                    finish({error:'Store anisette returned an incomplete AMD proof'}); return;
                }
                finish({amdB64:amd.toString(),amdMidB64:mid.toString(),epoch30:Math.floor(Date.now()/30000)});
            } catch (e) { finish({error:'Store anisette getter failed'}); }
            finally { activeBlocks.delete(state); }
        }});
        timer = setTimeout(() => finish({error:'Store anisette getter exceeded 15s'}),TRIGGER_TIMEOUT_MS);
        dispatchAsync(dispatchGetGlobalQueue(0,0),state.work.handle);
    });
    return amdRequest;
}

rpc.exports = {
    staticHeaders() {
        // Local getters only: no authentication, provisioning or HTTP request.
        const headers = {};
        const keys = ['X-Mme-Device-Id', 'X-Apple-I-SRL-NO', 'X-MMe-Client-Info',
            'X-Apple-I-MD-LU', 'X-Apple-I-TimeZone', 'X-Apple-Locale'];
        const Session = ObjC.classes.AKAppleIDSession;
        if (Session && Session['- _genericAppleIDHeadersDictionaryForRequest:']) {
            const session = Session.alloc().initWithIdentifier_('com.apple.akd');
            const url = ObjC.classes.NSURL.URLWithString_('https://gsa.apple.com/grandslam/GsService2');
            const request = ObjC.classes.NSURLRequest.requestWithURL_(url);
            const values = session['- _genericAppleIDHeadersDictionaryForRequest:'](request);
            if (values !== null) {
                for (const key of keys) {
                    const value = values.objectForKey_(key);
                    if (value !== null) headers[key] = value.toString();
                }
                if (!headers['X-Apple-Locale']) {
                    const locale = values.objectForKey_('X-Apple-I-Locale');
                    if (locale !== null) headers['X-Apple-Locale'] = locale.toString();
                }
            }
        }
        const Device = ObjC.classes.AKDevice;
        if (Device && Device['+ currentDevice']) {
            const device = Device.currentDevice();
            for (const [key, selector] of [
                ['X-Mme-Device-Id', 'uniqueDeviceIdentifier'],
                ['X-Apple-I-SRL-NO', 'serialNumber'],
                ['X-MMe-Client-Info', 'serverFriendlyDescription'],
                ['X-Apple-I-MD-LU', 'localUserUUID'],
            ]) {
                if (headers[key] || !device[selector]) continue;
                const value = device[selector]();
                if (value !== null) headers[key] = value.toString();
            }
        }
        if (!headers['X-Apple-I-TimeZone'])
            headers['X-Apple-I-TimeZone'] = ObjC.classes.NSTimeZone.localTimeZone().name().toString();
        if (!headers['X-Apple-Locale'])
            headers['X-Apple-Locale'] = ObjC.classes.NSLocale.currentLocale().localeIdentifier().toString();
        return headers;
    },
    requestGsa: requestGSA,
    requestAmd: requestAMD,
};
