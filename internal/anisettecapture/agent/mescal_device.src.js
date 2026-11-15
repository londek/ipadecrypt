import ObjC from 'frida-objc-bridge';

function loadFrameworks() {
    const dlopen = new NativeFunction(Module.getGlobalExportByName('dlopen'), 'int', ['pointer', 'int']);
    const paths = [
        '/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit',
        '/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit',
        '/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices',
        '/System/Library/PrivateFrameworks/PodcastsFoundation.framework/PodcastsFoundation',
    ];
    for (const path of paths) {
        const result = dlopen(Memory.allocUtf8String(path), 6);
        if (result === 0) throw new Error('framework load failed: ' + path);
    }
}

rpc.exports.sign = function (bodyBase64) {
    if (!ObjC.available) throw new Error('Objective-C runtime unavailable');
    loadFrameworks();
    const Session = ObjC.classes.AMSMescalSession;
    const Bag = ObjC.classes.IMURLBag;
    if (!Session || !Bag) throw new Error('Mescal classes unavailable');
    const data = ObjC.classes.NSData.alloc().initWithBase64EncodedString_options_(
        ObjC.classes.NSString.stringWithString_(bodyBase64), 0);
    if (data === null) throw new Error('invalid body base64');
    const session = Session.defaultSession();
    const bag = Bag.alloc().init();
    const promise = session.signData_bag_(data, bag);
    if (promise === null) throw new Error('Mescal returned no promise');
    const signature = promise.resultWithTimeout_error_(20, NULL);
    if (signature === null) throw new Error('Mescal returned no signature');
    return signature.base64EncodedStringWithOptions_(0).toString();
};
