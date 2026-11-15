These JavaScript agents run inside iPhone processes. The Go CLI embeds the built
agents; users do not need Node.js, npm, Python, or host Frida bindings.

To rebuild after editing an agent:

```sh
cd internal/anisettecapture/agent
npm ci
npm test
npm run build
```

The lockfile pins the compiler and Objective-C bridge. Review the readable `.js`
and `.src.js` inputs; keep their compiled outputs in the same change. The bridge
inside those bundles is third-party code, managed by npm rather than edited here.

`native_purchase.src.js` captures only Store `buyProduct` responses. Authentication
hooks observe the original method; dialog hooks that complete a request use a
replacement so the original cannot invoke its completion a second time. Its
Node tests simulate these two distinct Frida dispatch semantics without purchases.

The adid capture profile targets iPhone 11 / iOS 26 offsets and memory layout.
These offsets are specific to that profile. Live capture tests are
explicit opt-ins in the Go package and must write into an isolated directory.

The bundled bridge is [frida-objc-bridge 8.0.6](https://github.com/frida/frida-objc-bridge),
whose package metadata declares `LGPL-2.0 WITH WxWindows-exception-3.1`.
Its upstream notices and license apply to the embedded bridge as well.
