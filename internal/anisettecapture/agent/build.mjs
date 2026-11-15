import { execFileSync } from 'node:child_process';
const agents = [
  ['adi_dump.js', 'adi_dump.compiled.js'],
  ['adi_anisette_call.js', 'adi_anisette_call.compiled.js'],
  ['mescal_device.src.js', 'mescal_device.js'],
  ['native_purchase.src.js', 'native_purchase.js'],
];
for (const [source, output] of agents) {
  execFileSync('node', ['node_modules/frida-compile/dist/cli.js', source, '-o', output], { stdio: 'inherit' });
}
