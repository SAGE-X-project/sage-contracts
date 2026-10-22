// One selected compiler input only, with unchanged original-source membership.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import test from 'node:test';
const here = new URL('./', import.meta.url);
assert.equal(process.version, 'v24.4.1');
assert(process.execArgv.includes('--max-old-space-size=512'));
assert.equal(process.env.NODE_OPTIONS ?? '', ''); assert.equal(process.env.DEBUG ?? '', '');
test('selected bounded source compilation', () => {
  const build = process.env.SAGE_CONTROL_BUILD; assert(/^(stateless|rules)-(paris|shanghai)$|^(processor|semantic|core)-shanghai$/.test(build));
  const compilerPath = new URL('../evidence/soljson.cjs', here);
  const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  assert.equal(digest(fs.readFileSync(compilerPath)), '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
  const compiler = createRequire(import.meta.url)(compilerPath.pathname);
  assert.equal(compiler.cwrap('solidity_version', 'string', [])(), '0.8.20+commit.a1b79de6.Emscripten.clang');
  const input = fs.readFileSync(new URL('evidence/' + build + '-input.json', here));
  const output = JSON.parse(compiler.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(input.toString(), 0, 0));
  const rendered = JSON.stringify(output, null, 2) + '\n';
  assert(Buffer.byteLength(rendered) <= 32 * 1024 ** 2);
  fs.writeFileSync(new URL('evidence/' + build + '-output.json', here), rendered, {flag: 'wx'});
  assert(!(output.errors ?? []).some(error => error.severity === 'error'), JSON.stringify(output.errors));
  assert.deepEqual(Object.keys(output.sources).sort(), Object.keys(JSON.parse(input).sources).sort());
  console.log(JSON.stringify({build, input_sha256: digest(input), node: process.version,
    node_binary_sha256: digest(fs.readFileSync(process.execPath)), compiler_sha256: digest(fs.readFileSync(compilerPath))}));
});
