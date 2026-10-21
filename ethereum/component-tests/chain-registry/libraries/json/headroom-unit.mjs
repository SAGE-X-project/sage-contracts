// Six fixed size-only controls. Uses exact production artifact from the main units.
// No Registry admission, branch/source coverage, chain or network assertion.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createVM} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createAddressFromString} from '@ethereumjs/util';
import {call} from '../normal-abi.mjs';
const root = new URL('./', import.meta.url);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const read = name => fs.readFileSync(new URL(name, root));
const write = (name, value) => fs.writeFileSync(new URL('headroom/evidence/' + name, root), JSON.stringify(value, null, 2) + '\n');
// The accepted coordinator must finish the fresh JSON group first. Its
// receipt seals the new-layout files and generated production artifacts.
const receipt = JSON.parse(read('evidence/local-execution.json'));
assert.equal(receipt.group, 'json');
assert.equal(receipt.exit_code, 0);
assert.deepEqual(receipt.command, ['node', '--max-old-space-size=512', '--test', '--test-concurrency=1', '--experimental-test-coverage', '--test-coverage-lines=90', '--test-coverage-include=**/unit.mjs', '--test-reporter=spec', '--test-reporter-destination=stdout', '--test-reporter=lcov', '--test-reporter-destination=evidence/js-coverage.lcov', 'unit.mjs']);
for (const [path, digest] of Object.entries(receipt.source_inputs_sha256)) {
  assert(!path.startsWith('/') && !path.split('/').includes('..'));
  assert.equal(sha(fs.readFileSync(new URL(path, new URL('../../../../../', root)))), digest);
}
const original = new URL('evidence/', root);
for (const [name, digest] of Object.entries(receipt.files_sha256)) {
  assert(!name.startsWith('/') && !name.split('/').includes('..'));
  assert.equal(sha(fs.readFileSync(new URL(name, original))), digest);
}
const goldenBytes = read('headroom-goldens.json');
const cases = JSON.parse(goldenBytes).cases;
assert.equal(cases.length, 6);
assert.equal(new Set(cases.map(value => value.name)).size, 6);
const word = value => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
fs.mkdirSync(new URL('headroom/evidence/', root), {recursive: true});
for (const target of ['paris', 'shanghai']) test(target + ': exact terminal-version record headroom', async () => {
  const inputBytes = fs.readFileSync(new URL(target + '-input.json', original));
  const outputBytes = fs.readFileSync(new URL(target + '-output.json', original));
  assert.equal(sha(inputBytes), receipt.files_sha256[target + '-input.json']);
  assert.equal(sha(outputBytes), receipt.files_sha256[target + '-output.json']);
  const input = JSON.parse(inputBytes), output = JSON.parse(outputBytes);
  assert.equal(input.language, 'Solidity');
  const productionPrefix = 'ethereum/contracts/chain-registry/';
  assert.deepEqual(Object.keys(input.sources).sort(), ['JsonHarness.sol', ...['RegistryJson.sol', 'RegistryText.sol', 'RegistryBuffer.sol', 'IChainRegistry.sol'].map(name => productionPrefix + name)].sort());
  for (const [name, source] of Object.entries(input.sources)) {
    assert.deepEqual(Object.keys(source), ['content']);
    const path = name === 'JsonHarness.sol' ? new URL(name, root) : new URL('../../../../contracts/chain-registry/' + name.split('/').pop(), root);
    assert.equal(sha(Buffer.from(source.content)), sha(fs.readFileSync(path)));
  }
  assert.deepEqual(input.settings.metadata, {bytecodeHash: 'ipfs', appendCBOR: true});
  assert.deepEqual(input.settings.outputSelection, {'*': {'*': ['abi', 'evm.deployedBytecode'], '': ['ast']}});
  assert.equal(input.settings.evmVersion, target);
  assert.equal(input.settings.viaIR, true);
  assert.deepEqual(input.settings.optimizer, {enabled: true, runs: 200});
  assert(!(output.errors ?? []).some(value => value.severity === 'error'));
  const artifact = output.contracts['JsonHarness.sol'].JsonHarness;
  const object = artifact.evm.deployedBytecode.object;
  assert(/^(?:[0-9a-f]{2})+$/.test(object));
  assert.equal(Object.keys(artifact.evm.deployedBytecode.immutableReferences ?? {}).length, 0);
  const vm = await createVM({common: new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai})});
  assert.equal(vm.evm.DEBUG, false);
  assert.equal(vm.evm.events.listenerCount('step'), 0);
  const address = createAddressFromString('0x0000000000000000000000000000000000003000');
  const caller = createAddressFromString('0x0000000000000000000000000000000000001000');
  await vm.stateManager.putCode(address, Buffer.from(object, 'hex'));
  const rows = [];
  for (const entry of cases) {
    const hydrate = value => Array.isArray(value) ? value.map(hydrate) : value && typeof value === 'object' ? ('$hex' in value ? Buffer.from(value.$hex, 'hex') : Object.fromEntries(Object.entries(value).map(([name, item]) => [name, hydrate(item)]))) : value;
    const data = call(artifact.abi, entry.method, hydrate(entry.arguments));
    const expected = Buffer.from(entry.expected_hex, 'hex');
    const resultBytes = entry.exception ? expected : Buffer.concat([word(32), word(expected.length), expected, Buffer.alloc((32 - expected.length % 32) % 32)]);
    const result = await vm.evm.runCall({to: address, caller, data, gasLimit: 250_000_000n});
    const exception = result.execResult.exceptionError?.error ?? null;
    const returned = Buffer.from(result.execResult.returnValue);
    assert.equal(exception, entry.exception, entry.name);
    assert.deepEqual(returned, resultBytes, entry.name);
    assert.equal(vm.evm.events.listenerCount('step'), 0);
    rows.push({name: entry.name, calldata_sha256: sha(data), expected_return_hex: resultBytes.toString('hex'), actual_return_hex: returned.toString('hex'), exception, gas: result.execResult.executionGasUsed.toString(), actual_json_bytes: entry.actual_json_bytes, temporary_json_bytes: entry.temporary_json_bytes});
    write(target + '-rows.json', {scope: 'Six fixed pure production artifact size controls only; no source coverage or Registry admission', input_sha256: sha(inputBytes), output_sha256: sha(outputBytes), golden_sha256: sha(goldenBytes), runtime_sha256: sha(Buffer.from(object, 'hex')), complete: rows.length === 6, rows});
    console.log(target + ': ' + entry.name + ' actual=' + entry.actual_json_bytes + ' temporary=' + entry.temporary_json_bytes);
  }
});
