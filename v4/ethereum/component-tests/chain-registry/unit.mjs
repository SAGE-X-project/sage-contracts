import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createVM} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createAddressFromString} from '@ethereumjs/util';
import {compile, directory, sha, write} from './compile.mjs';
import {call, selector} from './normal-abi.mjs';
const read = name => JSON.parse(fs.readFileSync(new URL('fixtures/' + name, directory)));
const functions = read('functions.json'), outcomes = read('outcomes.json'), binding = read('binding.json');
const typeKey = 'ethereum/contracts/chain-registry/IChainRegistry.sol';
const frameKey = 'ethereum/contracts/chain-registry/RegistryFraming.sol';
const harnessKey = 'ethereum/component-tests/chain-registry/FramingHarness.sol';
function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'internalType').map(([key, entry]) => [key, normalize(entry)]));
  return value;
}
const sorted = abi => abi.map(normalize).sort((a, b) => (a.type + a.name).localeCompare(b.type + b.name));
const controller = '0x0000000000000000000000000000000000000001';
const entry = {name: 'signing', alg: 'ed25519', key: Buffer.alloc(32, 1), signer: 'did:sage:unit#signing', proof: Buffer.alloc(64, 2), hasExpiry: false, expires: 0n};
const service = {name: 'rpc', serviceType: 'A2A', uri: 'https://example.invalid/agent'};
// Public fixed unit data only. The harness neither validates nor produces proofs.
const normal = {
  commitClaim: [Buffer.alloc(32, 3)], revealClaim: ['unit', controller, [entry], [service], Buffer.alloc(32, 4)],
  activate: ['unit', 1n], deactivate: ['unit', 1n], addKey: ['unit', 1n, entry], revokeKey: ['unit', 1n, 'signing'],
  updateServices: ['unit', 1n, [service]], authorizeOperator: ['unit', 1n, controller, 'update-services'],
  revokeOperator: ['unit', 1n, controller, 'update-services'], record: ['unit'], registryId: [],
  activeGrants: ['unit'], historyItem: ['unit', 1n]
};
function mappedCoverage(output, visited) {
  const compiled = output.contracts[harnessKey].FramingHarness.evm.deployedBytecode;
  const bytes = Buffer.from(compiled.object, 'hex');
  let pc = 0, previous = ['0', '0', '-1', '', ''];
  const hits = [];
  for (const fragment of compiled.sourceMap.split(';')) {
    const row = fragment.split(':').map((value, index) => value === '' ? previous[index] : value);
    while (row.length < previous.length) row.push(previous[row.length]);
    if (visited.has(pc)) hits.push(row.slice(0, 3).map(Number));
    previous = row;
    const opcode = bytes[pc]; pc += 1 + (opcode >= 0x60 && opcode <= 0x7f ? opcode - 0x5f : 0);
  }
  const source = output.sources[frameKey], statements = [];
  function walk(node) {
    if (!node || typeof node !== 'object') return;
    if (['ExpressionStatement', 'VariableDeclarationStatement', 'IfStatement', 'ForStatement', 'Return', 'RevertStatement', 'InlineAssembly'].includes(node.nodeType)) {
      const [start, length, file] = node.src.split(':').map(Number);
      statements.push({id: node.id, type: node.nodeType, start, length, file});
    }
    for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(walk); else if (value && typeof value === 'object') walk(value);
  }
  walk(source.ast);
  // A whole-function/contract map must never mark its child statements covered.
  const covered = statements.filter(statement => hits.some(([start, length, file]) => file === source.id && length > 0 && start >= statement.start && start + length <= statement.start + statement.length));
  return {scope: 'Conservative contained statement source-map observation only; not branch or Registry coverage', statements,
    covered_statement_ids: covered.map(statement => statement.id).sort((a, b) => a - b), visited_pcs: [...visited].sort((a, b) => a - b),
    total: statements.length, covered: covered.length, percent: covered.length * 100 / statements.length};
}
for (const target of ['paris', 'shanghai']) test(target + ': exact ABI, framing and fixed refusals', async () => {
  for (const [name, identity] of Object.entries(read('source.json').files)) assert.equal(sha(fs.readFileSync(new URL('fixtures/' + name, directory))), identity.sha256);
  assert.equal(binding.status, 'ADOPTED_CHAIN_MANAGEMENT_BINDING');
  const {output} = compile(target);
  const coverageOutput = compile(target, true).output;
  assert.deepEqual(sorted(output.contracts[typeKey].IChainRegistry.abi), sorted([...functions, ...outcomes]));
  const harness = output.contracts[harnessKey].FramingHarness, code = Buffer.from(harness.evm.deployedBytecode.object, 'hex');
  assert(code.length > 0 && code.length <= 24576);
  const vm = await createVM({common: new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai})});
  const address = createAddressFromString('0x0000000000000000000000000000000000003000');
  const caller = createAddressFromString('0x0000000000000000000000000000000000001000');
  await vm.stateManager.putCode(address, code);
  const coverageAddress = createAddressFromString('0x0000000000000000000000000000000000004000');
  await vm.stateManager.putCode(coverageAddress, Buffer.from(coverageOutput.contracts[harnessKey].FramingHarness.evm.deployedBytecode.object, 'hex'));
  const visited = new Set(), rows = [];
  vm.evm.events.on('step', (step, next) => { if (step.address.equals(coverageAddress)) visited.add(step.pc); next?.(); });
  async function observe(name, input, diagnostic = null) {
    const result = await vm.evm.runCall({to: address, caller, data: call(harness.abi, 'check', [input]), gasLimit: 30_000_000n});
    const coveredResult = await vm.evm.runCall({to: coverageAddress, caller, data: call(harness.abi, 'check', [input]), gasLimit: 30_000_000n});
    assert.equal(coveredResult.execResult.exceptionError?.error, result.execResult.exceptionError?.error, 'coverage-control refusal parity: ' + name);
    assert.deepEqual(Buffer.from(coveredResult.execResult.returnValue), Buffer.from(result.execResult.returnValue), 'coverage-control result parity: ' + name);
    const bytes = Buffer.from(result.execResult.returnValue);
    const row = {name, input_bytes: input.length, input_sha256: sha(input), input_hex: input.toString('hex'), control_exception: coveredResult.execResult.exceptionError?.error ?? null, control_return_hex: Buffer.from(coveredResult.execResult.returnValue).toString('hex'), exception: result.execResult.exceptionError?.error ?? null,
      return_hex: bytes.toString('hex'), execution_gas: result.execResult.executionGasUsed.toString()}; rows.push(row);
    if (diagnostic) { assert.equal(row.exception, 'revert', name); assert.equal(row.return_hex, selector(diagnostic + '()').toString('hex'), name); }
    else { assert.equal(row.exception, null, name); assert.equal(bytes.length, 32); assert.equal(bytes.subarray(0, 4).toString('hex'), input.subarray(0, 4).toString('hex'), name); assert(bytes.subarray(4).equals(Buffer.alloc(28))); }
  }
  for (const [name, values] of Object.entries(normal)) await observe(name, call(functions, name, values));
  const maximalKey = {name: 'k'.repeat(32), alg: 'a'.repeat(24), key: Buffer.alloc(65, 1), signer: 's'.repeat(189), proof: Buffer.alloc(65, 2), hasExpiry: true, expires: (1n << 64n) - 1n};
  const maximalService = {name: 's'.repeat(32), serviceType: 't'.repeat(64), uri: 'u'.repeat(2048)};
  const maximum = call(functions, 'revealClaim', ['a'.repeat(64), controller, Array(128).fill(maximalKey), Array(16).fill(maximalService), Buffer.alloc(32)]);
  assert.equal(maximum.length, binding.limits.whole_calldata_bytes);
  await observe('maximum lengths: framing only', maximum);
  await observe('empty arrays: framing only', call(functions, 'revealClaim', ['', controller, [], [], Buffer.alloc(32)]));
  for (const input of [Buffer.alloc(0), Buffer.from('00', 'hex'), Buffer.from('ffffffff', 'hex'), Buffer.from('ffffffff00', 'hex')]) await observe('fixed incomplete or unknown call:' + input.toString('hex'), input, 'MalformedCall');
  await observe('whole input bound', Buffer.alloc(148805), 'BoundsExceeded');
  await observe('fixed method trailing byte', Buffer.concat([call(functions, 'registryId', []), Buffer.from([0])]), 'BoundsExceeded');
  await observe('truncated fixed argument', call(functions, 'commitClaim', [Buffer.alloc(32)]).subarray(0, 35), 'MalformedCall');
  await observe('field bound', call(functions, 'addKey', ['unit', 1n, {...entry, alg: 'a'.repeat(25)}]), 'BoundsExceeded');
  await observe('missing bounded tail', call(functions, 'record', ['a']).subarray(0, 68), 'MalformedCall');
  await observe('dynamic trailing byte', Buffer.concat([call(functions, 'record', ['a']), Buffer.from([0])]), 'MalformedCall');
  for (const fixture of read('fixed-refusals.json').cases) {
    assert(/^(?:[0-9a-f]{2})+$/.test(fixture.input_hex));
    await observe(fixture.name, Buffer.from(fixture.input_hex, 'hex'), fixture.diagnostic);
  }
  const emptyKey = {name: '', alg: '', key: Buffer.alloc(0), signer: '', proof: Buffer.alloc(0), hasExpiry: false, expires: 0n};
  const emptyService = {name: '', serviceType: '', uri: ''};
  await observe('key count bound', call(functions, 'revealClaim', ['', controller, Array(129).fill(emptyKey), [], Buffer.alloc(32)]), 'BoundsExceeded');
  await observe('service count bound', call(functions, 'updateServices', ['', 1n, Array(17).fill(emptyService)]), 'BoundsExceeded');
  await observe('URI field bound', call(functions, 'updateServices', ['unit', 1n, [{...service, uri: 'u'.repeat(2049)}]]), 'BoundsExceeded');
  await observe('key name field bound', call(functions, 'addKey', ['unit', 1n, {...entry, name: 'n'.repeat(33)}]), 'BoundsExceeded');
  await observe('proof field bound', call(functions, 'addKey', ['unit', 1n, {...entry, proof: Buffer.alloc(66)}]), 'BoundsExceeded');
  await observe('agent field bound', call(functions, 'addKey', ['a'.repeat(65), 1n, entry]), 'BoundsExceeded');
  const coverage = mappedCoverage(coverageOutput, visited);
  coverage.build = 'Minimal-optimization viaIR source-map control; every fixed outcome compared with production-settings build';
  write(target + '-calls.json', rows); write(target + '-coverage.json', coverage);
  assert(coverage.percent >= 90, JSON.stringify({total: coverage.total, covered: coverage.covered, percent: coverage.percent}));
  write(target + '-result.json', {scope: 'Interface/framing component units and isolated calls only; no Registry execution/conformance', target,
    methods: functions.length, errors: outcomes.filter(item => item.type === 'error').length, events: outcomes.filter(item => item.type === 'event').length,
    calls: rows.length, source_map_coverage_percent: coverage.percent, test_harness_code_bytes: code.length, deployment: 'NOT_RUN', new_runtime_conformance_verdicts: 0});
});
