// Draft-only pure structural guard units. No authority, proof, Registry or transaction.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {createVM} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createAddressFromString} from '@ethereumjs/util';
import {call} from '../normal-abi.mjs';

const root = new URL('./', import.meta.url);
const write = (name, value) => fs.writeFileSync(new URL('evidence/' + name, root), JSON.stringify(value, null, 2) + '\n');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const frameKey = 'ethereum/contracts/chain-registry/RegistryEntries.sol';
const harnessKey = 'EntryHarness.sol';
const interfaceKey = 'ethereum/contracts/chain-registry/IChainRegistry.sol';
const compiler = new URL('../../evidence/soljson.cjs', root);
assert.equal(sha(fs.readFileSync(compiler)), '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
const sol = createRequire(import.meta.url)(compiler.pathname);
assert.equal(sol.cwrap('solidity_version', 'string', [])(), '0.8.20+commit.a1b79de6.Emscripten.clang');
fs.mkdirSync(new URL('evidence/', root), {recursive: true});
const sources = Object.fromEntries([
  [frameKey, new URL('../../../../contracts/chain-registry/RegistryEntries.sol', root)],
  ['ethereum/contracts/chain-registry/RegistryJson.sol', new URL('../../../../contracts/chain-registry/RegistryJson.sol', root)],
  ['ethereum/contracts/chain-registry/RegistryGrammar.sol', new URL('../../../../contracts/chain-registry/RegistryGrammar.sol', root)],
  ['ethereum/contracts/chain-registry/RegistryText.sol', new URL('../../../../contracts/chain-registry/RegistryText.sol', root)],
  ['ethereum/contracts/chain-registry/RegistryBuffer.sol', new URL('../../../../contracts/chain-registry/RegistryBuffer.sol', root)],
  [harnessKey, new URL('EntryHarness.sol', root)],
  [interfaceKey, new URL('../../../../contracts/chain-registry/IChainRegistry.sol', root)]
].map(([name, path]) => [name, {content: fs.readFileSync(path, 'utf8')}]));
const goldens = JSON.parse(fs.readFileSync(new URL('goldens.json', root))).cases;
function compile(target, control) {
  const input = {language: 'Solidity', sources, settings: {optimizer: control ? {enabled: true, runs: 200,
    details: {peephole: false, inliner: false, jumpdestRemover: false, orderLiterals: false, deduplicate: false, cse: false, constantOptimizer: false, yul: true, yulDetails: {stackAllocation: true, optimizerSteps: 'u:'}}} : {enabled: true, runs: 200},
    viaIR: true, evmVersion: target, metadata: {bytecodeHash: 'ipfs', appendCBOR: true},
    outputSelection: {'*': {'*': ['abi', 'evm.deployedBytecode'], '': ['ast']}}}};
  const output = JSON.parse(sol.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(JSON.stringify(input), 0, 0));
  const label = target + (control ? '-control' : '');
  write(label + '-input.json', input); write(label + '-output.json', output);
  assert(!(output.errors ?? []).some(error => error.severity === 'error'), JSON.stringify(output.errors));
  assert(/^(?:[0-9a-f]{2})+$/.test(output.contracts[harnessKey].EntryHarness.evm.deployedBytecode.object));
  return output;
}
const word = value => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
function mappedCoverage(output, visited) {
  const compiled = output.contracts[harnessKey].EntryHarness.evm.deployedBytecode;
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

for (const target of ['paris', 'shanghai']) test(target + ': draft structural guard fragments', async () => {
  const output = compile(target, false), control = compile(target, true);
  const artifact = output.contracts[harnessKey].EntryHarness;
  const vm = await createVM({common: new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai})});
  assert.equal(vm.evm.DEBUG, false, 'Excluded source tracing requires EVM DEBUG disabled');
  assert.equal(vm.evm.events.listenerCount('step'), 0, 'No preexisting step observer');
  const caller = createAddressFromString('0x0000000000000000000000000000000000001000');
  const addresses = ['0x0000000000000000000000000000000000003000', '0x0000000000000000000000000000000000004000'].map(createAddressFromString);
  for (const [index, compiled] of [output, control].entries()) await vm.stateManager.putCode(addresses[index], Buffer.from(compiled.contracts[harnessKey].EntryHarness.evm.deployedBytecode.object, 'hex'));
  const visited = new Set();
  const capture = (step, next) => { if (step.address.equals(addresses[1])) visited.add(step.pc); next?.(); };
  const sourceMapCases = [];
  // The VM step hook copies all memory. Observe source PCs on bounded small
  // control inputs only; all cases still compare complete outputs on BOTH builds.
  const rows = [];
  for (const entry of goldens) {
    const hydrate = value => Array.isArray(value) ? value.map(hydrate) : value && typeof value === 'object' ? ('$hex' in value ? Buffer.from(value.$hex, 'hex') : Object.fromEntries(Object.entries(value).map(([name, item]) => [name, hydrate(item)]))) : value;
    const input = call(artifact.abi, entry.method, hydrate(entry.arguments));
    const expected = Buffer.from(entry.expected_hex, 'hex');
    const resultBytes = entry.exception ? expected : Buffer.concat([word(32), word(expected.length), expected, Buffer.alloc((32 - expected.length % 32) % 32)]);
    const observed = [];
    const row = {method: entry.method, name: entry.name, input_sha256: sha(input), expected_hex: resultBytes.toString('hex'), observed, validated: false};
    rows.push(row);
    for (const address of addresses) {
      const traced = address.equals(addresses[1]) && input.length <= 8192;
      if (traced) { vm.evm.events.on('step', capture); sourceMapCases.push(entry.name); }
      const gasLimit = address.equals(addresses[1]) ? 500_000_000n : 250_000_000n;
      let result;
      try { result = await vm.evm.runCall({to: address, caller, data: input, gasLimit}); } finally { if (traced) vm.evm.events.removeListener('step', capture); }
      assert.equal(vm.evm.events.listenerCount('step'), 0, 'Observer cleanup before next call');
      const exception = result.execResult.exceptionError?.error ?? null;
      observed.push({source_map_observed: traced, gas_limit: gasLimit.toString(), exception, return_hex: Buffer.from(result.execResult.returnValue).toString('hex'), gas: result.execResult.executionGasUsed.toString()});
      write(target + '-rows.json', {scope: 'Standalone pure fixed structural controls; partial observed outcomes, not acceptance', complete: false, cases: rows.length, rows});
      assert.equal(exception, entry.exception, entry.name);
      assert.deepEqual(Buffer.from(result.execResult.returnValue), resultBytes, entry.name);
    }
    row.validated = true;
    console.log(target + ': ' + entry.name + ' both build outcomes checked');
  }
  const coverage = {...mappedCoverage(control, visited), source_map_case_names: sourceMapCases,
    observation_policy: 'Minimal-Yul control inputs at most8192 calldata bytes only; every case checks both full build outcomes'};
  write(target + '-coverage.json', coverage);
  assert(coverage.percent >= 90, JSON.stringify({covered: coverage.covered, total: coverage.total, percent: coverage.percent}));
  write(target + '-rows.json', {scope: 'Standalone fixed structural guard controls; not admission, proof, deployment or operating budget', complete: true, cases: rows.length, rows});
});
