// Fixed defensive and ordinary owned verifier controls, no network or chain writes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {createVM} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createAddressFromString} from '@ethereumjs/util';
const root = new URL('./', import.meta.url);
const read = name => fs.readFileSync(new URL(name, root));
const write = (name, value) => fs.writeFileSync(new URL('evidence/' + name, root), JSON.stringify(value, null, 2) + '\n');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const compilerPath = new URL('../../evidence/soljson.cjs', root);
assert.equal(sha(fs.readFileSync(compilerPath)), '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
const sol = createRequire(import.meta.url)(compilerPath.pathname);
assert.equal(sol.cwrap('solidity_version', 'string', [])(), '0.8.20+commit.a1b79de6.Emscripten.clang');
const names = ['RegistryEd25519.sol', 'VerifierControls.sol', 'RegistrySha512.sol', 'RegistryHashBytes.sol', 'IChainRegistry.sol', 'vendor/Sha2Ext.sol'];
const frameKey = 'ethereum/contracts/chain-registry/RegistryEd25519.sol';
const sourceKey = name => name === 'VerifierControls.sol' ? name : 'ethereum/contracts/chain-registry/' + name;
const sources = Object.fromEntries(names.map(name => [sourceKey(name), {content: fs.readFileSync(name === 'VerifierControls.sol' ? new URL(name, root) : new URL('../../../../contracts/chain-registry/' + name, root), 'utf8')}]));
const fixed = JSON.parse(read('frozen-research-cases.json')).cases;
const ordinary = JSON.parse(read('owned-cases.json')).cases;
const cases = [...fixed, ...ordinary];
assert.equal(cases.length, 48);
assert.equal(new Set(cases.map(value => value.name)).size, cases.length);
const word = value => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
const binary = value => Buffer.from(value, 'hex');
const expectedBoolean = value => word(value ? 1 : 0);
function calldata(selector, args) {
  let offset = 32 * args.length;
  const heads = [], tails = [];
  for (const argument of args) {
    heads.push(word(offset));
    const tail = Buffer.concat([word(argument.length), argument, Buffer.alloc((32 - argument.length % 32) % 32)]);
    tails.push(tail); offset += tail.length;
  }
  return Buffer.concat([binary(selector), ...heads, ...tails]);
}
function compile(target, control) {
  const input = {language: 'Solidity', sources, settings: {viaIR: false, optimizer: {enabled: true, runs: 200,
    details: {yul: true, yulDetails: {stackAllocation: true, optimizerSteps: control ? 'u:' : 'dhfoDgvulfnTUtnIf'},
      ...(control ? {peephole: false, inliner: false, jumpdestRemover: false, orderLiterals: false, deduplicate: false, cse: false, constantOptimizer: false} : {})}},
    evmVersion: target, metadata: {bytecodeHash: 'ipfs', appendCBOR: true}, outputSelection: {'*': {'*': ['abi', 'evm.deployedBytecode', 'evm.methodIdentifiers'], '': ['ast']}}}};
  const output = JSON.parse(sol.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(JSON.stringify(input), 0, 0));
  const prefix = target + (control ? '-control' : '');
  write(prefix + '-input.json', input); write(prefix + '-output.json', output);
  assert(!(output.errors ?? []).some(value => value.severity === 'error'), JSON.stringify(output.errors));
  for (const name of ['RegistryEd25519', 'ArithmeticControls', 'MissingBackendControl', 'InvalidBackendControl']) {
    const artifact = output.contracts[name === 'RegistryEd25519' ? frameKey : 'VerifierControls.sol'][name];
    assert(/^(?:[0-9a-f]{2})+$/.test(artifact.evm.deployedBytecode.object));
    assert(artifact.evm.deployedBytecode.object.length / 2 <= 24576, 'EIP170 runtime bound: ' + name);
  }
  return output;
}
function coverage(output, visited) {
  const source = output.sources[frameKey], statements = [], hits = [];
  const walk = node => {
    if (!node || typeof node !== 'object') return;
    if (['ExpressionStatement', 'VariableDeclarationStatement', 'IfStatement', 'ForStatement', 'WhileStatement', 'Return', 'RevertStatement', 'InlineAssembly'].includes(node.nodeType)) {
      const [start, length, file] = node.src.split(':').map(Number); statements.push({id: node.id, type: node.nodeType, start, length, file});
    }
    for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(walk); else if (value && typeof value === 'object') walk(value);
  };
  walk(source.ast);
  for (const [name, pcs] of Object.entries(visited)) {
    const object = output.contracts[name === 'RegistryEd25519' ? frameKey : 'VerifierControls.sol'][name].evm.deployedBytecode;
    const code = binary(object.object); let pc = 0, previous = ['0', '0', '-1', '', ''];
    for (const item of object.sourceMap.split(';')) {
      const row = item.split(':').map((value, index) => value === '' ? previous[index] : value);
      while (row.length < previous.length) row.push(previous[row.length]);
      if (pcs.has(pc)) hits.push(row.slice(0, 3).map(Number));
      previous = row; const opcode = code[pc]; pc += 1 + (opcode >= 0x60 && opcode <= 0x7f ? opcode - 0x5f : 0);
    }
  }
  const covered = statements.filter(value => hits.some(([start, length, file]) => file === source.id && length > 0 && start >= value.start && start + length <= value.start + value.length));
  return {scope: 'Contained AST statement/source-map observations on fixed control builds only; not branch, proof or Registry coverage', statements,
    covered_statement_ids: covered.map(value => value.id).sort((a, b) => a - b),
    visited_pcs: Object.fromEntries(Object.entries(visited).map(([name, pcs]) => [name, [...pcs].sort((a, b) => a - b)])),
    total: statements.length, covered: covered.length, percent: 100 * covered.length / statements.length};
}
fs.mkdirSync(new URL('evidence/', root), {recursive: true});
for (const target of ['paris', 'shanghai']) test(target + ': candidate strict verifier composition', async () => {
  const builds = [compile(target, false), compile(target, true)];
  const vm = await createVM({common: new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai})});
  assert.equal(vm.evm.DEBUG, false); assert.equal(vm.evm.events.listenerCount('step'), 0);
  const caller = createAddressFromString('0x0000000000000000000000000000000000001000');
  const contractNames = ['RegistryEd25519', 'ArithmeticControls', 'MissingBackendControl', 'InvalidBackendControl'];
  const installed = new Map(), visited = Object.fromEntries(contractNames.map(name => [name, new Set()]));
  for (const [index, output] of builds.entries()) for (const [n, name] of contractNames.entries()) {
    const artifact = output.contracts[name === 'RegistryEd25519' ? frameKey : 'VerifierControls.sol'][name];
    const address = createAddressFromString('0x' + BigInt(0x3000 + index * 16 + n).toString(16).padStart(40, '0'));
    await vm.stateManager.putCode(address, binary(artifact.evm.deployedBytecode.object));
    installed.set(index + ':' + name, {address, artifact});
  }
  const rows = [];
  for (const entry of cases) {
    const method = entry.method ?? 'verify(bytes,bytes,bytes)';
    const args = entry.args ? entry.args.map(binary) : method === 'verify(bytes,bytes,bytes)' ? [entry.key, entry.message, entry.signature].map(binary) : [];
    const expected = Buffer.concat((entry.expectedWords ?? [entry.expected]).map(expectedBoolean));
    const observed = []; let data;
    for (const index of [0, 1]) {
      const {address, artifact} = installed.get(index + ':' + entry.contract);
      const input = calldata(artifact.evm.methodIdentifiers[method], args);
      if (data) assert.deepEqual(input, data); else data = input;
      const capture = (step, next) => { if (step.address.equals(address)) visited[entry.contract].add(step.pc); next?.(); };
      if (index === 1) vm.evm.events.on('step', capture);
      const gasLimit = index === 0 ? 15_000_000n : 100_000_000n;
      let result;
      try { result = await vm.evm.runCall({to: address, caller, data: input, gasLimit, isStatic: true}); }
      finally { if (index === 1) vm.evm.events.removeListener('step', capture); }
      assert.equal(vm.evm.events.listenerCount('step'), 0);
      const exception = result.execResult.exceptionError?.error ?? null;
      const returned = Buffer.from(result.execResult.returnValue);
      assert.equal(exception, null, entry.name); assert.deepEqual(returned, expected, entry.name);
      observed.push({build: index === 0 ? 'production' : 'source-control', gas_limit: gasLimit.toString(), runtime_sha256: sha(binary(artifact.evm.deployedBytecode.object)), exception, return_hex: returned.toString('hex'), gas: result.execResult.executionGasUsed.toString()});
    }
    rows.push({name: entry.name, contract: entry.contract, method, group: entry.group, input_hex: data.toString('hex'), input_sha256: sha(data), expected_hex: expected.toString('hex'), observed});
    write(target + '-rows.json', {scope: 'Candidate raw verifier controls only; no full Registry or operating Source', complete: rows.length === cases.length, rows});
    console.log(target + ': ' + entry.name);
  }
  const mapped = coverage(builds[1], visited); write(target + '-coverage.json', mapped);
  assert(mapped.percent >= 90, JSON.stringify({covered: mapped.covered, total: mapped.total, percent: mapped.percent}));
});
