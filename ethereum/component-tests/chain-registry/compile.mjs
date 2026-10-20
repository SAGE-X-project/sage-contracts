import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';

export const directory = new URL('./', import.meta.url);
export const project = new URL('../../../', directory);
export const evidence = new URL('evidence/', directory);
export const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const write = (name, value) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(value, null, 2) + '\n');
const compilerDigest = '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657';

export function compile(target, coverage = false) {
  assert(['paris', 'shanghai'].includes(target));
  fs.mkdirSync(evidence, {recursive: true});
  const compiler = new URL('evidence/soljson.cjs', directory);
  assert.equal(sha(fs.readFileSync(compiler)), compilerDigest);
  const sol = createRequire(import.meta.url)(compiler.pathname);
  const version = sol.cwrap('solidity_version', 'string', [])();
  assert.equal(version, '0.8.20+commit.a1b79de6.Emscripten.clang');
  const names = ['ethereum/contracts/chain-registry/IChainRegistry.sol',
    'ethereum/contracts/chain-registry/RegistryFraming.sol',
    'ethereum/component-tests/chain-registry/FramingHarness.sol'];
  const sources = Object.fromEntries(names.map(name => [name, {content: fs.readFileSync(new URL(name, project), 'utf8')}]));
  const input = {language: 'Solidity', sources, settings: {
    optimizer: coverage ? {enabled: true, runs: 200, details: {peephole: false, inliner: false, jumpdestRemover: false, orderLiterals: false, deduplicate: false, cse: false, constantOptimizer: false, yul: true, yulDetails: {stackAllocation: true, optimizerSteps: 'u:'}}} : {enabled: true, runs: 200}, viaIR: true, evmVersion: target,
    metadata: {bytecodeHash: 'ipfs', appendCBOR: true},
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers'], '': ['ast']}}
  }};
  const output = JSON.parse(sol.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(JSON.stringify(input), 0, 0));
  const label = target + (coverage ? '-coverage-control' : '');
  write(label + '-input.json', input);
  write(label + '-output.json', output);
  assert.equal((output.errors ?? []).filter(error => error.severity === 'error').length, 0, JSON.stringify(output.errors));
  const harness = output.contracts['ethereum/component-tests/chain-registry/FramingHarness.sol'].FramingHarness;
  assert(/^(?:[0-9a-f]{2})+$/.test(harness.evm.deployedBytecode.object), 'Refuse unresolved library placeholders before any VM call');
  write(label + '-compiler.json', {scope: 'Interface and framing components only; no Registry deployment or conformance',
    node: process.version, compiler: version, compiler_sha256: compilerDigest, target,
    optimizer_settings: input.settings.optimizer, coverage_control: coverage,
    input_sha256: sha(JSON.stringify(input)), output_sha256: sha(JSON.stringify(output)),
    source_sha256: Object.fromEntries(Object.entries(sources).map(([name, item]) => [name, sha(item.content)]))});
  return {target, output};
}
