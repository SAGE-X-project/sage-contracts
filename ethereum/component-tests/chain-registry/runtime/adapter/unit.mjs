// Fixed stateless product-module units only; no transaction/attack producer.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import test from 'node:test';
import {createVM} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {call} from '../normal-abi.mjs';

const root = new URL('./', import.meta.url), runtime = new URL('../', root), repo = new URL('../../../../../', root);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const load = url => JSON.parse(fs.readFileSync(url, 'utf8'));
assert.deepEqual(process.execArgv.filter(value => value.startsWith('--max-old-space-size')), ['--max-old-space-size=512']);
const manifestBytes = fs.readFileSync(new URL('source-identities.json', runtime));
const manifest = JSON.parse(manifestBytes);
assert.equal(manifest.scope, 'Bound Registry source and verification tools only; not operating qualification');
for (const group of ['source_files_sha256', 'tool_files_sha256']) for (const [path,digest] of Object.entries(manifest[group])) {
  assert(!path.startsWith('/') && !path.split('/').includes('..'));
  const url = new URL(path,repo);assert(fs.lstatSync(url).isFile() && !fs.lstatSync(url).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(url)),digest,path);
}
assert.equal(manifest.tool_files_sha256['ethereum/component-tests/chain-registry/runtime/adapter/unit.mjs'],sha(fs.readFileSync(new URL(import.meta.url))));
const checkBytes = fs.readFileSync(new URL('evidence/compiler-check.json',runtime)), check = JSON.parse(checkBytes);
assert.equal(check.verified,true);assert.equal(check.source_manifest_sha256,sha(manifestBytes));
const compiledRoot = new URL('evidence/compiler/',runtime);
assert.deepEqual(fs.readdirSync(compiledRoot).sort(),Object.keys(check.evidence_files_sha256).sort());
for(const [name,digest]of Object.entries(check.evidence_files_sha256)) {
  assert(!name.startsWith('/') && !name.split('/').includes('..'));assert.equal(sha(fs.readFileSync(new URL(name,compiledRoot))),digest);
}
const goldenPath = new URL('goldens.json',root);
const goldens = load(goldenPath);
const pcPolicy = {max_input_bytes: 1024, max_expected_output_bytes: 1024, max_steps: 2048, max_memory_bytes: 4096};

assert.equal(goldens.executed,false);assert.equal(goldens.cases.length,255);assert.equal(goldens.skipped.length,137);
assert.equal(new Set(goldens.cases.map(value=>value.name)).size,255);
for(const [path,digest]of Object.entries(goldens.fixtures_sha256)) assert.equal(sha(fs.readFileSync(new URL(path,repo))),digest);
const baselines=load(new URL('fixtures/expected-modules.json',runtime));
const evidence = new URL('evidence/adapter/', runtime);
assert(!fs.existsSync(evidence), 'Preserve prior unit evidence before any retry');
fs.mkdirSync(evidence);
const bin = value => { assert(/^(?:[0-9a-f]{2})*$/.test(value)); return Buffer.from(value, 'hex'); };
function hydrate(field, value) {
  if (field.type.endsWith('[]')) return value.map(child => hydrate({...field, type: field.type.slice(0, -2)}, child));
  if (field.type === 'tuple') return Object.fromEntries(field.components.map(child => [child.name, hydrate(child, value[child.name])]));
  if (field.type.startsWith('bytes')) { assert.deepEqual(Object.keys(value), ['$hex']); return bin(value.$hex); }
  return value;
}
for (const target of ['paris', 'shanghai']) test(target + ': fixed stateless adapter expectations', async () => {
  const compiled = load(new URL(target + '-output.json', compiledRoot));
  const vm = await createVM({common: new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai})});
  assert.equal(vm.evm.DEBUG, false);
  assert.equal(vm.evm.events.listenerCount('step'), 0);
  const visited = Object.fromEntries(['RegistryRules','RegistryRenderer'].map(name=>[name,new Set()]));
  const rowsPath = new URL(target + '-rows.jsonl', evidence);
  fs.writeFileSync(rowsPath, '', {flag: 'wx'});
  let count = 0;
  const traced = [], untraced = [];
  const artifacts = {};
  for (const contract of ['RegistryRules', 'RegistryRenderer']) {
    const artifact = compiled.contracts['ethereum/contracts/chain-registry/' + contract + '.sol'][contract];
    assert.deepEqual(artifact.evm.deployedBytecode.immutableReferences, {});
    assert.equal(sha(Buffer.from(artifact.evm.deployedBytecode.object,'hex')), baselines.targets[target][contract==='RegistryRules'?'RULES':'RENDERER'].runtime_sha256);
    artifacts[contract] = artifact;
  }
  for (const fixed of goldens.cases) {
    const artifact = artifacts[fixed.contract];
    const method = artifact.abi.find(value => value.type === 'function' && value.name === fixed.method);
    assert.deepEqual(method.inputs, fixed.input_types);
    assert.deepEqual(method.outputs, fixed.output_types);
    const input = call(artifact.abi, fixed.method, method.inputs.map((field, index) => hydrate(field, fixed.arguments[index])));
    const code = bin(artifact.evm.deployedBytecode.object);
    // Direct pure-code unit execution: no deployed Registry/caller identity claim.
    const pcEligible = input.length <= pcPolicy.max_input_bytes && bin(fixed.expected_return_hex).length <= pcPolicy.max_expected_output_bytes;
    let pcSteps = 0, pcMemory = 0, pcStop = pcEligible ? 'complete' : 'size';
    const capture=(step,next)=>{
      assert.equal(step.depth,0);visited[fixed.contract].add(step.pc);
      pcSteps++;pcMemory=Math.max(pcMemory,step.memory.length);
      // The upstream event has already copied this snapshot. Stop immediately
      // after the first oversized snapshot or step budget; never retain memory.
      if (pcMemory > pcPolicy.max_memory_bytes || pcSteps >= pcPolicy.max_steps) {
        pcStop = pcMemory > pcPolicy.max_memory_bytes ? 'memory' : 'steps';
        vm.evm.events.removeListener('step',capture);
      }
      next?.();
    };
    if (pcEligible) vm.evm.events.on('step',capture);
    let result;
    try {result=await vm.evm.runCode({code, data: input, gasLimit: 250_000_000n, isStatic: true});}
    finally {vm.evm.events.removeListener('step',capture);}
    const row = {index: count++, name: fixed.name, contract: fixed.contract, method: fixed.method,
      input_hex: input.toString('hex'), input_sha256: sha(input), runtime_sha256: sha(code),
      expected_exception: fixed.exception, exception: result.exceptionError?.error ?? null,
      expected_return_hex: fixed.expected_return_hex, return_hex: Buffer.from(result.returnValue).toString('hex'),
      execution_gas: result.executionGasUsed.toString(), gas_limit: '250000000', logs:result.logs ?? [],
      pc_trace: {eligible:pcEligible, steps:pcSteps, max_memory_bytes:pcMemory, stop:pcStop}};
    fs.appendFileSync(rowsPath, JSON.stringify(row) + '\n');
    assert.deepEqual(result.logs ?? [], []);
    assert.equal(row.exception, fixed.exception, fixed.name);
    assert.equal(row.return_hex, fixed.expected_return_hex, fixed.name);
    assert.equal(vm.evm.DEBUG, false);
    assert.equal(vm.evm.events.listenerCount('step'), 0);
    (pcEligible ? traced : untraced).push({index:row.index,name:row.name});
    fs.writeFileSync(new URL(target+'-pc-prefix.json',evidence),JSON.stringify({cases_completed:count,policy:pcPolicy,traced,untraced,visited:Object.fromEntries(Object.entries(visited).map(([name,pcs])=>[name,[...pcs].sort((a,b)=>a-b)]))})+'\n');
  }
  assert.equal(count, 255);
  const result = {scope: 'Fixed stateless product adapter UNIT observations only; no full Registry admission/runtime/coverage/Source verdict',
    complete: true, cases: count, source_manifest_sha256: sha(manifestBytes), compiler_check_sha256:sha(checkBytes), goldens_sha256: sha(fs.readFileSync(goldenPath)),
    rows_sha256: sha(fs.readFileSync(rowsPath)), pc_prefix_sha256:sha(fs.readFileSync(new URL(target+'-pc-prefix.json',evidence))), pc_policy:pcPolicy, runtime_sha256: Object.fromEntries(Object.entries(artifacts).map(([name, value]) => [name, sha(bin(value.evm.deployedBytecode.object))])),
    skipped_data_cases: 137, PC_observations_recorded: true, coverage_percent: null, fixed5_complete: false};
  fs.writeFileSync(new URL(target + '-result.json', evidence), JSON.stringify(result, null, 2) + '\n', {flag: 'wx'});
});
