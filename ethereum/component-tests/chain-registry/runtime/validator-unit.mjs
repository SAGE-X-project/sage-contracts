// Fixed defensive UNIT data on the deployed pure validator only. No Core
// requests, submission interface, network, forged proof or input mutator.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import test from 'node:test';
import {createVM, runTx} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createBlock} from '@ethereumjs/block';
import {createFeeMarket1559Tx} from '@ethereumjs/tx';
import {createAccount, createAddressFromPrivateKey, createContractAddress} from '@ethereumjs/util';
import {call, selector} from './normal-abi.mjs';
import {senderTestSeed} from './owned-fixtures.mjs';

const root = new URL('./', import.meta.url), repo = new URL('../../../../', root);
const sha = data => crypto.createHash('sha256').update(data).digest('hex');
const load = url => JSON.parse(fs.readFileSync(url, 'utf8'));
assert.deepEqual(process.execArgv.filter(x => x.startsWith('--max-old-space-size')), ['--max-old-space-size=512']);
const manifestBytes = fs.readFileSync(new URL('source-identities.json', root)), manifest = JSON.parse(manifestBytes);
for (const section of ['source_files_sha256', 'tool_files_sha256']) for (const [path, digest] of Object.entries(manifest[section])) {
  assert(!path.startsWith('/') && !path.split('/').includes('..'));
  const source = new URL(path, repo);
  assert(fs.lstatSync(source).isFile() && !fs.lstatSync(source).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(source)), digest, path);
}
assert.equal(manifest.tool_files_sha256['ethereum/component-tests/chain-registry/runtime/validator-unit.mjs'], sha(fs.readFileSync(new URL(import.meta.url))));
const compilerRoot = new URL('evidence/compiler/', root), check = load(new URL('evidence/compiler-check.json', root));
assert.equal(check.verified, true);
assert.equal(check.source_manifest_sha256, sha(manifestBytes));
assert.deepEqual(check.targets, ['paris', 'shanghai']);
for (const [path, digest] of Object.entries(check.evidence_files_sha256)) {
  assert(!path.startsWith('/') && !path.split('/').includes('..'));
  const file = new URL(path, compilerRoot);
  assert(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(file)), digest, path);
}
assert.deepEqual(fs.readdirSync(compilerRoot).sort(), Object.keys(check.evidence_files_sha256).sort());
const fixed = load(new URL('validator-cases.json', root));
assert.equal(sha(fs.readFileSync(new URL('../fixtures/fixed-refusals.json', root))), fixed.framing_fixture_sha256);
const framingFixtures = load(new URL('../fixtures/fixed-refusals.json', root));
assert.equal(fixed.literal_refusals.length, framingFixtures.cases.length);
const evidence = new URL('evidence/validator/', root);
assert(!fs.existsSync(evidence), 'Preserve earlier evidence before another attempt');
fs.mkdirSync(evidence);
const write = (name, data) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(data, null, 2) + '\n', {flag: name.endsWith('-partial.json') ? 'w' : 'wx'});
const entry = {name:'signing', alg:'ed25519', key:Buffer.alloc(32, 1), signer:'did:sage:unit#signing', proof:Buffer.alloc(64, 2), hasExpiry:false, expires:0n};
const service = {name:'rpc', serviceType:'A2A', uri:'https://example.invalid/agent'};
const controller = '0x0000000000000000000000000000000000000001';
const normal = {
  commitClaim:[Buffer.alloc(32, 3)], revealClaim:['unit',controller,[entry],[service],Buffer.alloc(32, 4)],
  activate:['unit',1n], deactivate:['unit',1n], addKey:['unit',1n,entry], revokeKey:['unit',1n,'signing'],
  updateServices:['unit',1n,[service]], authorizeOperator:['unit',1n,controller,'update-services'],
  revokeOperator:['unit',1n,controller,'update-services'], registryId:[], record:['unit'], activeGrants:['unit'], historyItem:['unit',1n]
};
for (const target of ['paris', 'shanghai']) test(target + ': fixed pure validator units', async () => {
  const output = load(new URL(target + '-output.json', compilerRoot));
  const artifact = output.contracts['ethereum/contracts/chain-registry/RegistryCallValidator.sol'].RegistryCallValidator;
  const code = Buffer.from(artifact.evm.deployedBytecode.object, 'hex');
  assert(code.length > 0 && code.length <= 24576);
  const common = new Common({chain:Mainnet, hardfork:target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai});
  const vm = await createVM({common});
  assert.equal(vm.evm.DEBUG, false); assert.equal(vm.evm.events.listenerCount('step'), 0);
  const caller = createAddressFromPrivateKey(senderTestSeed(0));
  await vm.stateManager.putAccount(caller, createAccount({balance:10n ** 30n}));
  const address = createContractAddress(caller, 0n);
  const tx = createFeeMarket1559Tx({chainId:1n, nonce:0n, data:Buffer.from(artifact.evm.bytecode.object,'hex'), gasLimit:30_000_000n, maxFeePerGas:2n, maxPriorityFeePerGas:1n, value:0n, accessList:[]},{common}).sign(senderTestSeed(0));
  const block = createBlock({header:{number:1n,timestamp:10001n,gasLimit:30_000_000n,baseFeePerGas:1n}},{common});
  const creation = await runTx(vm,{tx,block});
  write(target + '-creation.json',{exception:creation.execResult.exceptionError?.error ?? null,address:creation.createdAddress?.toString() ?? null,return_hex:Buffer.from(creation.execResult.returnValue).toString('hex'),transaction_hash:Buffer.from(tx.hash()).toString('hex'),total_gas:creation.totalGasSpent.toString()});
  assert.equal(creation.execResult.exceptionError, undefined);
  assert.equal(creation.createdAddress.toString(), address.toString());
  assert.equal(Buffer.from(await vm.stateManager.getCode(address)).toString('hex'), code.toString('hex'));
  const rows = [];
  async function observe(label, input, expected) {
    // A direct isolated pure UNIT call, never signed/submitted as a Core request.
    const result = await vm.evm.runCall({to:address,caller,data:input,gasLimit:30_000_000n});
    const row = {index:rows.length,label,input_hex:input.toString('hex'),input_sha256:sha(input),expected,
      exception:result.execResult.exceptionError?.error ?? null,return_hex:Buffer.from(result.execResult.returnValue).toString('hex'),
      logs:(result.execResult.logs ?? []).map(([a,t,b])=>({address:Buffer.from(a).toString('hex'),topics:t.map(x=>Buffer.from(x).toString('hex')),data:Buffer.from(b).toString('hex')})),execution_gas:result.execResult.executionGasUsed.toString()};
    rows.push(row); write(target + '-partial.json',{complete:false,rows});
    assert.equal(row.exception,expected === 'success' ? null : 'revert',label);
    assert.equal(row.return_hex,expected === 'success' || expected === 'native-empty' ? '' : selector(expected + '()').toString('hex'),label);
    assert.deepEqual(row.logs,[],label);
    assert.equal(vm.evm.DEBUG,false); assert.equal(vm.evm.events.listenerCount('step'),0);
  }
  for (const [name, values] of Object.entries(normal)) await observe('canonical:' + name,call(artifact.abi,name,values),'success');
  for (const [index, expected] of fixed.literal_refusals.entries()) {
    const item = framingFixtures.cases[index];assert.equal(item.name,expected.name);
    assert(/^(?:[a-f0-9]{2})+$/.test(item.input_hex));
    await observe('literal:' + item.name,Buffer.from(item.input_hex,'hex'),expected.validator_outcome);
  }
  assert.equal(rows.length,fixed.expected_calls_per_fork);
  write(target + '-calls.json',{complete:true,scope:fixed.scope,rows,code_sha256:sha(code),code_hex:code.toString('hex'),validator_address:address.toString(),source_manifest_sha256:sha(manifestBytes),product_PC_observation:false,operating_ready:false});
});
