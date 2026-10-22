// Candidate ordinary constructor integration; isolated VM/public test seeds only.
// No live RPC, real funds, attack producer, hostile callback or code injection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import test from 'node:test';
import {createVM, runTx} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createBlock} from '@ethereumjs/block';
import {createFeeMarket1559Tx} from '@ethereumjs/tx';
import {createAddressFromPrivateKey, createContractAddress, createAccount} from '@ethereumjs/util';
import {keccak_256} from '@noble/hashes/sha3.js';
import {call, word, sequence} from './normal-abi.mjs';
import {senderTestSeed, initialFixture, ownedKey, publicKey, publicServices, jcs} from './owned-fixtures.mjs';
import {assertStoreLayout, observeClaim, observeRecord} from './observe.mjs';
import {messageObserver,captureObservedRequest} from './message-observer.mjs';

const root = new URL('./', import.meta.url), repo = new URL('../../../../', root), prefix = 'ethereum/contracts/chain-registry/';
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
assert.deepEqual(process.execArgv.filter(value => value.startsWith('--max-old-space-size')), ['--max-old-space-size=512']);
const load = url => JSON.parse(fs.readFileSync(url, 'utf8'));
const manifestBytes = fs.readFileSync(new URL('source-identities.json', root));
const manifest = JSON.parse(manifestBytes);
assert.equal(manifest.scope, 'Bound Registry source and verification tools only; not operating qualification');
for (const section of ['source_files_sha256', 'tool_files_sha256']) for (const [path, digest] of Object.entries(manifest[section])) {
  assert(!path.startsWith('/') && !path.split('/').includes('..'));
  const url = new URL(path, repo);
  assert(fs.lstatSync(url).isFile() && !fs.lstatSync(url).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(url)), digest, path);
}
const proofManifest=load(new URL('proof-order-identities.json',root));
assert.equal(proofManifest.scope,'Fixed owned proof-order source only; separate from compiler provenance');
assert.deepEqual(proofManifest.product_source_sha256,manifest.source_files_sha256);
assert.deepEqual(Object.keys(proofManifest.tools_sha256).sort(),['message-observer-unit.mjs','message-observer.mjs','proof-order-unit.mjs'].map(value=>'ethereum/component-tests/chain-registry/runtime/'+value).sort());
for(const[path,digest]of Object.entries(proofManifest.tools_sha256)){
  assert(!path.startsWith('/')&&!path.split('/').includes('..'));
  const p=new URL(path,repo);assert(fs.lstatSync(p).isFile()&&!fs.lstatSync(p).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(p)),digest,path);
}
assert.equal(proofManifest.tools_sha256['ethereum/component-tests/chain-registry/runtime/proof-order-unit.mjs'],sha(fs.readFileSync(new URL(import.meta.url))));
const productCompile=proofManifest.fresh_compiler_product_pins;
assert.equal(productCompile.mode,'CURRENT_MANIFEST_FRESH_COMPILE_EXACT_PRODUCT_INPUT_OUTPUT');
assert.deepEqual(Object.keys(productCompile.files_sha256).sort(),
  ['paris-input.json','paris-output.json','shanghai-input.json','shanghai-output.json'].sort());
for(const[path,digest]of Object.entries(productCompile.files_sha256)){
  const p=new URL('evidence/compiler/'+path,root);
  assert(fs.lstatSync(p).isFile()&&!fs.lstatSync(p).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(p)),digest,path);
}
const compileRoot = new URL('evidence/compiler/', root);
const compilerCheckBytes = fs.readFileSync(new URL('evidence/compiler-check.json', root));
const compilerCheck = JSON.parse(compilerCheckBytes);
assert.equal(compilerCheck.verified, true);
assert.equal(compilerCheck.source_manifest_sha256, sha(manifestBytes));
assert.deepEqual(compilerCheck.targets, ['paris', 'shanghai']);
assert.equal(compilerCheck.bound_role_digest_joins, 16);
for (const [path, digest] of Object.entries(compilerCheck.evidence_files_sha256)) {
  assert(!path.startsWith('/') && !path.split('/').includes('..'));
  const url = new URL(path, compileRoot);
  assert(fs.lstatSync(url).isFile() && !fs.lstatSync(url).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(url)), digest, path);
}
assert.deepEqual(fs.readdirSync(compileRoot).sort(), Object.keys(compilerCheck.evidence_files_sha256).sort());
const compilerPath = new URL('ethereum/component-tests/chain-registry/evidence/soljson.cjs', repo);
assert.equal(sha(fs.readFileSync(compilerPath)), '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
const evidence = new URL('evidence/proof-order/', root);
assert(!fs.existsSync(evidence), 'Preserve prior constructor evidence before rerunning');
fs.mkdirSync(evidence);
const write = (name, value) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(value, null, 2) + '\n', {flag: name.endsWith('-partial.json') ? 'w' : 'wx'});
const bin = hex => { assert(/^(?:[0-9a-f]{2})*$/.test(hex)); return Buffer.from(hex, 'hex'); };
const senders = [0, 1].map(index => createAddressFromPrivateKey(senderTestSeed(index)));
for (const target of ['paris', 'shanghai']) test(target + ': fixed owned signing-before-KEM message order', async () => {
  const compiled = load(new URL(target + '-output.json', compileRoot));
  const registryArtifact = compiled.contracts[prefix + 'ChainRegistry.sol'].ChainRegistry;
  const storageLayout = assertStoreLayout(compiled.contracts[prefix + 'RegistryStore.sol'].RegistryStore.storageLayout);
  const storageObservations = [];
  const common = new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai});
  const vm = await createVM({common});
  assert.equal(vm.evm.DEBUG, false);
  assert.equal(vm.evm.events.listenerCount('step'), 0);
  for (const sender of senders) await vm.stateManager.putAccount(sender, createAccount({balance: 10n ** 30n}));
  const rows = []; let height = 1n;
  const storageReadLog = new URL(target + '-storage-reads.jsonl', evidence);
  fs.writeFileSync(storageReadLog, '', {flag:'wx'});
  let storageReadIndex = 0;
  const onStorageRead = entry => fs.appendFileSync(storageReadLog, JSON.stringify({global_index:storageReadIndex++,after_transaction_index:rows.length-1,...entry}) + '\n');
  const observedClaim = (...args) => observeClaim(...args,onStorageRead);
  const observedRecord = (...args) => observeRecord(...args,onStorageRead);
  const transact = async (label, to, data, sender = 0, expectedException = null) => {
    const nonce = (await vm.stateManager.getAccount(senders[sender])).nonce;
    // Existing finite100M transaction ceiling, not an operating-chain selection.
    const tx = createFeeMarket1559Tx({chainId: 1n, nonce, ...(to ? {to} : {}), data, gasLimit: 100_000_000n,
      maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, value: 0n, accessList: []}, {common}).sign(senderTestSeed(sender));
    const number = height++, timestamp = 10000n + number;
    const block=createBlock({header:{number,timestamp,gasLimit:100_000_000n,baseFeePerGas:1n}},{common});
    const result = await runTx(vm, {tx, block});
    const row = {index: rows.length, label, sender: senders[sender].toString(), to: to?.toString() ?? null,
      block: number.toString(), timestamp: timestamp.toString(), transaction_hash: Buffer.from(tx.hash()).toString('hex'),
      calldata_hex: data.toString('hex'), calldata_sha256: sha(data), exception: result.execResult.exceptionError?.error ?? null,
      return_hex: Buffer.from(result.execResult.returnValue).toString('hex'), execution_gas: result.execResult.executionGasUsed.toString(), total_gas: result.totalGasSpent.toString(),
      created_address: result.createdAddress?.toString() ?? null,
      logs: (result.execResult.logs ?? []).map(([address, topics, bytes]) => ({address: Buffer.from(address).toString('hex'), topics: topics.map(value => Buffer.from(value).toString('hex')), data: Buffer.from(bytes).toString('hex')}))};
    rows.push(row); write(target + '-partial.json', {complete: false, rows});
    assert.equal(row.exception, expectedException, JSON.stringify(row));
    return row;
  };
  const codes = {}, moduleAddresses = {};
  const moduleNames = ['RegistryRenderer', 'RegistryEd25519', 'RegistryRules', 'RegistryCallValidator',
    'RegistryStoreFactory', 'RegistryClaimProcessorFactory', 'RegistryKeyServiceProcessorFactory', 'RegistryLifecycleProcessorFactory'];
  for (const [index, name] of moduleNames.entries()) {
    const artifact = compiled.contracts[prefix + name + '.sol'][name];
    const address = createContractAddress(senders[0], BigInt(index));
    const deployment = await transact('constructor:' + name, null, bin(artifact.evm.bytecode.object));
    assert.equal(deployment.created_address, address.toString());
    const code = Buffer.from(await vm.stateManager.getCode(address));
    assert.equal(code.toString('hex'), artifact.evm.deployedBytecode.object);
    moduleAddresses[name] = address;
    codes[name] = {address: address.toString(), code_hex: code.toString('hex'), code_sha256: sha(code), code_keccak256: Buffer.from(keccak_256(code)).toString('hex')};
  }
  const registry = createContractAddress(senders[0], 8n);
  const coreInit = Buffer.concat([bin(registryArtifact.evm.bytecode.object), sequence(Array.from({length: 8}, () => ({type: 'address'})), moduleNames.map(name => moduleAddresses[name].toString()))]);
  assert(coreInit.length <= 49152);
  const deployment = await transact('constructor:Registry', null, coreInit);
  assert.equal(deployment.created_address, registry.toString());
  const renderer = moduleAddresses.RegistryRenderer, verifier = moduleAddresses.RegistryEd25519;
  const rules = moduleAddresses.RegistryRules, callValidator = moduleAddresses.RegistryCallValidator;
  const childNames = ['RegistryStore', 'RegistryClaimProcessor', 'RegistryKeyServiceProcessor', 'RegistryLifecycleProcessor'];
  const children = Object.fromEntries(childNames.map((name, index) => [name, createContractAddress(moduleAddresses[moduleNames[4 + index]], 1n)]));
  const walk = (value, visitor) => { if (Array.isArray(value)) value.forEach(item => walk(item, visitor)); else if (value && typeof value === 'object') {
    visitor(value); Object.values(value).forEach(item => walk(item, visitor));
  }};
  const actualRuntime = async (name, address, bindings, inherited = []) => {
    const artifact = compiled.contracts[prefix + name + '.sol'][name], declarations = [];
    for (const file of [name, ...inherited]) walk(compiled.sources[prefix + file + '.sol'].ast, node => {
      if (node.nodeType === 'VariableDeclaration' && node.mutability === 'immutable') declarations.push(node);
    });
    assert.deepEqual(declarations.map(node => node.name).sort(), Object.keys(bindings).sort());
    assert.deepEqual(declarations.map(node => String(node.id)).sort(), Object.keys(artifact.evm.deployedBytecode.immutableReferences).sort());
    const expected = bin(artifact.evm.deployedBytecode.object);
    for (const declaration of declarations) for (const span of artifact.evm.deployedBytecode.immutableReferences[String(declaration.id)]) {
      assert.equal(span.length, 32); assert(span.start >= 0 && span.start + 32 <= expected.length);
      bindings[declaration.name].copy(expected, span.start);
    }
    const code = Buffer.from(await vm.stateManager.getCode(address)); assert.equal(code.toString('hex'), expected.toString('hex'), name);
    return {address: address.toString(), code_hex: code.toString('hex'), code_sha256: sha(code), code_keccak256: Buffer.from(keccak_256(code)).toString('hex'),
      immutable_count: declarations.length, immutable_words: Object.fromEntries(Object.entries(bindings).map(([key, value]) => [key, value.toString('hex')]))};
  };
  const addressWord = address => word(BigInt(address.toString()));
  for (const name of childNames) {
    const bindings = {core: addressWord(registry), executionChain: word(1n), instance: addressWord(children[name])};
    if (name !== 'RegistryStore') Object.assign(bindings, {store: addressWord(children.RegistryStore), renderer: addressWord(renderer), verifier: addressWord(verifier), rules: addressWord(rules)});
    codes[name] = await actualRuntime(name, children[name], bindings, name === 'RegistryStore' ? [] : ['RegistryProcessor']);
  }
  const bindings = {executionChain: word(1n), instance: addressWord(registry), renderer: addressWord(renderer), verifier: addressWord(verifier), rules: addressWord(rules), validator: addressWord(callValidator),
    store: addressWord(children.RegistryStore), claimProcessor: addressWord(children.RegistryClaimProcessor), keyProcessor: addressWord(children.RegistryKeyServiceProcessor), lifecycleProcessor: addressWord(children.RegistryLifecycleProcessor),
    rendererHash: bin(codes.RegistryRenderer.code_keccak256), verifierHash: bin(codes.RegistryEd25519.code_keccak256), rulesHash: bin(codes.RegistryRules.code_keccak256), validatorHash: bin(codes.RegistryCallValidator.code_keccak256),
    storeHash: bin(codes.RegistryStore.code_keccak256), claimHash: bin(codes.RegistryClaimProcessor.code_keccak256), keyHash: bin(codes.RegistryKeyServiceProcessor.code_keccak256), lifecycleHash: bin(codes.RegistryLifecycleProcessor.code_keccak256)};
  codes.ChainRegistry = await actualRuntime('ChainRegistry', registry, bindings);
  for (const name of moduleNames.slice(4)) assert.equal((await vm.stateManager.getAccount(moduleAddresses[name])).nonce, 2n);
  const principal=senders[0].toString(),agent='owned-proof-order';
  const identity='eip155:1:'+registry.toString();
  const fixture=initialFixture(identity,agent,principal);
  assert.deepEqual(fixture.keys.map(value=>value.name),['a-kem','z-sign']);
  const observed=async(label,method,args)=>{
    const observer=messageObserver(vm.evm,verifier.toString());
    const {row,trace}=await captureObservedRequest(observer,label,
      ()=>transact(label,registry,call(registryArtifact.abi,method,args)),
      value=>write(target+'-'+label+'-messages.json',value));
    assert.equal(trace.frames[0].to,registry.toString());
    assert.equal(trace.frames[0].caller,principal);
    assert.equal(trace.frames[0].input_sha256,row.calldata_sha256);
    assert.equal(trace.frames[0].exception,null);
    assert(trace.frames.every(value=>value.completed));
    return {row,trace};
  };
  const commit=await observed('commit','commitClaim',[fixture.commitment]);
  assert.equal(commit.trace.frames.filter(value=>value.code_address===verifier.toString()).length,0);
  assert.equal(commit.row.return_hex,'');
  assert.deepEqual(commit.row.logs,[{address:registry.toString().slice(2),
    topics:[Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'),
      word(BigInt(principal)).toString('hex'),fixture.commitment.toString('hex')],data:word(BigInt(commit.row.block)).toString('hex')}]);
  storageObservations.push(await observedRecord(vm,children.RegistryStore,identity,agent,null));
  storageObservations.push(await observedClaim(vm,children.RegistryStore,principal,fixture.commitment,
    {present:true,consumed:false,committed:BigInt(commit.row.block)}));
  const expectedAdmitted=10000n+height;
  const revealed=await observed('reveal','revealClaim',[agent,principal,fixture.keys,fixture.services,fixture.salt]);
  assert.equal(BigInt(revealed.row.timestamp),expectedAdmitted);
  const proofs=revealed.trace.frames.filter(value=>value.code_address===verifier.toString());
  assert.equal(proofs.length,2);
  const verifyABI=compiled.contracts[prefix+'RegistryEd25519.sol'].RegistryEd25519.abi;
  const expectedProofs=[1,0].map(index=>call(verifyABI,'verify',
    [fixture.keys[1].key,fixture.challenges[index],fixture.keys[index].proof]));
  for(let index=0;index<2;++index){
    const frame=proofs[index],expected=expectedProofs[index];
    assert.equal(frame.to,verifier.toString());assert.equal(frame.caller,children.RegistryClaimProcessor.toString());
    assert.equal(frame.depth,2);assert.equal(frame.is_static,true);assert.equal(frame.delegatecall,false);
    assert.equal(frame.input_bytes,expected.length);assert.equal(frame.input_sha256,sha(expected));
    assert.equal(frame.verifier_input_hex,expected.toString('hex'));
    assert.equal(frame.verifier_return_hex,word(1n).toString('hex'));assert.equal(frame.return_bytes,32);
    assert.equal(frame.exception,null);
  }
  assert.equal(proofs[0].parent,proofs[1].parent);
  assert(proofs[0].after_event<proofs[1].before_event);
  const recordSelector=compiled.contracts[prefix+'RegistryRenderer.sol'].RegistryRenderer.evm.methodIdentifiers[
    Object.keys(compiled.contracts[prefix+'RegistryRenderer.sol'].RegistryRenderer.evm.methodIdentifiers).find(value=>value.startsWith('record('))];
  const headroomSelector=compiled.contracts[prefix+'RegistryRenderer.sol'].RegistryRenderer.evm.methodIdentifiers[
    Object.keys(compiled.contracts[prefix+'RegistryRenderer.sol'].RegistryRenderer.evm.methodIdentifiers).find(value=>value.startsWith('checkHeadroom('))];
  const renderFrames=revealed.trace.frames.filter(value=>value.code_address===renderer.toString());
  const beforeRecord=renderFrames.find(value=>value.selector_hex===recordSelector);
  const headroom=renderFrames.filter(value=>value.selector_hex===headroomSelector);
  assert(beforeRecord&&headroom.length===1);
  assert.equal(headroom[0].return_bytes,0);
  for(const frame of [beforeRecord,headroom[0]]){
    assert.equal(frame.caller,children.RegistryClaimProcessor.toString());assert.equal(frame.exception,null);
    assert.equal(frame.parent,proofs[0].parent);assert.equal(frame.depth,2);
    assert.equal(frame.is_static,true);assert.equal(frame.delegatecall,false);
    assert(frame.after_event<proofs[0].before_event);
  }
  const storeArtifact=compiled.contracts[prefix+'RegistryStore.sol'].RegistryStore;
  const applySelector=storeArtifact.evm.methodIdentifiers[
    Object.keys(storeArtifact.evm.methodIdentifiers).find(value=>value.startsWith('commit('))];
  const applications=revealed.trace.frames.filter(value=>value.code_address===children.RegistryStore.toString()&&value.selector_hex===applySelector);
  assert.equal(applications.length,1);const apply=applications[0];
  assert.equal(apply.caller,registry.toString());assert.equal(apply.is_static,false);
  assert.equal(apply.delegatecall,false);assert.equal(apply.exception,null);
  assert(proofs[1].after_event<apply.before_event);
  const recordBytes=Buffer.from(jcs(fixture.record)),grantsBytes=Buffer.from('[]');
  const command={actor:principal,arguments:{controller:principal,keys:fixture.record.keys,
    salt:fixture.salt.toString('base64url'),services:fixture.record.services},binding:'sage-registry-chain-0.11.0',
    did:fixture.record.id,expectedVersion:'',operation:'create',registry:identity};
  const commandBytes=Buffer.from(jcs(command));
  const b64=value=>crypto.createHash('sha256').update(value).digest('base64url');
  const history={actor:principal,admitted:Number(expectedAdmitted),automaticRemovals:[],
    commandDigest:b64(commandBytes),grantsDigest:b64(grantsBytes),operation:'create',previousVersion:'',
    recordDigest:b64(recordBytes),target:null,version:'1'};
  const historyBytes=Buffer.from(jcs(history));
  assert.equal(revealed.row.return_hex,word(1n).toString('hex'));
  const eventData=sequence([{type:'string'},{type:'uint64'},{type:'uint64'},{type:'string'},
    {type:'bytes32'},{type:'bytes32'},{type:'bytes32'},{type:'uint64'}],
    [fixture.record.id,0n,1n,'create',bin(sha(commandBytes)),bin(sha(recordBytes)),bin(sha(grantsBytes)),BigInt(history.admitted)]);
  assert.deepEqual(revealed.row.logs,[{address:registry.toString().slice(2),
    topics:[Buffer.from(keccak_256(Buffer.from('RecordChanged(bytes32,address,string,uint64,uint64,string,bytes32,bytes32,bytes32,uint64)'))).toString('hex'),
      sha(Buffer.from(fixture.record.id)),word(BigInt(principal)).toString('hex')],data:eventData.toString('hex')}]);
  storageObservations.push(await observedRecord(vm,children.RegistryStore,identity,agent,
    {record:recordBytes,grants:grantsBytes,admitted:BigInt(history.admitted),
      history:[{version:1n,history:historyBytes,command:commandBytes}]}));
  storageObservations.push(await observedClaim(vm,children.RegistryStore,principal,fixture.commitment,
    {present:true,consumed:true,committed:BigInt(commit.row.block)}));
  assert.equal(rows.length,11);
  assert.equal(commit.row.block,'10');assert.equal(revealed.row.block,'11');
  assert.equal(expectedAdmitted,10011n);
  write(target+'-scenario.json',{scope:'Fixed normal owned proof-order transaction only; no PC or operating verdict',
    complete:true,identity,agent,controller:principal,record:fixture.record,claim:fixture.claim,
    claim_jcs_hex:Buffer.from(jcs(fixture.claim)).toString('hex'),commitment_hex:fixture.commitment.toString('hex'),
    expected_verifier_inputs_hex:expectedProofs.map(value=>value.toString('hex')),
    record_hex:recordBytes.toString('hex'),grants_hex:grantsBytes.toString('hex'),
    command_hex:commandBytes.toString('hex'),history_hex:historyBytes.toString('hex'),
    modules:codes,storageLayout,storageObservations,rows,
    compiler_check_sha256:sha(compilerCheckBytes),source_manifest_sha256:sha(manifestBytes)});
});
