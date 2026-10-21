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
import {lateHeadroomMessageObserver,captureObservedRequest} from './late-headroom-message-observer.mjs';

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
// Fresh current complete-manifest compilation is required for CI.
// No accepted-local marker, alternate mode or compiler receipt rebinding exists.
// The side identity binds the fixed fixture and its separate observer tools.
const localIdentity=load(new URL('late-headroom-identities.json',root));
assert.equal(localIdentity.mode,'CURRENT_MANIFEST_FRESH_COMPILE_EXACT_PRODUCT_INPUT_OUTPUT');
assert.deepEqual(localIdentity.product_source_sha256,manifest.source_files_sha256);
assert.deepEqual(localIdentity.fresh_compiler_product_pins,productCompile);
for(const[name,digest]of Object.entries(localIdentity.extra_tool_files_sha256)){
  assert(!name.includes('/')&&!name.includes('..'));
  const path=new URL(name,root);assert(fs.lstatSync(path).isFile()&&!fs.lstatSync(path).isSymbolicLink());
  assert.equal(sha(fs.readFileSync(path)),digest,name);
}
assert.equal(localIdentity.extra_tool_files_sha256['late-headroom-unit.mjs'],sha(fs.readFileSync(new URL(import.meta.url))));
assert.deepEqual(Object.keys(localIdentity.extra_tool_files_sha256).sort(),['late-headroom-base-fixture.json','late-headroom-message-observer-unit.mjs','late-headroom-message-observer.mjs','late-headroom-unit.mjs']);
const evidence = new URL('evidence/late-headroom/', root);
assert(!fs.existsSync(evidence), 'Preserve prior constructor evidence before rerunning');
fs.mkdirSync(evidence);
const write = (name, value) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(value, null, 2) + '\n', {flag: name.endsWith('-partial.json') ? 'w' : 'wx'});
const bin = hex => { assert(/^(?:[0-9a-f]{2})*$/.test(hex)); return Buffer.from(hex, 'hex'); };
const senders = [0, 1].map(index => createAddressFromPrivateKey(senderTestSeed(index)));
for (const target of ['paris', 'shanghai']) test(target + ': fixed owned late-headroom refusal diagnostic', async () => {
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
    // Constructors retain100M. Only the two fixed diagnostic requests use1.5B.
    const diagnostic=label==='commit'||label==='reveal',gas=diagnostic?1_500_000_000n:100_000_000n;
    const tx = createFeeMarket1559Tx({chainId: 1n, nonce, ...(to ? {to} : {}), data, gasLimit: gas,
      maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, value: 0n, accessList: []}, {common}).sign(senderTestSeed(sender));
    const number = height++, timestamp = 10000n + number;
    const block=createBlock({header:{number,timestamp,gasLimit:gas,baseFeePerGas:1n}},{common});
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
  // One fixed owned fixture only; no external target, input parameter or sender.
  const base=load(new URL('late-headroom-base-fixture.json',root));
  const principal=senders[0].toString(),agent=base.agent_id;
  const identity='eip155:1:'+registry.toString();
  assert.equal(identity,base.registry);assert.equal(principal,base.controller);
  assert.equal(registry.toString(),base.predicted_core);
  assert.equal(agent.length,64);assert.equal(base.keys.length,128);assert.equal(base.services.length,16);
  const keys=base.keys.map(value=>({...value,key:bin(value.key_hex),proof:bin(value.proof_hex),expires:BigInt(value.expires)}));
  const services=structuredClone(base.services);
  assert.equal(Buffer.byteLength(services[5].uri),442);services[5].uri+='a';
  assert.equal(Buffer.byteLength(services[5].uri),443);
  assert.deepEqual(keys.map(value=>publicKey(value)),base.record.keys);
  const record={...structuredClone(base.record),services:publicServices(services)};
  const terminal={...structuredClone(record),state:'deactivated',version:'18446744073709551615'};
  assert.equal(Buffer.byteLength(jcs(base.record)),65513);
  assert.equal(Buffer.byteLength(jcs(base.projected_terminal)),65536);
  const recordBytes=Buffer.from(jcs(record)),terminalBytes=Buffer.from(jcs(terminal));
  assert.equal(recordBytes.length,65514);assert.equal(terminalBytes.length,65537);
  assert.equal(new Set(keys.map(value=>value.name)).size,128);
  assert.equal(new Set(keys.map(value=>value.key_hex)).size,128);
  assert.deepEqual(keys.map(value=>value.name),keys.map(value=>value.name).sort());
  assert.deepEqual(services.map(value=>value.name),services.map(value=>value.name).sort());
  const names=new Set(keys.map(value=>value.name));
  for(const service of services){
    assert(!names.has(service.name));assert(service.name.length<=32&&service.serviceType.length<=64);
    assert(service.uri.startsWith('https://')&&Buffer.byteLength(service.uri)<=2048);
    assert(/^[\x20-\x7e]*$/.test(service.uri));
  }
  const lengthPrefixed=value=>{const bytes=Buffer.from(value),length=Buffer.alloc(2);assert(bytes.length<=65535);length.writeUInt16BE(bytes.length);return Buffer.concat([length,bytes]);};
  for(const entry of keys){
    assert(/^[a-z0-9][a-z0-9._-]{0,31}$/.test(entry.name));
    assert.equal(entry.hasExpiry,false);assert.equal(entry.expires,0n);
    assert(['ed25519','x25519'].includes(entry.alg));
    const signerName=entry.signer.slice(record.id.length+1);
    assert.equal(entry.signer,record.id+'#'+signerName);
    const signer=keys.find(value=>value.name===signerName);
    assert(signer&&signer.alg==='ed25519'&&!signer.hasExpiry);
    const challenge=Buffer.concat([Buffer.from('sage-pop-0.11.0'),...[identity,agent,entry.name,entry.alg,entry.key].map(lengthPrefixed)]);
    assert(challenge.length<=292);
    const publicSigner=crypto.createPublicKey({key:Buffer.concat([bin('302a300506032b6570032100'),signer.key]),format:'der',type:'spki'});
    assert(crypto.verify(null,challenge,publicSigner,entry.proof));
  }
  const salt=bin(base.salt_hex),claim={...structuredClone(base.claim),services:publicServices(services)};
  assert.equal(claim.salt,salt.toString('base64url'));
  assert.deepEqual(claim.keys,record.keys);assert.equal(claim.agentId,agent);
  const claimBytes=Buffer.from(jcs(claim));
  const digestInput=Buffer.concat([Buffer.from('sage-claim-0.11.0'),Buffer.from([0]),claimBytes]);
  const commitment=bin(sha(digestInput));assert.notEqual(commitment.toString('hex'),base.commitment_hex);
  const observed=async(label,method,args,expectedException=null)=>{
    const observer=lateHeadroomMessageObserver(vm.evm,verifier.toString());
    let persisted;
    const {row,trace}=await captureObservedRequest(observer,label,
      ()=>transact(label,registry,call(registryArtifact.abi,method,args),0,expectedException),
      value=>{write(target+'-'+label+'-messages.json',value);persisted=value;});
    assert(trace.complete&&trace.failure===null);
    assert.deepEqual(persisted,{...trace,root_validation_passed:true,root_failure:null});
    assert.equal(trace.frames[0].to,registry.toString());assert.equal(trace.frames[0].caller,principal);
    assert.equal(trace.frames[0].input_sha256,row.calldata_sha256);
    assert.equal(trace.frames[0].exception,expectedException);assert(trace.frames.every(value=>value.completed));
    return {row,trace};
  };
  // Read-only fixed absent headers and the only prospective retained version.
  // Persist each raw slot before asserting; no state/code injection occurs.
  const absenceObservations=[];
  const absentHeaders=async(label)=>{
    const mask=(1n<<256n)-1n;
    const hashWord=bytes=>BigInt('0x'+Buffer.from(keccak_256(bytes)).toString('hex'));
    const recordSlot=hashWord(Buffer.concat([Buffer.from(agent),word(2n)]));
    const retained=hashWord(Buffer.concat([word(1n),word((recordSlot+10n)&mask)]));
    const slots=[...Array.from({length:11},(_,i)=>(recordSlot+BigInt(i))&mask),
      ...Array.from({length:3},(_,i)=>(retained+BigInt(i))&mask)];
    const reads=[];
    for(const[index,slot]of slots.entries()){
      const raw=Buffer.from(await vm.stateManager.getStorage(children.RegistryStore,word(slot)));
      assert(raw.length<=32);
      const normalized=Buffer.concat([Buffer.alloc(32-raw.length),raw]);
      const entry={observer:'late-headroom-absence',context:label,agent_id:agent,store:children.RegistryStore.toString(),
        read_index:index,slot_hex:word(slot).toString('hex'),value_hex:normalized.toString('hex')};
      reads.push(entry);onStorageRead(entry);
      assert.equal(normalized.toString('hex'),'00'.repeat(32));
    }
    absenceObservations.push({scope:'14 fixed record headers and prospective history version1 ONLY, not arbitrary slot enumeration',context:label,record_slot_hex:word(recordSlot).toString('hex'),reads});
  };
  const commit=await observed('commit','commitClaim',[commitment]);
  assert.equal(commit.trace.frames.length,3);assert.equal(commit.row.return_hex,'');
  assert.deepEqual(commit.row.logs,[{address:registry.toString().slice(2),
    topics:[Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'),
      word(BigInt(principal)).toString('hex'),commitment.toString('hex')],data:word(BigInt(commit.row.block)).toString('hex')}]);
  storageObservations.push(await observedRecord(vm,children.RegistryStore,identity,agent,null));
  storageObservations.push(await observedClaim(vm,children.RegistryStore,principal,commitment,
    {present:true,consumed:false,committed:BigInt(commit.row.block)}));
  await absentHeaders('after-commit');
  const admitted=10000n+height;
  const revealed=await observed('reveal','revealClaim',[agent,principal,keys,services,salt],'revert');
  assert.equal(BigInt(revealed.row.timestamp),admitted);assert.equal(admitted,10011n);
  const errorSelector=Buffer.from(keccak_256(Buffer.from('BoundsExceeded()'))).subarray(0,4).toString('hex');
  assert.equal(revealed.row.return_hex,errorSelector);assert.deepEqual(revealed.row.logs,[]);
  const getABI=name=>compiled.contracts[prefix+name+'.sol'][name].abi;
  const storedRecord={did:record.id,controller:principal,keys:keys.map(input=>({input,state:0})),services,state:0,version:1n};
  const frames=revealed.trace.frames,expected=[];
  const rawAdd=(address,data,parent,caller,exception=null)=>expected.push({address:address.toString(),data,parent,caller:caller.toString(),exception});
  const revealData=call(registryArtifact.abi,'revealClaim',[agent,principal,keys,services,salt]);
  rawAdd(registry,revealData,null,senders[0],'revert');
  rawAdd(callValidator,revealData,0,registry);
  rawAdd(children.RegistryClaimProcessor,call(getABI('RegistryClaimProcessor'),'prepare',[principal,revealData]),0,registry,'revert');
  rawAdd(rules,call(getABI('RegistryRules'),'name',[agent,true]),2,children.RegistryClaimProcessor);
  for(const key of keys)rawAdd(rules,call(getABI('RegistryRules'),'keyScalars',[key]),2,children.RegistryClaimProcessor);
  rawAdd(rules,call(getABI('RegistryRules'),'serviceScalars',[services]),2,children.RegistryClaimProcessor);
  rawAdd(children.RegistryStore,call(getABI('RegistryStore'),'snapshot',[agent]),2,children.RegistryClaimProcessor);
  rawAdd(renderer,call(getABI('RegistryRenderer'),'claim',[identity,agent,principal,keys,services,salt]),2,children.RegistryClaimProcessor);
  rawAdd('0x'+'0'.repeat(39)+'2',digestInput,2,children.RegistryClaimProcessor);
  rawAdd(children.RegistryStore,call(getABI('RegistryStore'),'claim',[principal,commitment]),2,children.RegistryClaimProcessor);
  rawAdd(rules,call(getABI('RegistryRules'),'createTargets',[storedRecord,admitted]),2,children.RegistryClaimProcessor);
  rawAdd(renderer,call(getABI('RegistryRenderer'),'record',[storedRecord]),2,children.RegistryClaimProcessor);
  rawAdd(renderer,call(getABI('RegistryRenderer'),'checkHeadroom',[storedRecord]),2,children.RegistryClaimProcessor,'revert');
  assert.equal(expected.length,140);assert.equal(frames.length,140);
  for(let index=0;index<140;++index){
    const frame=frames[index],want=expected[index];
    assert.equal(frame.sequence,index);assert.equal(frame.parent,want.parent);
    assert.equal(frame.code_address,want.address);assert.equal(frame.to,want.address);
    assert.equal(frame.caller,want.caller);assert.equal(frame.depth,index===0?0:index<=2?1:2);
    assert.equal(frame.is_static,index!==0);assert.equal(frame.delegatecall,false);
    assert.equal(frame.input_bytes,want.data.length);assert.equal(frame.input_sha256,sha(want.data));
    assert.equal(frame.selector_hex,want.data.subarray(0,4).toString('hex'));assert.equal(frame.exception,want.exception);
  }
  const events=frames.flatMap(value=>[value.before_event,value.after_event]).sort((a,b)=>a-b);
  assert.deepEqual(events,Array.from({length:280},(_,index)=>index));
  for(const frame of frames){
    assert(frame.before_event<frame.after_event);
    if(frame.parent!==null){assert(frames[frame.parent].before_event<frame.before_event);assert(frame.after_event<frames[frame.parent].after_event);}
  }
  assert.equal(frames[0].after_event,279);assert.equal(frames[2].after_event,278);
  assert.equal(frames[138].return_bytes,65600);assert.equal(frames[139].return_bytes,4);
  assert.equal(frames[139].before_event,276);assert.equal(frames[139].after_event,277);
  assert(frames[138].after_event<frames[139].before_event);
  assert.equal(frames.filter(value=>value.code_address===verifier.toString()).length,0);
  const methods=compiled.contracts[prefix+'RegistryStore.sol'].RegistryStore.evm.methodIdentifiers;
  const applySignature=Object.keys(methods).filter(value=>value.startsWith('commit('));
  assert.equal(applySignature.length,1);
  assert.equal(frames.filter(value=>value.code_address===children.RegistryStore.toString()&&value.selector_hex===methods[applySignature[0]]).length,0);
  storageObservations.push(await observedRecord(vm,children.RegistryStore,identity,agent,null));
  storageObservations.push(await observedClaim(vm,children.RegistryStore,principal,commitment,
    {present:true,consumed:false,committed:BigInt(commit.row.block)}));
  await absentHeaders('after-refused-reveal');
  assert.equal(rows.length,11);assert.equal(commit.row.block,'10');assert.equal(revealed.row.block,'11');
  write(target+'-scenario.json',{scope:'Fixed owned late-headroom refusal diagnostic ONLY, fresh current complete source manifest compiler; no operating/product90 verdict',complete:true,
    identity,agent,controller:principal,record,claim,record_hex:recordBytes.toString('hex'),projected_size:terminalBytes.length,
    claim_jcs_hex:claimBytes.toString('hex'),commitment_hex:commitment.toString('hex'),expected_error_hex:errorSelector,
    expected_frames:expected.map(value=>({...value,data:value.data.toString('hex')})),modules:codes,storageLayout,storageObservations,absenceObservations,rows,
    compiler_check_sha256:sha(compilerCheckBytes),source_manifest_sha256:sha(manifestBytes)});
});
