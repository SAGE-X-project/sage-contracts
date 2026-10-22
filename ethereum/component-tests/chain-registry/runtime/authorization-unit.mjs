// Candidate ordinary constructor integration; isolated VM/public test seeds only.
// No live RPC, real funds, attack producer, hostile callback or code injection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
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
import {entryFixtures} from './entry-fixtures.mjs';

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
assert.equal(manifest.tool_files_sha256['ethereum/component-tests/chain-registry/runtime/authorization-unit.mjs'], sha(fs.readFileSync(new URL(import.meta.url))));
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
const compiler = createRequire(import.meta.url)(compilerPath.pathname);
assert.equal(compiler.cwrap('solidity_version', 'string', [])(), '0.8.20+commit.a1b79de6.Emscripten.clang');
const evidence = new URL('evidence/authorization/', root);
assert(!fs.existsSync(evidence), 'Preserve prior constructor evidence before rerunning');
fs.mkdirSync(evidence);
const write = (name, value) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(value, null, 2) + '\n', {flag: name.endsWith('-partial.json') ? 'w' : 'wx'});
const bin = hex => { assert(/^(?:[0-9a-f]{2})*$/.test(hex)); return Buffer.from(hex, 'hex'); };
const senders = [0, 1].map(index => createAddressFromPrivateKey(senderTestSeed(index)));
for (const target of ['paris', 'shanghai']) test(target + ': normal wallet operator authority and retained history', async () => {
  const compiled = load(new URL(target + '-output.json', compileRoot));
  const registryArtifact = compiled.contracts[prefix + 'ChainRegistry.sol'].ChainRegistry;
  const storageLayout = assertStoreLayout(compiled.contracts[prefix + 'RegistryStore.sol'].RegistryStore.storageLayout);
  const storageObservations = [];
  const walletInput = {language: 'Solidity', sources: {'OwnedWallet.sol': {content: fs.readFileSync(new URL('OwnedWallet.sol', root), 'utf8')}}, settings: {
    optimizer: {enabled: true, runs: 200}, viaIR: true, evmVersion: target,
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode', 'evm.deployedBytecode'], '': ['ast']}}
  }};
  write(target + '-wallet-input.json', walletInput);
  const walletOutput = JSON.parse(compiler.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(JSON.stringify(walletInput), 0, 0));
  write(target + '-wallet-output.json', walletOutput);
  assert.deepEqual((walletOutput.errors ?? []).filter(row => row.severity === 'error'), []);
  const walletArtifact = walletOutput.contracts['OwnedWallet.sol'].OwnedWallet;
  assert(bin(walletArtifact.evm.deployedBytecode.object).length <= 24576);
  const common = new Common({chain: Mainnet, hardfork: target === 'paris' ? Hardfork.Paris : Hardfork.Shanghai});
  const vm = await createVM({common});
  assert.equal(vm.evm.DEBUG, false);
  assert.equal(vm.evm.events.listenerCount('step'), 0);
  for (const sender of senders) await vm.stateManager.putAccount(sender, createAccount({balance: 10n ** 30n}));
  const rows = []; let height = 1n;
  let claimUnitSchedule = false;
  const claimBlockReservations = new Map();
  const storageReadLog = new URL(target + '-storage-reads.jsonl', evidence);
  fs.writeFileSync(storageReadLog, '', {flag:'wx'});
  let storageReadIndex = 0;
  const onStorageRead = entry => fs.appendFileSync(storageReadLog, JSON.stringify({global_index:storageReadIndex++,after_transaction_index:rows.length-1,...entry}) + '\n');
  const observedClaim = (...args) => observeClaim(...args,onStorageRead);
  const observedRecord = (...args) => observeRecord(...args,onStorageRead);
  const transact = async (label, to, data, sender = 0, expectedException = null) => {
    const nonce = (await vm.stateManager.getAccount(senders[sender])).nonce;
    // This finite isolated100M ceiling is not any selected chain/block/operating budget.
    const tx = createFeeMarket1559Tx({chainId: 1n, nonce, ...(to ? {to} : {}), data, gasLimit: 100_000_000n,
      maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, value: 0n, accessList: []}, {common}).sign(senderTestSeed(sender));
    const number = height++, timestamp = 10000n + number;
    // The original216-row schedule keeps100M per block. Only the appended
    // claim unit has a same-block pair: both100M declarations fit a common200M
    // header. The transaction execution ceiling itself stays100M.
    const unitBlockGasLimit = claimUnitSchedule ? 200_000_000n : 100_000_000n;
    const block = createBlock({header: {number, timestamp, gasLimit: unitBlockGasLimit, baseFeePerGas: 1n}}, {common});
    let claimBlock;
    if (claimUnitSchedule) {
      const headerHex = Buffer.from(block.header.serialize()).toString('hex');
      const prior = claimBlockReservations.get(number.toString());
      if (prior) assert.equal(prior.headerHex, headerHex, 'Same block must use the identical header');
      claimBlock = {headerHex, transactions:(prior?.transactions ?? 0) + 1,
        declaredGas:(prior?.declaredGas ?? 0n) + 100_000_000n};
      assert(claimBlock.transactions <= 2 && claimBlock.declaredGas <= unitBlockGasLimit);
      claimBlockReservations.set(number.toString(), claimBlock);
    }
    const result = await runTx(vm, {tx, block});
    const row = {index: rows.length, label, sender: senders[sender].toString(), to: to?.toString() ?? null,
      block: number.toString(), timestamp: timestamp.toString(), transaction_hash: Buffer.from(tx.hash()).toString('hex'),
      calldata_hex: data.toString('hex'), calldata_sha256: sha(data), exception: result.execResult.exceptionError?.error ?? null,
      return_hex: Buffer.from(result.execResult.returnValue).toString('hex'), execution_gas: result.execResult.executionGasUsed.toString(), total_gas: result.totalGasSpent.toString(),
      created_address: result.createdAddress?.toString() ?? null,
      logs: (result.execResult.logs ?? []).map(([address, topics, bytes]) => ({address: Buffer.from(address).toString('hex'), topics: topics.map(value => Buffer.from(value).toString('hex')), data: Buffer.from(bytes).toString('hex')}))};
    if (claimUnitSchedule) Object.assign(row, {unit_block_gas_limit:unitBlockGasLimit.toString(),
      unit_block_header_hex:claimBlock.headerHex, unit_block_transactions:claimBlock.transactions,
      unit_block_declared_gas:claimBlock.declaredGas.toString()});
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
  const walletInit = Buffer.concat([bin(walletArtifact.evm.bytecode.object), sequence([{type: 'address'}], [registry.toString()])]);
  assert(walletInit.length <= 49152);
  const walletAddress = createContractAddress(senders[0], 9n), walletDeployment = await transact('constructor:OwnedWallet', null, walletInit);
  assert.equal(walletDeployment.created_address, walletAddress.toString());
  const expectedWallet = bin(walletArtifact.evm.deployedBytecode.object);
  const walletImmutable = [];
  walk(walletOutput.sources['OwnedWallet.sol'].ast, node => {
    if (node.nodeType === 'VariableDeclaration' && node.mutability === 'immutable') walletImmutable.push(node);
  });
  assert.deepEqual(walletImmutable.map(node => node.name).sort(), ['owner', 'registry']);
  for (const node of walletImmutable) for (const span of walletArtifact.evm.deployedBytecode.immutableReferences[String(node.id)]) {
    assert.equal(span.length, 32); (node.name === 'owner' ? addressWord(senders[0]) : addressWord(registry)).copy(expectedWallet, span.start);
  }
  assert.equal(Buffer.from(await vm.stateManager.getCode(walletAddress)).toString('hex'), expectedWallet.toString('hex'));
  // Fixed ordinary owned direct calls are unit ACL checks, not alternate Source or impersonation.
  const errorReference = load(new URL('../fixtures/error-selector-reference.json', root)).error_selectors;
  const unauthorized = errorReference.UnauthorizedCaller.replace(/^0x/, '');
  const storeABI = compiled.contracts[prefix + 'RegistryStore.sol'].RegistryStore.abi;
  const storeBinding = await transact('auxiliary:Store binding', children.RegistryStore, call(storeABI, 'binding', []));
  assert.equal(storeBinding.return_hex, sequence([{type:'address'},{type:'uint256'},{type:'address'}], [registry.toString(), 1n, children.RegistryStore.toString()]).toString('hex'));
  const acl = await transact('unit:owned direct Store write refused', children.RegistryStore, call(storeABI, 'commitClaim', [senders[0].toString(), Buffer.alloc(32, 7)]), 0, 'revert');
  assert.equal(acl.return_hex, unauthorized); assert.deepEqual(acl.logs, []);
  const claimAfterRefusal = await transact('auxiliary:no claim after refused direct write', children.RegistryStore, call(storeABI, 'claim', [senders[0].toString(), Buffer.alloc(32, 7)]));
  assert.equal(claimAfterRefusal.return_hex, sequence([{type:'bool'},{type:'bool'},{type:'uint256'}], [false, false, 0n]).toString('hex'));
  storageObservations.push(await observedClaim(vm, children.RegistryStore, senders[0].toString(), Buffer.alloc(32,7), {present:false,consumed:false,committed:0n}));
  for (const name of childNames.slice(1)) {
    const abi = compiled.contracts[prefix + name + '.sol'][name].abi;
    const bound = await transact('auxiliary:' + name + ' binding', children[name], call(abi, 'binding', []));
    assert.equal(bound.return_hex, sequence([...Array.from({length:5},()=>({type:'address'})), {type:'uint256'}, {type:'address'}],
      [registry.toString(), children.RegistryStore.toString(), renderer.toString(), verifier.toString(), rules.toString(), 1n, children[name].toString()]).toString('hex'));
    const refusal = await transact('unit:owned direct ' + name + ' prepare refused', children[name], call(abi, 'prepare', [senders[0].toString(), call(registryArtifact.abi, 'activate', ['owned-eoa', 1n])]), 0, 'revert');
    assert.equal(refusal.return_hex, unauthorized); assert.deepEqual(refusal.logs, []);
  }

  write(target + '-constructor-identities.json', {scope: 'Actual isolated constructor-created code; no operating/finality qualification', registry: registry.toString(), wallet: walletAddress.toString(), registry_runtime_sha256: codes.ChainRegistry.code_sha256, modules: codes,
    compiler_check_sha256: sha(compilerCheckBytes), source_manifest_sha256: sha(manifestBytes)});
  const operatorWallet = createContractAddress(senders[1], 0n);
  const operatorDeployment = await transact('constructor:OwnedOperatorWallet', null, walletInit, 1);
  assert.equal(operatorDeployment.created_address, operatorWallet.toString());
  const operatorCode = bin(walletArtifact.evm.deployedBytecode.object);
  for (const node of walletImmutable) for (const span of walletArtifact.evm.deployedBytecode.immutableReferences[String(node.id)]) {
    (node.name === 'owner' ? addressWord(senders[1]) : addressWord(registry)).copy(operatorCode, span.start);
  }
  assert.equal(Buffer.from(await vm.stateManager.getCode(operatorWallet)).toString('hex'), operatorCode.toString('hex'));
  write(target+'-operator-wallet-identity.json',{scope:'Normal constructor-created fixed-target wallet only',address:operatorWallet.toString(),owner:senders[1].toString(),registry:registry.toString(),runtime_hex:operatorCode.toString('hex'),runtime_sha256:sha(operatorCode),creation_input_hex:walletInit.toString('hex'),immutable_references:walletArtifact.evm.deployedBytecode.immutableReferences});
  const api = async (name, values, expectedValues, {viaOperatorWallet = false, sender = 0} = {}) => {
    const data = call(registryArtifact.abi, name, values);
    const expected = sequence(registryArtifact.abi.find(value => value.type === 'function' && value.name === name).outputs, expectedValues);
    const row = await transact(name, viaOperatorWallet ? operatorWallet : registry, viaOperatorWallet ? call(walletArtifact.abi, 'invoke', [data]) : data, sender);
    const expectedOuter = viaOperatorWallet ? sequence([{type: 'bytes'}], [expected]) : expected;
    assert.equal(row.return_hex, expectedOuter.toString('hex'), name);
    return row;
  };
  const identity = 'eip155:1:' + registry.toString();
  await api('registryId', [], [identity]);
  for (const wallet of [false]) {
    const agent = 'owned-wallet-operator', principal = senders[0].toString(), operator = operatorWallet.toString();
    const fixture = initialFixture(identity, agent, principal), added = ownedKey(identity, agent, 'm-add', {index: 1}).input;
    const rotated = [{name: 'svc-next', serviceType: 'fixture', uri: 'https://example.invalid/next/'}];
    await api('record', [agent], [false, Buffer.alloc(0)]);
    storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent, null));
    const commit = await api('commitClaim', [fixture.commitment], [], {wallet});
    assert.deepEqual(commit.logs, [{address: registry.toString().slice(2), topics: [Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'), word(BigInt(principal)).toString('hex'), fixture.commitment.toString('hex')], data: word(BigInt(commit.block)).toString('hex')}]);
    storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:false,committed:BigInt(commit.block)}));
    const refusalPlans = [[],
      [['activate',[agent,1n],false],['activate',[agent,1n],true]],
      [['activate',[agent,2n],false],['authorizeOperator',[agent,2n,senders[1].toString(),'deactivate'],true]],
      // The one-use activate grant was removed: authorization must refuse first.
      [['activate',[agent,3n],true]],
      [['updateServices',[agent,4n,rotated],false]],
      [['addKey',[agent,5n,added],true]],
      [['revokeKey',[agent,6n,'m-add'],true]],
      [['authorizeOperator',[agent,7n,senders[1].toString(),'deactivate'],true]],
      [['revokeOperator',[agent,8n,operator,'deactivate'],true]],
      [['deactivate',[agent,9n],true]],
      [['deactivate',[agent,10n],false]],
      [['deactivate',[agent,11n],true]],
      [['deactivate',[agent,12n],false]]
    ];
    assert.equal(refusalPlans.reduce((sum,rows)=>sum+rows.length,0),14);
    let plannedHeight = height;
    const admitted = Array.from({length:13},(_,index)=>{
      plannedHeight+=BigInt(refusalPlans[index].length);
      const time=Number(10000n+plannedHeight);plannedHeight+=BigInt(4+index);return time;
    });
    const modelInput = {registry: identity, initial: fixture.record, added: publicKey(added), rotated_services: publicServices(rotated), operator, admitted, salt: fixture.salt.toString('base64url'), end_mode: wallet ? 'last-signing-revoke' : 'explicit-deactivate'};
    const model = spawnSync('python3', ['-B', new URL('expected-runtime.py', root).pathname], {input: JSON.stringify(modelInput), encoding: 'utf8'});
    assert.equal(model.status, 0, model.stderr);
    const expected = JSON.parse(model.stdout).steps;
    write(target + '-' + agent + '-model.json', {inputs: modelInput, expected});
    const plans = [
      ['revealClaim', [agent, principal, fixture.keys, fixture.services, fixture.salt], 0],
      ['authorizeOperator', [agent, 1n, operator, 'activate'], 0], ['activate', [agent, 2n], 1],
      ['authorizeOperator', [agent, 3n, operator, 'update-services'], 0], ['updateServices', [agent, 4n, rotated], 1],
      ['addKey', [agent, 5n, added], 0], ['revokeKey', [agent, 6n, 'm-add'], 0],
      ['authorizeOperator', [agent, 7n, operator, 'deactivate'], 0],
      ['revokeOperator', [agent, 8n, operator, 'deactivate'], 0],
      ['authorizeOperator', [agent, 9n, operator, 'deactivate'], 0],
      ['revokeOperator', [agent, 10n, operator, 'deactivate'], 0],
      ['authorizeOperator', [agent, 11n, operator, 'deactivate'], 0],
      wallet ? ['revokeKey', [agent, 12n, 'z-sign'], 0] : ['deactivate', [agent, 12n], 1]
    ];
    for (let index = 0; index < plans.length; ++index) {
      for (const [failedName,failedValues,viaOperatorWallet] of refusalPlans[index]) {
        const data=call(registryArtifact.abi,failedName,failedValues);
        const row=await transact('authorization:fixed-refusal:'+failedName+(viaOperatorWallet?':wallet':':owner'),viaOperatorWallet?operatorWallet:registry,
          viaOperatorWallet?call(walletArtifact.abi,'invoke',[data]):data,1,'revert');
        assert.equal(row.return_hex,unauthorized);assert.deepEqual(row.logs,[]);
        const prior=expected[index-1];assert(prior);
        storageObservations.push(await observedRecord(vm,children.RegistryStore,identity,agent,{record:bin(prior.record_hex),grants:bin(prior.grants_hex),admitted:BigInt(JSON.parse(bin(prior.history_hex)).admitted),
          history:expected.slice(0,index).map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
        storageObservations.push(await observedClaim(vm,children.RegistryStore,principal,fixture.commitment,{present:true,consumed:true,committed:BigInt(commit.block)}));
      }
      const [name, values, sender] = plans[index], golden = expected[index], version = BigInt(index + 1);
      const row = await api(name, values, [version], {viaOperatorWallet:sender===1,sender});
      assert.equal(Number(row.timestamp), admitted[index]);
      if (index === 0) storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:true,committed:BigInt(commit.block)}));
      const history = JSON.parse(bin(golden.history_hex)), command = JSON.parse(bin(golden.command_hex));
      assert.equal(command.actor, sender === 0 ? principal : operator);
      const eventData = sequence([{type: 'string'}, {type: 'uint64'}, {type: 'uint64'}, {type: 'string'}, {type: 'bytes32'}, {type: 'bytes32'}, {type: 'bytes32'}, {type: 'uint64'}],
        [fixture.record.id, BigInt(index), version, golden.operation, bin(golden.command_digest_hex), bin(golden.record_digest_hex), bin(golden.grants_digest_hex), BigInt(history.admitted)]);
      assert.deepEqual(row.logs, [{address: registry.toString().slice(2), topics: [Buffer.from(keccak_256(Buffer.from('RecordChanged(bytes32,address,string,uint64,uint64,string,bytes32,bytes32,bytes32,uint64)'))).toString('hex'), golden.did_hash_hex, word(BigInt(golden.actor)).toString('hex')], data: eventData.toString('hex')}]);
      await api('record', [agent], [true, bin(golden.record_hex)]);
      await api('activeGrants', [agent], [bin(golden.grants_hex)]);
      for (let previous = 0; previous <= index; ++previous) await api('historyItem', [agent, BigInt(previous + 1)], [bin(expected[previous].history_hex), bin(expected[previous].command_hex)]);
      storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent, {record:bin(golden.record_hex),grants:bin(golden.grants_hex),admitted:BigInt(history.admitted),
        history:expected.slice(0,index+1).map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
    }
    // A fixed owned ordinary activation request after terminal deactivation is
    // refused. No malformed/forged producer or live submission path is involved.
    const activation = call(registryArtifact.abi, 'activate', [agent, 13n]);
    const refusal = await transact('terminal:activate-refused', registry, activation, 0, 'revert');
    assert.equal(refusal.return_hex, '8f229313'); // Frozen public WrongRecordState().
    assert.deepEqual(refusal.logs, []);
    await api('record', [agent], [true, bin(expected.at(-1).record_hex)]);
    await api('activeGrants', [agent], [bin(expected.at(-1).grants_hex)]);
    for (let index = 0; index < 13; ++index) await api('historyItem', [agent, BigInt(index + 1)], [bin(expected[index].history_hex), bin(expected[index].command_hex)]);
    storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent, {record:bin(expected.at(-1).record_hex),grants:bin(expected.at(-1).grants_hex),admitted:BigInt(JSON.parse(bin(expected.at(-1).history_hex)).admitted),
      history:expected.map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
    storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:true,committed:BigInt(commit.block)}));
    // Fixed read-only requests exercise public missing/zero/future semantics.
    // They never prepare a write, replace a proof or contact a live endpoint.
    const missingAgent = 'owned-missing';
    storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, missingAgent, null));
    const readRefusals = [
      ['zero-existing', 'historyItem', [agent, 0n], 'InvalidEntry'],
      ['zero-missing', 'historyItem', [missingAgent, 0n], 'InvalidEntry'],
      ['future-terminal', 'historyItem', [agent, 14n], 'HistoryUnavailable'],
      ['positive-missing', 'historyItem', [missingAgent, 1n], 'WrongRecordState'],
      ['grants-missing', 'activeGrants', [missingAgent], 'WrongRecordState']
    ];
    for (const [label, name, values, error] of readRefusals) {
      const row = await transact('read-guard:' + label, registry, call(registryArtifact.abi, name, values), 1, 'revert');
      assert.equal(row.return_hex, errorReference[error].replace(/^0x/, ''));
      assert.deepEqual(row.logs, []);
      storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent, {record:bin(expected.at(-1).record_hex),grants:bin(expected.at(-1).grants_hex),admitted:BigInt(JSON.parse(bin(expected.at(-1).history_hex)).admitted),
        history:expected.map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
      storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:true,committed:BigInt(commit.block)}));
      storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, missingAgent, null));
    }
    const absentRead = await api('record', [missingAgent], [false, Buffer.alloc(0)], {sender:1});
    assert.deepEqual(absentRead.logs, []);
    storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, missingAgent, null));
    // Canonical, fixed read-only scalar cases; all inputs remain parser data.
    // The actual ungranted owner EOA1 is a legitimate public reader.
    const scalarPlan = JSON.parse(fs.readFileSync(new URL('read-scalars.json', root), 'utf8'));
    assert.equal(scalarPlan.execution_ready, false);
    assert.equal(scalarPlan.sender_index, 1);
    assert.equal(scalarPlan.cases.length, 27);
    assert.equal(rows.length, scalarPlan.baseline_rows_per_fork);
    for (const fixed of scalarPlan.cases) {
      const targetAgent = fixed.agent === '$terminal' ? agent : fixed.agent;
      const values = fixed.method === 'historyItem' ? [targetAgent, BigInt(fixed.version)] : [targetAgent];
      let result;
      if (fixed.error !== null) {
        assert(Object.hasOwn(errorReference, fixed.error));
        result = await transact('read-scalar:' + fixed.label, registry,
          call(registryArtifact.abi, fixed.method, values), 1, 'revert');
        assert.equal(result.return_hex, errorReference[fixed.error].replace(/^0x/, ''));
      } else {
        let expectedValues;
        if (fixed.expected === 'absent-record') expectedValues = [false, Buffer.alloc(0)];
        else if (fixed.expected === 'terminal-record') expectedValues = [true, bin(expected.at(-1).record_hex)];
        else if (fixed.expected === 'terminal-activeGrants') expectedValues = [bin(expected.at(-1).grants_hex)];
        else {
          assert.equal(fixed.expected, 'terminal-historyItem');
          expectedValues = [bin(expected.at(-1).history_hex), bin(expected.at(-1).command_hex)];
        }
        result = await api(fixed.method, values, expectedValues, {sender:1});
      }
      assert.deepEqual(result.logs, []);
      storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent,
        {record:bin(expected.at(-1).record_hex), grants:bin(expected.at(-1).grants_hex),
          admitted:BigInt(JSON.parse(bin(expected.at(-1).history_hex)).admitted),
          history:expected.map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
      storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment,
        {present:true,consumed:true,committed:BigInt(commit.block)}));
      // Raw storage observation only, not a public snapshot call or admission.
      if (targetAgent !== agent) storageObservations.push(await observedRecord(vm,
        children.RegistryStore, identity, targetAgent, null));
    }
    assert.equal(rows.length, scalarPlan.planned_rows_per_fork);
    // Finite local unit requests using only the two disclosed owned EOAs.
    // No network client, arbitrary input surface, forged proof or state writes.
    const claimPlan = JSON.parse(fs.readFileSync(new URL('claim-cases.json', root), 'utf8'));
    assert.equal(claimPlan.execution_ready, false);
    assert.equal(rows.length, claimPlan.baseline_rows_per_fork);
    const make = (name, controllerIndex = 0) => ({name, controllerIndex,
      ...initialFixture(identity, name, senders[controllerIndex].toString())});
    const pending = make('owned-claim-pending');
    const otherController = make('owned-claim-controller', 1);
    const sameBlock = make('owned-claim-same-block');
    const late = make('owned-claim-late');
    const duplicateName = make('owned-claim-duplicate-name');
    duplicateName.keys = [...duplicateName.keys, duplicateName.keys[1]];
    duplicateName.claim = {...duplicateName.claim, keys: duplicateName.keys.map(key => publicKey(key))};
    duplicateName.commitment = bin(sha(Buffer.concat([Buffer.from('sage-claim-0.11.0'),
      Buffer.from([0]), Buffer.from(jcs(duplicateName.claim))])));
    const fixtures = {pending, otherController, sameBlock, late, duplicateName};
    const revealValues = fixed => [fixed.name, senders[fixed.controllerIndex].toString(),
      fixed.keys, fixed.services, fixed.salt];
    const zero = Buffer.alloc(32);
    const digests = [zero, fixture.commitment, ...Object.values(fixtures).map(value => value.commitment)];
    assert.equal(new Set(digests.map(value => value.toString('hex'))).size, 7);
    const claims = digests.flatMap(digest => senders.map((actor, senderIndex) => ({digest, senderIndex,
      actor: actor.toString(), present: digest.equals(fixture.commitment) && senderIndex === 0,
      consumed: digest.equals(fixture.commitment) && senderIndex === 0,
      committed: digest.equals(fixture.commitment) && senderIndex === 0 ? BigInt(commit.block) : 0n})));
    const references = {zero, terminal: fixture, ...fixtures};
    write(target + '-claim-fixtures.json', {scope: claimPlan.scope,
      fixtures: Object.fromEntries(Object.entries(fixtures).map(([name, fixed]) => [name,
        {agent:fixed.name, controller:senders[fixed.controllerIndex].toString(), claim:fixed.claim,
          claim_jcs_hex:Buffer.from(jcs(fixed.claim)).toString('hex'), commitment_hex:fixed.commitment.toString('hex'),
          reveal_calldata_hex:call(registryArtifact.abi, 'revealClaim', revealValues(fixed)).toString('hex')}])),
      zero_commitment_hex: zero.toString('hex'), baseline_rows: rows.length});
    const invariant = async () => {
      storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent,
        {record:bin(expected.at(-1).record_hex), grants:bin(expected.at(-1).grants_hex),
          admitted:BigInt(JSON.parse(bin(expected.at(-1).history_hex)).admitted),
          history:expected.map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
      for (const fixed of Object.values(fixtures)) storageObservations.push(await observedRecord(vm,
        children.RegistryStore, identity, fixed.name, null));
      for (const entry of claims) storageObservations.push(await observedClaim(vm,
        children.RegistryStore, entry.actor, entry.digest,
        {present:entry.present,consumed:entry.consumed,committed:entry.committed}));
    };
    await invariant();
    assert.equal(claimPlan.unit_block_gas_limit, '200000000');
    assert.equal(claimPlan.transaction_gas_limit, '100000000');
    claimUnitSchedule = true;
    const commitRows = {};
    for (const fixed of claimPlan.cases) {
      const value = references[fixed.fixture];
      assert(value !== undefined && [0,1].includes(fixed.sender));
      const digest = fixed.fixture === 'zero' ? zero : value.commitment;
      if (fixed.block_delta !== null) {
        assert(fixed.method === 'revealClaim' && [0,257].includes(fixed.block_delta));
        assert(Object.hasOwn(commitRows, fixed.fixture));
        // Same-block consecutive transactions and a finite forward block gap
        // are ordinary isolated unit block schedules, not storage injection.
        height = BigInt(commitRows[fixed.fixture].block) + BigInt(fixed.block_delta);
      }
      const values = fixed.method === 'commitClaim' ? [digest] :
        fixed.fixture === 'terminal' ? [agent, principal, fixture.keys, fixture.services, fixture.salt] : revealValues(value);
      const row = await transact('claim-guard:' + fixed.label, registry,
        call(registryArtifact.abi, fixed.method, values), fixed.sender, fixed.error === null ? null : 'revert');
      if (fixed.error !== null) {
        assert(Object.hasOwn(errorReference, fixed.error));
        assert.equal(row.return_hex, errorReference[fixed.error].replace(/^0x/, ''));
        assert.deepEqual(row.logs, []);
      } else {
        assert.equal(fixed.method, 'commitClaim');
        assert.equal(row.return_hex, '');
        const entry = claims.find(entry => entry.senderIndex === fixed.sender && entry.digest.equals(digest));
        assert(entry && !entry.present && !entry.consumed && entry.committed === 0n);
        entry.present = true; entry.committed = BigInt(row.block);
        assert.deepEqual(row.logs, [{address:registry.toString().slice(2),
          topics:[Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'),
            word(BigInt(entry.actor)).toString('hex'), digest.toString('hex')], data:word(entry.committed).toString('hex')}]);
        commitRows[fixed.fixture] = row;
      }
      await invariant();
    }
    const repeated = [...claimBlockReservations.values()].filter(value => value.transactions === 2);
    assert.equal(repeated.length, 1);
    assert.equal(repeated[0].declaredGas, 200_000_000n);
    assert.equal(claimPlan.cases.length, 22);
    assert.equal(rows.length, claimPlan.planned_rows_per_fork);
    // Four fixed owned lifecycle schedules. Prior238 rows and R2 claim headers
    // stay unchanged; each new request occupies its own100M unit block context.
    claimUnitSchedule = false;
    const lifecyclePlan = load(new URL('lifecycle-cases.json', root));
    assert.equal(lifecyclePlan.execution_ready, false);
    assert.equal(lifecyclePlan.baseline_rows_per_fork, 238);
    assert.equal(rows.length, lifecyclePlan.baseline_rows_per_fork);
    assert.deepEqual(lifecyclePlan.traces.map(value => value.mode),
      ['created', 'active', 'expiry-recovery', 'expiry-created']);
    const completedLifecycle = [];
    const observeLifecycle = async (value, steps, committed) => {
      const last = steps.at(-1);
      storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, value.agent,
        last ? {record:bin(last.record_hex),grants:bin(last.grants_hex),
          admitted:BigInt(JSON.parse(bin(last.history_hex)).admitted),
          history:steps.map((step,index)=>({version:BigInt(index+1),history:bin(step.history_hex),command:bin(step.command_hex)}))} : null));
      storageObservations.push(await observedClaim(vm, children.RegistryStore, principal,
        value.fixture.commitment,{present:committed!==null,consumed:steps.length>0,committed:committed??0n}));
    };
    const preservedLifecycle = async () => {
      await invariant();
      for (const value of completedLifecycle) await observeLifecycle(value,value.steps,value.committed);
    };
    let lifecycleSuccesses = 0, lifecycleRefusals = 0, lifecycleMutations = 0;
    for (const fixedTrace of lifecyclePlan.traces) {
      const nextAgent = fixedTrace.agent;
      const nextFixture = initialFixture(identity,nextAgent,principal);
      const expiry = fixedTrace.expiry_offset===null ? null : Number(10000n+height+BigInt(fixedTrace.expiry_offset));
      if (expiry!==null) {
        nextFixture.keys[1] = ownedKey(identity,nextAgent,'z-sign',{expires:expiry}).input;
        nextFixture.record.keys = nextFixture.keys.map(value=>publicKey(value));
        nextFixture.claim.keys = nextFixture.record.keys;
        nextFixture.commitment = bin(sha(Buffer.concat([Buffer.from('sage-claim-0.11.0'),
          Buffer.from([0]),Buffer.from(jcs(nextFixture.claim))])));
      }
      const nextAdded = ownedKey(identity,nextAgent,'m-add',{index:1}).input;
      const value = {agent:nextAgent,fixture:nextFixture};
      let nextHeight = height+2n;
      const times = [Number(10000n+height+1n)];
      for (const fixed of fixedTrace.cases) {
        if (fixed.at_expiry) {
          assert(expiry!==null);
          nextHeight = nextHeight>BigInt(expiry)-10000n?nextHeight:BigInt(expiry)-10000n;
        }
        if (fixed.error===null) times.push(Number(10000n+nextHeight));
        ++nextHeight;
      }
      assert.equal(times.length,fixedTrace.successful_mutations);
      const inputs = {mode:fixedTrace.mode,registry:identity,initial:nextFixture.record,
        added:publicKey(nextAdded),operator:senders[1].toString(),wallet:operatorWallet.toString(),
        admitted:times,salt:nextFixture.salt.toString('base64url')};
      const modeled = spawnSync('python3',['-B',new URL('expected-lifecycle.py',root).pathname],
        {input:JSON.stringify(inputs),encoding:'utf8'});
      assert.equal(modeled.status,0,modeled.stderr);
      const steps = JSON.parse(modeled.stdout).steps;
      assert.equal(steps.length,fixedTrace.successful_mutations);
      write(target+'-'+nextAgent+'-model.json',{inputs,expected:steps});
      await observeLifecycle(value,[],null);
      const committed = await api('commitClaim',[nextFixture.commitment],[]);
      assert.deepEqual(committed.logs,[{address:registry.toString().slice(2),
        topics:[Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'),
          word(BigInt(principal)).toString('hex'),nextFixture.commitment.toString('hex')],
        data:word(BigInt(committed.block)).toString('hex')}]);
      ++lifecycleSuccesses;
      await observeLifecycle(value,[],BigInt(committed.block));
      await preservedLifecycle();
      let applied = 0;
      const accept = async (row,golden) => {
        assert.equal(Number(row.timestamp),times[applied]);
        assert.equal(row.sender,golden.actor);
        assert.equal(row.return_hex,sequence([{type:'uint64'}],[BigInt(applied+1)]).toString('hex'));
        const history = JSON.parse(bin(golden.history_hex));
        const eventData = sequence([{type:'string'},{type:'uint64'},{type:'uint64'},{type:'string'},
          {type:'bytes32'},{type:'bytes32'},{type:'bytes32'},{type:'uint64'}],
          [nextFixture.record.id,BigInt(applied),BigInt(applied+1),golden.operation,
            bin(golden.command_digest_hex),bin(golden.record_digest_hex),bin(golden.grants_digest_hex),BigInt(history.admitted)]);
        assert.deepEqual(row.logs,[{address:registry.toString().slice(2),
          topics:[Buffer.from(keccak_256(Buffer.from('RecordChanged(bytes32,address,string,uint64,uint64,string,bytes32,bytes32,bytes32,uint64)'))).toString('hex'),golden.did_hash_hex,word(BigInt(golden.actor)).toString('hex')],
          data:eventData.toString('hex')}]);
        ++applied; ++lifecycleSuccesses; ++lifecycleMutations;
      };
      const revealed = await transact('lifecycle:'+fixedTrace.mode+':create',registry,
        call(registryArtifact.abi,'revealClaim',[nextAgent,principal,nextFixture.keys,nextFixture.services,nextFixture.salt]));
      await accept(revealed,steps[applied]);
      await observeLifecycle(value,steps.slice(0,applied),BigInt(committed.block));
      await preservedLifecycle();
      const symbols = {'$agent':nextAgent,'$controller':principal,'$operator':senders[1].toString(),
        '$wallet':operatorWallet.toString(),'$zero':'0x'+'0'.repeat(40),'$added':nextAdded};
      for (const fixed of fixedTrace.cases) {
        if (fixed.at_expiry) {
          assert(expiry!==null);
          height = height>BigInt(expiry)-10000n?height:BigInt(expiry)-10000n;
        }
        const args = fixed.args.map(item=>typeof item==='string'&&Object.hasOwn(symbols,item)?symbols[item]:item);
        assert([0,1].includes(fixed.sender));
        if (fixed.error!==null) assert(Object.hasOwn(errorReference,fixed.error));
        const row = await transact('lifecycle:'+fixedTrace.mode+':'+fixed.label,registry,
          call(registryArtifact.abi,fixed.method,args),fixed.sender,fixed.error===null?null:'revert');
        if (fixed.error===null) await accept(row,steps[applied]);
        else {
          assert.equal(row.return_hex,errorReference[fixed.error].replace(/^0x/,''));
          assert.deepEqual(row.logs,[]); ++lifecycleRefusals;
        }
        await observeLifecycle(value,steps.slice(0,applied),BigInt(committed.block));
        await preservedLifecycle();
      }
      assert.equal(height,nextHeight);
      assert.equal(applied,steps.length);
      completedLifecycle.push({...value,steps,committed:BigInt(committed.block)});
    }
    assert.equal(completedLifecycle.length,4);
    assert.equal(lifecycleSuccesses,lifecyclePlan.expected_new_successful_transactions);
    assert.equal(lifecycleRefusals,lifecyclePlan.expected_new_refusals);
    assert.equal(lifecycleMutations,lifecyclePlan.expected_new_mutations);
    assert.equal(rows.length,lifecyclePlan.planned_rows_per_fork);

    // Fixed owned entry and service targets, appended after the original302.
    // Pre-proof refusals use fixed inert fields; no corrupted signatures run.
    const entryPlan = load(new URL('entry-cases.json', root));
    assert.equal(entryPlan.execution_ready, false);
    assert.equal(rows.length, entryPlan.baseline_rows_per_fork);
    const entryAgent = entryPlan.agent;
    const entryInitial = initialFixture(identity, entryAgent, principal);
    const entries = entryFixtures(identity, entryAgent);
    const serviceValue = name => ({name, serviceType:'fixture', uri:'https://example.invalid/entry/'});
    const freshServices = [serviceValue('fresh-service')];
    const entryValue = {agent:entryAgent, fixture:entryInitial};
    const fullDid = entryInitial.record.id;
    const symbols = {'$agent':entryAgent, '$controller':principal,
      '$initialKeys':entryInitial.keys, '$initialServices':entryInitial.services, '$salt':entryInitial.salt,
      '$expired':entries.expired.input, '$added':entries.added.input,
      '$kemAdded':entries.kemAdded.input, '$service':entries.service.input,
      '$freshServices':freshServices};
    const times = entryPlan.cases.flatMap((fixed,index) => fixed.error===null
      ? [Number(10000n+height+1n+BigInt(index))] : []);
    const inputs = {registry:identity, initial:entryInitial.record,
      keys:['expired','added','kemAdded','service'].map(name=>publicKey(entries[name].input)),
      services:publicServices(freshServices), admitted:times, salt:entryInitial.salt.toString('base64url')};
    const modeled = spawnSync('python3',['-B',new URL('expected-entry.py',root).pathname],
      {input:JSON.stringify(inputs),encoding:'utf8'});
    assert.equal(modeled.status,0,modeled.stderr);
    const steps = JSON.parse(modeled.stdout).steps;
    assert.equal(steps.length,11);
    write(target+'-'+entryAgent+'-model.json',{inputs,expected:steps});
    let entryApplied=0, entryRefusals=0;
    const diagnostic = label => {
      const key = {...entries.guard.input};
      const add = (value=key,version=entryApplied) => ['addKey',[entryAgent,version,value]];
      const services = (values,version=entryApplied) => ['updateServices',[entryAgent,version,values]];
      switch (label) {
        case 'empty-key-name-before-caller': return add({...key,name:''});
        case 'absent-expiry-nonzero-before-caller': return add({...key,hasExpiry:false,expires:1n});
        case 'unsafe-expiry-before-caller': return add({...key,hasExpiry:true,expires:9007199254740992n});
        case 'algorithm-width-before-caller': return add({...key,alg:'a'.repeat(25)});
        case 'key-width-before-caller': return add({...key,key:Buffer.alloc(66,4)});
        case 'proof-width-before-caller': return add({...key,proof:Buffer.alloc(66,2)});
        case 'signer-width-before-caller': return add({...key,signer:'a'.repeat(190)});
        case 'fragment-uri-before-caller': return services([{...serviceValue('ab-service'),uri:'https://example.invalid/entry/#fixed'}]);
        case 'service-target-after-caller': return services([serviceValue('z-sign')]);
        case 'predecessor-before-algorithm': return add({...key,alg:'p256'},0);
        case 'unsupported-before-width': return add({...key,alg:'p256',key:Buffer.alloc(65,4),proof:Buffer.alloc(65,2)});
        case 'ed-key-width': return add({...key,key:Buffer.alloc(31,4)});
        case 'ed-proof-width': return add({...key,proof:Buffer.alloc(63,2)});
        case 'ed-self-signer': return add({...key,signer:fullDid+'#z-sign'});
        case 'accepted-name-before-material': return add(entries.initial.input);
        case 'accepted-material-after-name': return add(entries.reusedInitial.input);
        case 'live-service-name-blocks-key': return add(entries.service.input);
        case 'service-inversion': return services([serviceValue('za-service'),serviceValue('ab-service')]);
        case 'service-duplicate': return services([serviceValue('ab-service'),serviceValue('ab-service')]);
        case 'kem-role-signer': return add({...entries.kemGuard.input,signer:fullDid+'#a-kem'});
        case 'kem-absent-signer': return add({...entries.kemGuard.input,signer:fullDid+'#absent'});
        case 'kem-cross-record-signer': return add({...entries.kemGuard.input,
          signer:'did:sage:'+identity+':owned-other-entry#z-sign'});
        case 'kem-expired-signer': return add(entries.kemExpired.input);
        case 'revoked-name-retained': return add(entries.added.input);
        case 'revoked-material-retained': return add(entries.reusedAdded.input);
        case 'kem-revoked-m-add-signer': return add(entries.kemRevokedAdded.input);
        case 'revoked-key-blocks-service': return services([serviceValue('m-add')]);
        case 'accepted-key-blocks-service': return services([serviceValue('svc')]);
        case 'kem-revoked-z-sign-signer': return add(entries.kemRevokedInitial.input);
        case 'terminal-before-predecessor-target': return services([serviceValue('svc')],0);
        case 'uri-width-before-caller': return services([{...serviceValue('ab-service'),
          uri:'https://example.invalid/'+ 'a'.repeat(2049-'https://example.invalid/'.length)}]);
        default: assert.fail('Unrecognized fixed entry diagnostic '+label);
      }
    };
    await observeLifecycle(entryValue,[],null);
    const entryCommitted = await api('commitClaim',[entryInitial.commitment],[]);
    assert.deepEqual(entryCommitted.logs,[{address:registry.toString().slice(2),
      topics:[Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'),
        word(BigInt(principal)).toString('hex'),entryInitial.commitment.toString('hex')],
      data:word(BigInt(entryCommitted.block)).toString('hex')}]);
    await observeLifecycle(entryValue,[],BigInt(entryCommitted.block));
    await preservedLifecycle();
    for (const fixed of entryPlan.cases) {
      const [method,args] = fixed.error===null
        ? [fixed.method,fixed.args.map(value=>typeof value==='string'&&Object.hasOwn(symbols,value)?symbols[value]:value)]
        : diagnostic(fixed.diagnostic);
      assert([0,1].includes(fixed.sender));
      const row = await transact('entries:'+fixed.label,registry,
        call(registryArtifact.abi,method,args),fixed.sender,fixed.error===null?null:'revert');
      if (fixed.error===null) {
        const golden = steps[entryApplied], version=BigInt(entryApplied+1);
        assert.equal(Number(row.timestamp),times[entryApplied]);
        assert.equal(row.sender,golden.actor);
        assert.equal(row.return_hex,sequence([{type:'uint64'}],[version]).toString('hex'));
        const history = JSON.parse(bin(golden.history_hex));
        const eventData = sequence([{type:'string'},{type:'uint64'},{type:'uint64'},{type:'string'},
          {type:'bytes32'},{type:'bytes32'},{type:'bytes32'},{type:'uint64'}],
          [fullDid,BigInt(entryApplied),version,golden.operation,
            bin(golden.command_digest_hex),bin(golden.record_digest_hex),bin(golden.grants_digest_hex),BigInt(history.admitted)]);
        assert.deepEqual(row.logs,[{address:registry.toString().slice(2),
          topics:[Buffer.from(keccak_256(Buffer.from('RecordChanged(bytes32,address,string,uint64,uint64,string,bytes32,bytes32,bytes32,uint64)'))).toString('hex'),
            golden.did_hash_hex,word(BigInt(golden.actor)).toString('hex')],data:eventData.toString('hex')}]);
        ++entryApplied;
      } else {
        assert(Object.hasOwn(errorReference,fixed.error));
        assert.equal(row.return_hex,errorReference[fixed.error].replace(/^0x/,''));
        assert.deepEqual(row.logs,[]);
        ++entryRefusals;
      }
      await observeLifecycle(entryValue,steps.slice(0,entryApplied),BigInt(entryCommitted.block));
      await preservedLifecycle();
    }
    assert.equal(entryApplied,entryPlan.new_mutations);
    assert.equal(entryApplied+1,entryPlan.new_successful_transactions);
    assert.equal(entryRefusals,entryPlan.new_refusals);
    assert.equal(rows.length,entryPlan.planned_rows_per_fork);

    // Appended normal owned claim-window/clock units; no old row/header changes.
    const clockPlan = load(new URL('claim-clock-cases.json',root));
    assert.equal(clockPlan.execution_ready,false);
    assert.equal(rows.length,clockPlan.baseline_rows_per_fork);
    assert.equal(clockPlan.unit_block_gas_limit,'200000000');
    assert.equal(clockPlan.transaction_execution_gas_limit,'100000000');
    const clockBase=height;
    const upper=make('owned-claim-upper'), retry=make('owned-claim-retry');
    const corrected=make('owned-claim-collision');
    const collision=make('owned-claim-collision');
    collision.services=[{name:'z-sign',serviceType:'fixture',uri:'https://example.invalid/collision/'}];
    collision.record.services=publicServices(collision.services);
    collision.claim.services=collision.record.services;
    collision.commitment=bin(sha(Buffer.concat([Buffer.from('sage-claim-0.11.0'),
      Buffer.from([0]),Buffer.from(jcs(collision.claim))])));
    const clockFixtures={upper,retry,collision,corrected};
    assert.equal(new Set(Object.values(clockFixtures).map(value=>value.commitment.toString('hex'))).size,4);
    const modelInputs={registry:identity,base_height:Number(clockBase),
      collision:{claim:collision.claim,commitment_hex:collision.commitment.toString('hex')},
      fixtures:[upper,retry,corrected].map(value=>({record:value.record,claim:value.claim,
        commitment_hex:value.commitment.toString('hex')}))};
    const clockModeled=spawnSync('python3',['-B',new URL('expected-claim-clock.py',root).pathname],
      {input:JSON.stringify(modelInputs),encoding:'utf8'});
    assert.equal(clockModeled.status,0,clockModeled.stderr);
    const clockSteps=JSON.parse(clockModeled.stdout).traces;
    assert.deepEqual(clockSteps.map(value=>value.length),[1,2,1]);
    write(target+'-claim-clock-model.json',{inputs:modelInputs,expected:clockSteps,
      collision_claim:collision.claim,collision_commitment_hex:collision.commitment.toString('hex')});
    const clockStates=Object.fromEntries(Object.keys(clockFixtures).map(name=>[name,{committed:null,consumed:false}]));
    const appliedClock={upper:0,retry:0,corrected:0};
    const clockTrace={upper:clockSteps[0],retry:clockSteps[1],corrected:clockSteps[2]};
    const preservedClock=async()=>{
      await preservedLifecycle();
      await observeLifecycle(entryValue,steps,BigInt(entryCommitted.block));
      for (const name of ['upper','retry','corrected']) {
        const value=clockFixtures[name], state=clockStates[name];
        await observeLifecycle({agent:value.name,fixture:value},clockTrace[name].slice(0,appliedClock[name]),state.committed);
      }
      for (const value of Object.values(clockFixtures)) storageObservations.push(await observedClaim(vm,
        children.RegistryStore,senders[1].toString(),value.commitment,{present:false,consumed:false,committed:0n}));
      const state=clockStates.collision;
      storageObservations.push(await observedClaim(vm,children.RegistryStore,principal,collision.commitment,
        {present:state.committed!==null,consumed:state.consumed,committed:state.committed??0n}));
    };
    await preservedClock();
    claimUnitSchedule=true;
    let clockSuccesses=0,clockRefusals=0,clockMutations=0;
    const scheduledRows=[];
    for (const fixed of clockPlan.cases) {
      const value=clockFixtures[fixed.fixture],state=clockStates[fixed.fixture];
      height=clockBase+BigInt(fixed.block_offset);
      const args=fixed.method==='commitClaim'?[value.commitment]:fixed.method==='activate'?
        [value.name,1n]:revealValues(value);
      const row=await transact('claim-clock:'+fixed.label,registry,
        call(registryArtifact.abi,fixed.method,args),0,fixed.error===null?null:'revert');
      scheduledRows.push(row);
      assert.equal(BigInt(row.block),clockBase+BigInt(fixed.block_offset));
      if (fixed.error!==null) {
        assert.equal(row.return_hex,errorReference[fixed.error].replace(/^0x/,''));
        assert.deepEqual(row.logs,[]);++clockRefusals;
      } else if (fixed.method==='commitClaim') {
        assert.equal(state.committed,null);
        assert.equal(row.return_hex,'');state.committed=BigInt(row.block);
        assert.deepEqual(row.logs,[{address:registry.toString().slice(2),
          topics:[Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'),
            word(BigInt(principal)).toString('hex'),value.commitment.toString('hex')],data:word(state.committed).toString('hex')}]);
        ++clockSuccesses;
      } else {
        const index=appliedClock[fixed.fixture],golden=clockTrace[fixed.fixture][index];
        const history=JSON.parse(bin(golden.history_hex));
        assert.equal(row.sender,golden.actor);
        assert.equal(BigInt(row.timestamp),BigInt(history.admitted));
        assert.equal(row.return_hex,sequence([{type:'uint64'}],[BigInt(index+1)]).toString('hex'));
        const eventData=sequence([{type:'string'},{type:'uint64'},{type:'uint64'},{type:'string'},
          {type:'bytes32'},{type:'bytes32'},{type:'bytes32'},{type:'uint64'}],
          [value.record.id,BigInt(index),BigInt(index+1),golden.operation,bin(golden.command_digest_hex),
            bin(golden.record_digest_hex),bin(golden.grants_digest_hex),BigInt(history.admitted)]);
        assert.deepEqual(row.logs,[{address:registry.toString().slice(2),
          topics:[Buffer.from(keccak_256(Buffer.from('RecordChanged(bytes32,address,string,uint64,uint64,string,bytes32,bytes32,bytes32,uint64)'))).toString('hex'),
            golden.did_hash_hex,word(BigInt(golden.actor)).toString('hex')],data:eventData.toString('hex')}]);
        ++appliedClock[fixed.fixture];state.consumed=true;++clockSuccesses;++clockMutations;
      }
      await preservedClock();
    }
    assert.equal(height,clockBase+263n);
    for (const [left,right] of [[2,3],[4,5]]) {
      assert.equal(scheduledRows[left].unit_block_header_hex,scheduledRows[right].unit_block_header_hex);
      assert.equal(scheduledRows[left].unit_block_transactions,1);
      assert.equal(scheduledRows[right].unit_block_transactions,2);
      assert.equal(scheduledRows[right].unit_block_declared_gas,'200000000');
    }
    assert.equal(scheduledRows[4].timestamp,scheduledRows[5].timestamp);
    assert.equal(BigInt(scheduledRows[1].block)-clockStates.upper.committed,256n);
    assert.equal(BigInt(scheduledRows[4].block)-clockStates.retry.committed,1n);
    assert.deepEqual(appliedClock,{upper:1,retry:2,corrected:1});
    assert.equal(clockStates.collision.consumed,false);
    assert.equal(clockSuccesses,clockPlan.new_successful_transactions);
    assert.equal(clockRefusals,clockPlan.new_refusals);
    assert.equal(clockMutations,clockPlan.new_mutations);
    assert.equal(rows.length,clockPlan.planned_rows_per_fork);
    claimUnitSchedule=false;


  }
  write(target + '-store-observations.json', {scope:'Read-only local owned fullStore packing/mapping/claim/retained-state observations only; not Source',storageLayout,storageObservations});
  write(target + '-rows.json', {scope: 'Owned wallet-operator13-mutation trace with14fixed authority refusals plus controller terminal refusal and5fixed read refusals/one absent-record read plus27fixed scalar/public-reader queries,22fixed owned claim-namespace/window requests and64fixed lifecycle/grant/expiry requests plus43fixed owned entry/service requests and10fixed owned claim-window/clock requests, raw Store/history observations; no maximumcost/coverage/operating/finality claim', complete: true, rows});
});
