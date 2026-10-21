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
import {senderTestSeed, initialFixture, ownedKey, publicKey, publicServices} from './owned-fixtures.mjs';
import {assertStoreLayout, observeClaim, observeRecord} from './observe.mjs';

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
assert.equal(manifest.tool_files_sha256['ethereum/component-tests/chain-registry/runtime/constructor-unit.mjs'], sha(fs.readFileSync(new URL(import.meta.url))));
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
const evidence = new URL('evidence/ordinary/', root);
assert(!fs.existsSync(evidence), 'Preserve prior constructor evidence before rerunning');
fs.mkdirSync(evidence);
const write = (name, value) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(value, null, 2) + '\n', {flag: name.endsWith('-partial.json') ? 'w' : 'wx'});
const bin = hex => { assert(/^(?:[0-9a-f]{2})*$/.test(hex)); return Buffer.from(hex, 'hex'); };
const senders = [0, 1].map(index => createAddressFromPrivateKey(senderTestSeed(index)));
const cases = [...load(new URL('../libraries/verifier/frozen-research-cases.json', root)).cases,
  ...load(new URL('../libraries/verifier/owned-cases.json', root)).cases].filter(row => row.contract === 'RegistryEd25519' && row.method === 'verify(bytes,bytes,bytes)');
assert.equal(cases.length, 35);

for (const target of ['paris', 'shanghai']) test(target + ': real constructor, owned callers and retained history', async () => {
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
    const block = createBlock({header: {number, timestamp, gasLimit: 100_000_000n, baseFeePerGas: 1n}}, {common});
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
  const verifierArtifact = compiled.contracts[prefix + 'RegistryEd25519.sol'].RegistryEd25519;
  for (const fixed of cases) {
    const row = await transact('backend:' + fixed.name, verifier, call(verifierArtifact.abi, 'verify', [bin(fixed.key), bin(fixed.message), bin(fixed.signature)]));
    assert.equal(row.return_hex, word(fixed.expected ? 1n : 0n).toString('hex'));
    assert(BigInt(row.execution_gas) <= 15_000_000n);
  }
  const api = async (name, values, expectedValues, {wallet = false, sender = 0} = {}) => {
    const data = call(registryArtifact.abi, name, values);
    const expected = sequence(registryArtifact.abi.find(value => value.type === 'function' && value.name === name).outputs, expectedValues);
    const row = await transact(name, wallet ? walletAddress : registry, wallet ? call(walletArtifact.abi, 'invoke', [data]) : data, sender);
    const expectedOuter = wallet ? sequence([{type: 'bytes'}], [expected]) : expected;
    assert.equal(row.return_hex, expectedOuter.toString('hex'), name);
    return row;
  };
  const identity = 'eip155:1:' + registry.toString();
  await api('registryId', [], [identity]);
  for (const wallet of [false, true]) {
    const agent = wallet ? 'owned-wallet' : 'owned-eoa', principal = wallet ? walletAddress.toString() : senders[0].toString();
    const fixture = initialFixture(identity, agent, principal), added = ownedKey(identity, agent, 'm-add', {index: 1}).input;
    const rotated = [{name: 'svc-next', serviceType: 'fixture', uri: 'https://example.invalid/next/'}];
    await api('record', [agent], [false, Buffer.alloc(0)]);
    storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent, null));
    const commit = await api('commitClaim', [fixture.commitment], [], {wallet});
    assert.deepEqual(commit.logs, [{address: registry.toString().slice(2), topics: [Buffer.from(keccak_256(Buffer.from('ClaimCommitted(address,bytes32,uint256)'))).toString('hex'), word(BigInt(principal)).toString('hex'), fixture.commitment.toString('hex')], data: word(BigInt(commit.block)).toString('hex')}]);
    storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:false,committed:BigInt(commit.block)}));
    let plannedHeight = height;
    const admitted = Array.from({length: 13}, (_, index) => { const time = Number(10000n + plannedHeight); plannedHeight += BigInt(4 + index); return time; });
    const modelInput = {registry: identity, initial: fixture.record, added: publicKey(added), rotated_services: publicServices(rotated), operator: senders[1].toString(), admitted, salt: fixture.salt.toString('base64url'), end_mode: wallet ? 'last-signing-revoke' : 'explicit-deactivate'};
    const model = spawnSync('python3', ['-B', new URL('expected-runtime.py', root).pathname], {input: JSON.stringify(modelInput), encoding: 'utf8'});
    assert.equal(model.status, 0, model.stderr);
    const expected = JSON.parse(model.stdout).steps;
    write(target + '-' + agent + '-model.json', {inputs: modelInput, expected});
    const plans = [
      ['revealClaim', [agent, principal, fixture.keys, fixture.services, fixture.salt], 0],
      ['authorizeOperator', [agent, 1n, senders[1].toString(), 'activate'], 0], ['activate', [agent, 2n], 1],
      ['authorizeOperator', [agent, 3n, senders[1].toString(), 'update-services'], 0], ['updateServices', [agent, 4n, rotated], 1],
      ['addKey', [agent, 5n, added], 0], ['revokeKey', [agent, 6n, 'm-add'], 0],
      ['authorizeOperator', [agent, 7n, senders[1].toString(), 'deactivate'], 0],
      ['revokeOperator', [agent, 8n, senders[1].toString(), 'deactivate'], 0],
      ['authorizeOperator', [agent, 9n, senders[1].toString(), 'deactivate'], 0],
      ['revokeOperator', [agent, 10n, senders[1].toString(), 'deactivate'], 0],
      ['authorizeOperator', [agent, 11n, senders[1].toString(), 'deactivate'], 0],
      wallet ? ['revokeKey', [agent, 12n, 'z-sign'], 0] : ['deactivate', [agent, 12n], 1]
    ];
    for (let index = 0; index < plans.length; ++index) {
      const [name, values, sender] = plans[index], golden = expected[index], version = BigInt(index + 1);
      const row = await api(name, values, [version], {wallet: wallet && sender === 0, sender});
      assert.equal(Number(row.timestamp), admitted[index]);
      if (index === 0) storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:true,committed:BigInt(commit.block)}));
      const history = JSON.parse(bin(golden.history_hex)), command = JSON.parse(bin(golden.command_hex));
      assert.equal(command.actor, sender === 0 ? principal : senders[1].toString());
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
    const refusal = await transact('terminal:activate-refused', wallet ? walletAddress : registry,
      wallet ? call(walletArtifact.abi, 'invoke', [activation]) : activation, 0, 'revert');
    assert.equal(refusal.return_hex, '8f229313'); // Frozen public WrongRecordState().
    await api('record', [agent], [true, bin(expected.at(-1).record_hex)]);
    await api('activeGrants', [agent], [bin(expected.at(-1).grants_hex)]);
    for (let index = 0; index < 13; ++index) await api('historyItem', [agent, BigInt(index + 1)], [bin(expected[index].history_hex), bin(expected[index].command_hex)]);
    storageObservations.push(await observedRecord(vm, children.RegistryStore, identity, agent, {record:bin(expected.at(-1).record_hex),grants:bin(expected.at(-1).grants_hex),admitted:BigInt(JSON.parse(bin(expected.at(-1).history_hex)).admitted),
      history:expected.map((item,n)=>({version:BigInt(n+1),history:bin(item.history_hex),command:bin(item.command_hex)}))}));
    storageObservations.push(await observedClaim(vm, children.RegistryStore, principal, fixture.commitment, {present:true,consumed:true,committed:BigInt(commit.block)}));
  }
  write(target + '-store-observations.json', {scope:'Read-only local owned fullStore packing/mapping/claim/retained-state observations only; not Source',storageLayout,storageObservations});
  write(target + '-rows.json', {scope: 'Owned ordinary constructor/35actualproduction backend vectors/two13-mutation traces with all13API and retainedhistory reads only; no maximumcost/operating/finality claim', complete: true, rows});
});
