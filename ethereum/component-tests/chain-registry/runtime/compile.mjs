// Reproducible bound Registry compiler only. No VM, network, deployment or rebinding.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';

assert.deepEqual(process.execArgv, ['--max-old-space-size=512']);
const root = new URL('./', import.meta.url), repo = new URL('../../../../', root);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const read = path => fs.readFileSync(new URL(path, repo));
const manifestBytes = fs.readFileSync(new URL('source-identities.json', root));
const manifest = JSON.parse(manifestBytes);
assert.equal(manifest.scope, 'Bound Registry source and verification tools only; not operating qualification');
for (const section of ['source_files_sha256', 'tool_files_sha256']) {
  for (const [path, digest] of Object.entries(manifest[section])) {
    assert(!path.startsWith('/') && !path.split('/').includes('..'));
    const url = new URL(path, repo);
    assert(fs.lstatSync(url).isFile() && !fs.lstatSync(url).isSymbolicLink());
    assert.equal(sha(read(path)), digest, path);
  }
}
const self = 'ethereum/component-tests/chain-registry/runtime/compile.mjs';
assert.equal(manifest.tool_files_sha256[self], sha(fs.readFileSync(new URL(import.meta.url))));
const primitive = new URL('../node_modules/@noble/hashes/', root);
const primitivePins = {'package.json':'3e361734f5269de162fa362483d7f45dee7efb533ec217157945338f7591baaf',
  'sha3.js':'9a81e1edb24eae27b335533220167609cfb58008c5690e140ce478acdc669f32',
  '_u64.js':'b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102',
  'utils.js':'037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c'};
for(const [name,digest] of Object.entries(primitivePins)) assert.equal(sha(fs.readFileSync(new URL(name,primitive))),digest);
const {keccak_256}=await import(new URL('sha3.js',primitive));
const sourceNames = Object.keys(manifest.source_files_sha256).filter(path => path.endsWith('.sol')).sort();
assert.equal(sourceNames.length, 29);
const prefix = 'ethereum/contracts/chain-registry/';
assert.equal(Object.keys(manifest.source_files_sha256).length, 32);
assert(sourceNames.every(path => path.startsWith(prefix)));
const sources = Object.fromEntries(sourceNames.map(path => [path, {content: read(path).toString('utf8')}]));
const compilerPath = new URL('ethereum/component-tests/chain-registry/evidence/soljson.cjs', repo);
assert.equal(sha(fs.readFileSync(compilerPath)), '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
const compiler = createRequire(import.meta.url)(compilerPath.pathname);
assert.equal(compiler.cwrap('solidity_version', 'string', [])(), '0.8.20+commit.a1b79de6.Emscripten.clang');
const expected = JSON.parse(fs.readFileSync(new URL('fixtures/expected-modules.json', root)));
assert.equal(expected.compiler, '0.8.20+commit.a1b79de6.Emscripten.clang');
assert.deepEqual(Object.keys(expected.targets).sort(), ['paris', 'shanghai']);
const roles = {RENDERER: 'RegistryRenderer', VERIFIER: 'RegistryEd25519', RULES: 'RegistryRules', VALIDATOR: 'RegistryCallValidator',
  STOREFACTORY: 'RegistryStoreFactory', CLAIMFACTORY: 'RegistryClaimProcessorFactory', KEYFACTORY: 'RegistryKeyServiceProcessorFactory',
  LIFECYCLEFACTORY: 'RegistryLifecycleProcessorFactory'};
const children = ['RegistryStore', 'RegistryClaimProcessor', 'RegistryKeyServiceProcessor', 'RegistryLifecycleProcessor'];
const literals = Object.fromEntries([...sources[prefix + 'RegistryRoleHashes.sol'].content.matchAll(
  /bytes32 private constant ([A-Z_]+)\s*=\s*bytes32\(0x([0-9a-f]{64})\);/g)].map(row => [row[1], row[2]]));
assert.equal(Object.keys(literals).length, 16);
assert(Object.values(literals).every(value => BigInt('0x' + value) !== 0n));
const evidence = new URL('evidence/compiler/', root);
assert(!fs.existsSync(evidence), 'Preserve earlier compiler observations before another attempt');
fs.mkdirSync(evidence, {recursive: true});
const write = (name, value) => fs.writeFileSync(new URL(name, evidence), JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
write('source-graph.json', {scope: 'Bound compiler observations only; no constructors or operating qualification',
  source_manifest_sha256: sha(manifestBytes), compiler_sha256: sha(fs.readFileSync(compilerPath)),
  node: process.version, exec_args: process.execArgv, primitive_sha256: primitivePins,
  sources_sha256: Object.fromEntries(Object.entries(sources).map(([name, value]) => [name, sha(Buffer.from(value.content))]))});
const hashes = {};
for (const target of ['paris', 'shanghai']) {
  const input = {language: 'Solidity', sources, settings: {optimizer: {enabled: true, runs: 200}, viaIR: true, evmVersion: target,
    metadata: {bytecodeHash: 'ipfs', appendCBOR: true},
    outputSelection: {'*': {'*': ['abi', 'metadata', 'storageLayout', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers'], '': ['ast']}}}};
  write(target + '-input.json', input);
  const output = JSON.parse(compiler.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(JSON.stringify(input), 0, 0));
  write(target + '-output.json', output);
  assert(!(output.errors ?? []).some(error => error.severity === 'error'), JSON.stringify(output.errors));
  assert.deepEqual(Object.keys(output.sources).sort(), sourceNames);
  const rows = {};
  for (const [file, artifacts] of Object.entries(output.contracts)) {
    for (const [name, artifact] of Object.entries(artifacts)) {
      const metadata = JSON.parse(artifact.metadata);
      assert.equal(metadata.compiler.version, '0.8.20+commit.a1b79de6');
      assert.equal(metadata.language, 'Solidity');
      assert.deepEqual(metadata.settings, {compilationTarget: {[file]: name}, evmVersion: target, libraries: {},
        metadata: {bytecodeHash: 'ipfs'}, optimizer: {enabled: true, runs: 200}, remappings: [], viaIR: true});
      assert(file in metadata.sources && Object.keys(metadata.sources).every(path => path in sources));
      for (const [path, entry] of Object.entries(metadata.sources)) {
        assert.equal(entry.keccak256, '0x' + Buffer.from(keccak_256(Buffer.from(sources[path].content))).toString('hex'));
      }
      const runtime = artifact.evm.deployedBytecode.object, creation = artifact.evm.bytecode.object;
      if (runtime === '' && creation === '') continue;
      assert(/^(?:[0-9a-f]{2})+$/.test(runtime) && /^(?:[0-9a-f]{2})+$/.test(creation), 'Unlinked or partial bytecode: ' + name);
      const constructor = artifact.abi.find(row => row.type === 'constructor');
      assert((constructor?.inputs ?? []).every(row => row.type === 'address'), name);
      const args = (constructor?.inputs.length ?? 0) * 32;
      const digest = Buffer.from(keccak_256(Buffer.from(runtime, 'hex'))).toString('hex');
      rows[name] = {source: file, runtime_bytes: runtime.length / 2, creation_bytes: creation.length / 2,
        constructor_args_bytes: args, total_initcode_bytes: creation.length / 2 + args,
        runtime_sha256: sha(Buffer.from(runtime, 'hex')), creation_sha256: sha(Buffer.from(creation, 'hex')), runtime_keccak256: digest,
        immutable_references: artifact.evm.deployedBytecode.immutableReferences,
        EIP170_within: runtime.length / 2 <= 24576, EIP3860_within: creation.length / 2 + args <= 49152,
        constructor_not_executed: true};
      const role = Object.keys(roles).find(key => roles[key] === name);
      if (role) {
        assert.deepEqual(artifact.evm.deployedBytecode.immutableReferences, {});
        const baseline = expected.targets[target][role];
        assert.equal(baseline.contract, name);
        assert.equal(rows[name].runtime_sha256, baseline.runtime_sha256);
        assert.equal(rows[name].creation_sha256, baseline.creation_sha256);
        assert.equal(digest, baseline.runtime_keccak256);
        hashes[target.toUpperCase() + '_' + role] = digest;
        assert.equal(digest, literals[target.toUpperCase() + '_' + role]);
      }
    }
  }
  assert(['ChainRegistry', ...Object.values(roles), ...children].every(name => name in rows));
  write(target + '-sizes.json', {scope: 'Compiler sizes, not deployed-code or runtime qualification', rows});
  assert(Object.values(rows).every(row => row.EIP170_within && row.EIP3860_within), 'Core/component/factory exceeds EVM bytecode size limit');
  console.log(target, 'bound Registry compiler gates passed');
}
assert.deepEqual(hashes, literals);
write('role-hashes.json', {hashes, byte_identical_role_digests: 16, source_manifest_sha256: sha(manifestBytes)});
write('compilation-complete.json', {complete: true, targets: ['paris', 'shanghai'], graph_size: 29,
  source_manifest_sha256: sha(manifestBytes), constructors_executed: false, operating_ready: false});
