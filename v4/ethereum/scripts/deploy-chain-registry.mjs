#!/usr/bin/env node
// Deploys the SAGE 0.11.0 chain Registry (13 instances) and writes a record in
// the same shape as deployments/chain-registry-sepolia.json.
//
// Usage:
//   node scripts/deploy-chain-registry.mjs --rpc http://127.0.0.1:8545 --network anvil \
//     [--out deployments/chain-registry-anvil.json] [--allow-remote]
//
// The deployer key comes from SAGE_DEPLOYER_PRIVATE_KEY. On a local chain
// (chain ID 31337) without that variable, the well-known first Anvil/Hardhat
// test account is used. Any other chain needs --allow-remote and the variable.
// Run `python3 component-tests/chain-registry/prepare.py` first to fetch the
// pinned compiler.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {parseArgs} from 'node:util';
import {ethers} from 'ethers';

const LOCAL_CHAIN_ID = 31337n;
// Public test key #0 of Anvil and Hardhat. Never holds value on a real chain.
const LOCAL_TEST_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const COMPILER_VERSION = '0.8.20+commit.a1b79de6';
const COMPILER_SHA256 = '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657';
const PREFIX = 'ethereum/contracts/chain-registry/';
const ROLES = ['RegistryRenderer', 'RegistryEd25519', 'RegistryRules', 'RegistryCallValidator',
  'RegistryStoreFactory', 'RegistryClaimProcessorFactory', 'RegistryKeyServiceProcessorFactory',
  'RegistryLifecycleProcessorFactory'];
// Each factory creates exactly one child in the ChainRegistry constructor.
const CHILDREN = [['RegistryStoreFactory', 'RegistryStore'], ['RegistryClaimProcessorFactory', 'RegistryClaimProcessor'],
  ['RegistryKeyServiceProcessorFactory', 'RegistryKeyServiceProcessor'],
  ['RegistryLifecycleProcessorFactory', 'RegistryLifecycleProcessor']];

const ethereumDir = new URL('../', import.meta.url);
const repoDir = new URL('../', ethereumDir);
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function parseOptions(argv) {
  const {values} = parseArgs({args: argv, options: {
    rpc: {type: 'string'}, network: {type: 'string'}, out: {type: 'string'},
    'allow-remote': {type: 'boolean', default: false}}});
  if (!values.rpc || !values.network) throw new Error('--rpc and --network are required');
  if (!/^[a-z0-9-]+$/.test(values.network)) throw new Error('--network must be lowercase letters, digits or -');
  return {...values, out: values.out ?? `deployments/chain-registry-${values.network}.json`};
}

// Reads the 29 Registry sources through the component-test manifest so the
// compiled bytes match the sources the tests pin.
function readSources() {
  const manifest = JSON.parse(fs.readFileSync(new URL('component-tests/chain-registry/runtime/source-identities.json', ethereumDir)));
  const names = Object.keys(manifest.source_files_sha256).filter(path => path.endsWith('.sol')).sort();
  assert.equal(names.length, 29, 'unexpected Registry source count');
  return Object.fromEntries(names.map(path => {
    assert(path.startsWith(PREFIX) && !path.split('/').includes('..'), path);
    const bytes = fs.readFileSync(new URL(path, repoDir));
    assert.equal(sha256(bytes), manifest.source_files_sha256[path], `source changed: ${path}`);
    return [path, {content: bytes.toString('utf8')}];
  }));
}

function compile(sources) {
  const compilerPath = new URL('component-tests/chain-registry/evidence/soljson.cjs', ethereumDir);
  if (!fs.existsSync(compilerPath)) throw new Error('compiler missing; run python3 component-tests/chain-registry/prepare.py');
  assert.equal(sha256(fs.readFileSync(compilerPath)), COMPILER_SHA256, 'compiler identity mismatch');
  const solc = createRequire(import.meta.url)(compilerPath.pathname);
  const input = {language: 'Solidity', sources, settings: {optimizer: {enabled: true, runs: 200}, viaIR: true,
    evmVersion: 'shanghai', metadata: {bytecodeHash: 'ipfs', appendCBOR: true},
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object']}}}};
  const output = JSON.parse(solc.cwrap('solidity_compile', 'string', ['string', 'number', 'number'])(JSON.stringify(input), 0, 0));
  const errors = (output.errors ?? []).filter(error => error.severity === 'error');
  if (errors.length) throw new Error(errors.map(error => error.formattedMessage).join('\n'));
  const artifacts = {};
  for (const contracts of Object.values(output.contracts)) {
    for (const [name, artifact] of Object.entries(contracts)) artifacts[name] = artifact;
  }
  for (const name of [...ROLES, 'ChainRegistry', ...CHILDREN.map(row => row[1])]) assert(artifacts[name], `missing ${name}`);
  return artifacts;
}

async function deployerFor(provider, chainId, allowRemote) {
  const configured = process.env.SAGE_DEPLOYER_PRIVATE_KEY;
  if (chainId !== LOCAL_CHAIN_ID) {
    if (!allowRemote) throw new Error(`chain ${chainId} is not local; pass --allow-remote after approval`);
    if (!configured) throw new Error('SAGE_DEPLOYER_PRIVATE_KEY is required on a remote chain');
  }
  return new ethers.Wallet(configured ?? LOCAL_TEST_KEY, provider);
}

async function create(wallet, nonce, name, artifact, args) {
  const factory = new ethers.ContractFactory(artifact.abi, '0x' + artifact.evm.bytecode.object, wallet);
  const transaction = await factory.getDeployTransaction(...args);
  const sent = await wallet.sendTransaction({...transaction, nonce});
  const receipt = await sent.wait();
  if (receipt.status !== 1) throw new Error(`${name} creation failed`);
  console.log(`${name}: ${receipt.contractAddress} gas ${receipt.gasUsed}`);
  return {name, nonce, hash: receipt.hash, contract_address: receipt.contractAddress.toLowerCase(),
    block_number: receipt.blockNumber, block_hash: receipt.blockHash, status: '0x1',
    gas_used: Number(receipt.gasUsed), effective_gas_price_wei: receipt.gasPrice.toString(),
    fee_wei: (receipt.gasUsed * receipt.gasPrice).toString()};
}

async function codeRecord(provider, name, address, blockTag) {
  const code = await provider.getCode(address, blockTag);
  if (code === '0x') throw new Error(`no code at ${name} ${address}`);
  return {name, address, code_sha256: sha256(Buffer.from(code.slice(2), 'hex'))};
}

// Compares runtime hashes with the Sepolia record. Contracts without
// address-dependent immutables must match byte for byte.
function compareWithSepolia(contracts) {
  const path = new URL('deployments/chain-registry-sepolia.json', ethereumDir);
  const sepolia = new Map(JSON.parse(fs.readFileSync(path)).contracts.map(row => [row.name, row.code_sha256]));
  return Object.fromEntries(contracts.map(row => [row.name, sepolia.get(row.name) === row.code_sha256]));
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const out = new URL(options.out, ethereumDir);
  if (fs.existsSync(out)) throw new Error(`refusing to overwrite ${options.out}`);
  const artifacts = compile(readSources());
  const provider = new ethers.JsonRpcProvider(options.rpc, undefined, {staticNetwork: true});
  const chainId = (await provider.getNetwork()).chainId;
  const wallet = await deployerFor(provider, chainId, options['allow-remote']);

  // ethers caches nonce lookups briefly, so the script counts nonces itself.
  let nonce = await wallet.getNonce('latest');
  const transactions = [];
  for (const name of ROLES) transactions.push(await create(wallet, nonce++, name, artifacts[name], []));
  const roleAddress = Object.fromEntries(transactions.map(row => [row.name, row.contract_address]));
  transactions.push(await create(wallet, nonce++, 'ChainRegistry', artifacts.ChainRegistry, ROLES.map(name => roleAddress[name])));
  const registry = transactions.at(-1);
  const blockTag = registry.block_number;

  const instances = [...transactions.map(row => [row.name, row.contract_address]),
    ...CHILDREN.map(([factory, child]) => [child, ethers.getCreateAddress({from: roleAddress[factory], nonce: 1}).toLowerCase()])];
  const contracts = [];
  for (const [name, address] of instances) contracts.push(await codeRecord(provider, name, address, blockTag));

  const registryId = await new ethers.Contract(registry.contract_address, artifacts.ChainRegistry.abi, provider)
    .registryId({blockTag});
  const expectedId = `eip155:${chainId}:${registry.contract_address}`;
  if (registryId !== expectedId) throw new Error(`registryId ${registryId} != ${expectedId}`);

  const sepoliaRecord = JSON.parse(fs.readFileSync(new URL('deployments/chain-registry-sepolia.json', ethereumDir)));
  const record = {
    network: options.network, chain_id: Number(chainId),
    protocol_profile: sepoliaRecord.protocol_profile,
    deployment_date_utc: new Date().toISOString().slice(0, 10),
    source_commit: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: repoDir, encoding: 'utf8'}).trim(),
    source_dirty: execFileSync('git', ['status', '--porcelain', '--', PREFIX], {cwd: repoDir, encoding: 'utf8'}).trim() !== '',
    spec_commit: sepoliaRecord.spec_commit,
    compiler: {version: COMPILER_VERSION, evm_version: 'shanghai', via_ir: true, optimizer_runs: 200},
    client_version: await provider.send('web3_clientVersion', []),
    deployer: wallet.address.toLowerCase(),
    registry_address: registry.contract_address,
    registry_id: registryId,
    contracts,
    runtime_matches_sepolia: compareWithSepolia(contracts),
    transactions,
  };
  fs.writeFileSync(out, JSON.stringify(record, null, 2) + '\n', {flag: 'wx'});
  console.log(`${registryId} written to ${options.out}`);
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
