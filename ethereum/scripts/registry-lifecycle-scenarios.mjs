#!/usr/bin/env node
// Runs SAGE 0.11.0 agent lifecycle scenarios against a chain Registry on a
// local chain and records, for every step, who acted, what was called, and the
// canonical record and grants before and after. The trace is the debugging
// evidence for each point where Registry data or its acting subject changes.
//
// Usage:
//   node scripts/registry-lifecycle-scenarios.mjs --rpc http://127.0.0.1:8545 \
//     --deployment deployments/chain-registry-anvil.json --out /tmp/registry-trace.json
//
// Only chain ID 31337 is accepted. Keys come from the disclosed component-test
// recipes and the public Anvil accounts; none of them holds value anywhere.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {parseArgs} from 'node:util';
import {ethers} from 'ethers';
import {ownedKey, publicKey, publicServices, jcs, base64url, sha256} from '../component-tests/chain-registry/runtime/owned-fixtures.mjs';

const ethereumDir = new URL('../', import.meta.url);
// Public Anvil accounts #1-#3. Account #0 deployed the Registry.
const ACCOUNTS = {
  controller: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  attacker: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
  operator: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
};

function options() {
  const {values} = parseArgs({options: {rpc: {type: 'string'}, deployment: {type: 'string'}, out: {type: 'string'},
    agent: {type: 'string', default: 'payment-agent'}, 'keep-active': {type: 'boolean', default: false}}});
  if (!values.rpc || !values.deployment || !values.out) throw new Error('--rpc, --deployment and --out are required');
  return values;
}

class Trace {
  constructor(registry, provider) {
    this.registry = registry;
    this.provider = provider;
    this.steps = [];
  }

  async snapshot(agentId) {
    const [present, record] = await this.registry.record(agentId);
    const grants = present ? await this.registry.activeGrants(agentId) : '0x';
    const text = present ? ethers.toUtf8String(record) : null;
    return {present, record: text, record_sha256: text && sha256(Buffer.from(text)).toString('hex'),
      grants: grants === '0x' ? null : ethers.toUtf8String(grants), version: text ? Number(JSON.parse(text).version) : 0};
  }

  // A successful step must change the record version by exactly one.
  async expectSuccess(name, actor, method, args, agentId) {
    const before = await this.snapshot(agentId);
    const contract = this.registry.connect(actor.wallet);
    const tx = await contract[method](...args);
    const receipt = await tx.wait();
    const after = await this.snapshot(agentId);
    const events = receipt.logs.map(log => {
      try { return contract.interface.parseLog(log); } catch { return null; }
    }).filter(Boolean).map(event => ({name: event.name, args: Object.fromEntries(event.fragment.inputs.map((input, i) =>
      [input.name, typeof event.args[i] === 'bigint' ? event.args[i].toString() : event.args[i]]))}));
    const changed = method === 'commitClaim' ? before.version === after.version : after.version === before.version + 1;
    const step = {step: name, expected: 'success', actor: actor.name, actor_address: actor.address, method,
      args: describe(args), tx: receipt.hash, block: receipt.blockNumber, gas_used: receipt.gasUsed.toString(),
      version_before: before.version, version_after: after.version, record_before: before.record, record_after: after.record,
      grants_before: before.grants, grants_after: after.grants, events, record_changed: before.record_sha256 !== after.record_sha256,
      result: changed ? 'PASS' : 'FAIL'};
    this.steps.push(step);
    console.log(`${step.result} ${name} v${before.version}->v${after.version}`);
    return step;
  }

  // A refused step must revert with the named error and leave the record untouched.
  async expectRefusal(name, actor, method, args, agentId, error) {
    const before = await this.snapshot(agentId);
    let observed = 'no revert';
    try {
      await this.registry.connect(actor.wallet)[method].staticCall(...args);
    } catch (failure) {
      const data = failure.data ?? failure.info?.error?.data;
      try { observed = this.registry.interface.parseError(data)?.name ?? 'unknown revert'; } catch { observed = 'unknown revert'; }
    }
    const after = await this.snapshot(agentId);
    const step = {step: name, expected: `refuse ${error}`, actor: actor.name, actor_address: actor.address, method,
      args: describe(args), observed_error: observed, version_before: before.version, version_after: after.version,
      record_changed: before.record_sha256 !== after.record_sha256,
      result: observed === error && before.record_sha256 === after.record_sha256 ? 'PASS' : 'FAIL'};
    this.steps.push(step);
    console.log(`${step.result} ${name} (${observed})`);
    return step;
  }
}

function describe(args) {
  return JSON.parse(JSON.stringify(args, (_, value) => typeof value === 'bigint' ? value.toString()
    : value instanceof Uint8Array || Buffer.isBuffer(value) ? '0x' + Buffer.from(value).toString('hex') : value));
}

function claimFor(registryId, agentId, controller, keys, services, salt) {
  const claim = {registryId, agentId, controller, keys: keys.map(input => publicKey(input)),
    services: publicServices(services), salt: base64url(salt)};
  return sha256(Buffer.concat([Buffer.from('sage-claim-0.11.0'), Buffer.from([0]), Buffer.from(jcs(claim))]));
}

async function main() {
  const args = options();
  const deployment = JSON.parse(fs.readFileSync(args.deployment));
  const abi = JSON.parse(fs.readFileSync(new URL('deployments/chain-registry-sepolia-abi.json', ethereumDir)));
  const provider = new ethers.JsonRpcProvider(args.rpc, undefined, {staticNetwork: true});
  const chainId = (await provider.getNetwork()).chainId;
  if (chainId !== 31337n || deployment.chain_id !== 31337) throw new Error('scenarios run only on chain 31337');
  const registry = new ethers.Contract(deployment.registry_address, abi, provider);
  const registryId = await registry.registryId();
  assert.equal(registryId, deployment.registry_id);
  const actors = Object.fromEntries(Object.entries(ACCOUNTS).map(([name, key]) => {
    const wallet = new ethers.NonceManager(new ethers.Wallet(key, provider));
    return [name, {name, wallet, address: new ethers.Wallet(key).address.toLowerCase()}];
  }));
  const trace = new Trace(registry, provider);
  const agent = args.agent;
  const did = `did:sage:${registryId}:${agent}`;
  const controller = actors.controller.address;
  const key = (name, index, extra = {}) => ownedKey(registryId, agent, name, {index, ...extra});

  // 1. Registration: commit, then reveal with one signing and one KEM key.
  const sig1 = key('sig-1', 101);
  const kem1 = key('kem-1', 101, {kem: true, signerName: 'sig-1'});
  const keys = [kem1.input, sig1.input];
  const services = [{name: 'a2a', serviceType: 'A2AInterface', uri: 'https://agent.example.invalid/a2a'}];
  const salt = crypto.createHash('sha256').update('scenario salt ' + agent).digest();
  const commitment = claimFor(registryId, agent, controller, keys, services, salt);
  await trace.expectSuccess('register: commit claim', actors.controller, 'commitClaim', [commitment], agent);
  await trace.expectRefusal('attack: reveal another caller\'s claim', actors.attacker, 'revealClaim',
    [agent, actors.attacker.address, keys, services, salt], agent, 'ClaimUnavailable');
  await trace.expectSuccess('register: reveal claim', actors.controller, 'revealClaim', [agent, controller, keys, services, salt], agent);
  await trace.expectRefusal('attack: reveal the same identifier again', actors.controller, 'revealClaim',
    [agent, controller, keys, services, salt], agent, 'IdentifierUnavailable');
  await trace.expectSuccess('register: activate', actors.controller, 'activate', [agent, 1n], agent);

  // 2. Metadata change and stale or foreign writers.
  await trace.expectRefusal('attack: stale expected version', actors.controller, 'updateServices', [agent, 1n, services], agent, 'PreviousVersionMismatch');
  const updated = [...services, {name: 'pay', serviceType: 'X402PaymentEndpoint', uri: 'https://agent.example.invalid/pay'}];
  await trace.expectRefusal('attack: foreign wallet updates services', actors.attacker, 'updateServices', [agent, 2n, updated], agent, 'UnauthorizedCaller');
  await trace.expectSuccess('metadata: update services', actors.controller, 'updateServices', [agent, 2n, updated], agent);
  const sig2 = key('sig-2', 102);
  await trace.expectSuccess('metadata: add signing key', actors.controller, 'addKey', [agent, 3n, sig2.input], agent);

  // 3. Key compromise: the sig-1 private key leaks, the controller wallet does not.
  const injected = key('sig-9', 109);
  await trace.expectRefusal('compromise: holder of leaked key adds own key', actors.attacker, 'addKey', [agent, 4n, injected.input], agent, 'UnauthorizedCaller');
  await trace.expectRefusal('compromise: holder of leaked key revokes the new key', actors.attacker, 'revokeKey', [agent, 4n, 'sig-2'], agent, 'UnauthorizedCaller');
  const sig3 = key('sig-3', 103);
  await trace.expectSuccess('compromise: controller adds replacement key', actors.controller, 'addKey', [agent, 4n, sig3.input], agent);
  await trace.expectSuccess('compromise: controller revokes leaked key', actors.controller, 'revokeKey', [agent, 5n, 'sig-1'], agent);
  const reused = key('sig-1b', 101);
  await trace.expectRefusal('compromise: leaked key material cannot return', actors.controller, 'addKey', [agent, 6n, reused.input], agent, 'KeyMaterialReused');
  await trace.expectRefusal('compromise: leaked key name cannot return', actors.controller, 'addKey', [agent, 6n, key('sig-1', 104).input], agent, 'KeyNameReused');
  const kem2 = key('kem-2', 103, {kem: true, signerName: 'sig-3'});
  await trace.expectSuccess('compromise: new KEM key endorsed by the replacement', actors.controller, 'addKey', [agent, 6n, kem2.input], agent);

  // 4. Delegated authority through a scoped grant.
  await trace.expectSuccess('grant: authorize revoke-key operator', actors.controller, 'authorizeOperator', [agent, 7n, actors.operator.address, 'revoke-key'], agent);
  await trace.expectRefusal('grant: operator outside its scope', actors.operator, 'updateServices', [agent, 8n, services], agent, 'UnauthorizedCaller');
  await trace.expectSuccess('grant: operator revokes a key', actors.operator, 'revokeKey', [agent, 8n, 'sig-2'], agent);
  await trace.expectSuccess('grant: controller revokes operator', actors.controller, 'revokeOperator', [agent, 9n, actors.operator.address, 'revoke-key'], agent);
  await trace.expectRefusal('grant: revoked operator acts again', actors.operator, 'revokeKey', [agent, 10n, 'sig-3'], agent, 'UnauthorizedCaller');

  // 5. Removal is terminal. --keep-active stops before it so other components
  // can verify messages signed by the agent's remaining keys.
  if (!args['keep-active']) {
    await trace.expectSuccess('remove: deactivate', actors.controller, 'deactivate', [agent, 10n], agent);
    await trace.expectRefusal('remove: reactivate after deactivation', actors.controller, 'activate', [agent, 11n], agent, 'WrongRecordState');
  }

  const history = [];
  const lastVersion = args['keep-active'] ? 10n : 11n;
  for (let version = 1n; version <= lastVersion; version++) {
    const [item, command] = await registry.historyItem(agent, version);
    history.push({version: Number(version), history: ethers.toUtf8String(item), command: ethers.toUtf8String(command)});
  }
  const failed = trace.steps.filter(step => step.result !== 'PASS');
  const out = {scope: 'Local chain scenario trace; not testnet or operating qualification', did, registry_id: registryId,
    client_version: await provider.send('web3_clientVersion', []), deployment: args.deployment,
    observations: [
      'kem-1 was endorsed by the leaked sig-1 and stays accepted after sig-1 is revoked (spec/09-registry.md); a peer must decide whether KEM keys endorsed before a compromise remain usable.',
      'The leaked signing key cannot change the Registry by itself; every change needs the controller wallet or a scoped operator. A leaked controller wallet has no recovery path in this profile.',
    ],
    passed: trace.steps.length - failed.length, failed: failed.length, steps: trace.steps, history};
  fs.writeFileSync(args.out, JSON.stringify(out, null, 2) + '\n', {flag: 'wx'});
  console.log(`${out.passed}/${trace.steps.length} steps passed; trace written to ${args.out}`);
  if (failed.length) process.exitCode = 1;
}

main().catch(error => {
  console.error(error.shortMessage ?? error.message);
  process.exitCode = 1;
});
