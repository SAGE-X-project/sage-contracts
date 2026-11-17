// Finite positive normal CREATE/call controls. No RPC, signer or VM state patches.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import test from 'node:test';
import {createVM} from '@ethereumjs/vm';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createBlock} from '@ethereumjs/block';
import {createAddressFromString} from '@ethereumjs/util';
import {fixedPcObserver} from './fixed-pc-observer.mjs';

assert.equal(process.version, 'v24.4.1');
assert.equal(process.env.NODE_OPTIONS ?? '', '');
assert.equal(process.env.DEBUG ?? '', '');
const here = new URL('./', import.meta.url);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const hex = value => Buffer.from(value).toString('hex');
const bin = value => { assert(/^(?:[0-9a-f]{2})*$/.test(value)); return Buffer.from(value, 'hex'); };
const source = fs.readFileSync(new URL('evidence/subjects.json', here));
const subjects = JSON.parse(source);
const quiet = vm => {
  assert.equal(vm.evm.DEBUG, false);
  for (const name of ['step', 'beforeMessage', 'afterMessage']) assert.equal(vm.evm.events.listenerCount(name), 0);
};
const serialize = result => ({exception: result.execResult.exceptionError?.error ?? null,
  return_hex: hex(result.execResult.returnValue), gas: result.execResult.executionGasUsed.toString(),
  logs: (result.execResult.logs ?? []).map(([address, topics, data]) => ({address: hex(address), topics: topics.map(hex), data: hex(data)}))});
assert.equal(subjects.parts.length, 7);
for (const part of subjects.parts) {
  test('normal source controls: ' + part.id, {timeout: 180000}, async () => {
    const common = new Common({chain: Mainnet, hardfork: part.profile === 'paris' ? Hardfork.Paris : Hardfork.Shanghai});
    const vm = await createVM({common}); quiet(vm);
    const caller = createAddressFromString(part.caller);
    const modules = new Map(part.modules.map(module => [module.id, module]));
    const addresses = new Map();
    const result = {id: part.id, profile: part.profile, subject_sha256: sha(source), deployments: [], modules: [], setup: [], calls: [],
      complete: false, constructor_pc_observed: false, production_coverage_qualified: false, operating_ready: false};
    const persist = () => fs.writeFileSync(new URL('evidence/' + part.id + '-prefix.json', here), JSON.stringify(result, null, 2) + '\n');
    for (const call of part.deployments) {
      assert.equal((await vm.stateManager.getAccount(caller))?.nonce ?? 0n, BigInt(result.deployments.length));
      const rawResult = await vm.evm.runCall({caller, origin: caller, data: bin(call.data), gasLimit: 100000000n, value: 0n});
      const raw = serialize(rawResult), address = rawResult.createdAddress?.toString() ?? null;
      result.deployments.push({id: call.id, address, creation_sha256: sha(bin(call.data)), raw}); persist();
      assert.equal(raw.exception, null); assert.deepEqual(raw.logs, []); assert(address && /^0x[0-9a-f]{40}$/.test(address));
      assert.equal((await vm.stateManager.getAccount(caller)).nonce, BigInt(result.deployments.length));
      assert.equal(raw.return_hex, modules.get(call.id).images.runtime.hex);
      if (call.expected_address) assert.equal(address, call.expected_address);
      assert(![...addresses.values()].includes(address)); addresses.set(call.id, address); quiet(vm);
    }
    const images = [];
    for (const module of part.modules) {
      const address = module.address ?? addresses.get(module.id);
      assert(address); addresses.set(module.id, address);
      const code = Buffer.from(await vm.stateManager.getCode(createAddressFromString(address)));
      assert.equal(hex(code), module.images.runtime.hex); assert.equal(sha(code), module.images.runtime.sha256);
      result.modules.push({id: module.id, address, code_bytes: code.length, code_sha256: sha(code)});
      images.push({id: module.id, kind: 'runtime', address, code, code_sha256: sha(code)});
    }
    const unchanged = async () => {
      for (const image of images) assert.equal(sha(await vm.stateManager.getCode(createAddressFromString(image.address))), image.code_sha256);
    };
    const request = fixture => {
      const actor = createAddressFromString(fixture.sender ?? part.caller);
      const value = {caller: actor, origin: actor, to: createAddressFromString(fixture.to ?? addresses.get(fixture.module_id)),
        data: bin(fixture.input_hex), gasLimit: 100000000n, value: 0n};
      if (fixture.block !== undefined) value.block = createBlock({header: {number: BigInt(fixture.block),
        timestamp: BigInt(fixture.timestamp), gasLimit: 100000000n, baseFeePerGas: 1n}}, {common});
      assert.equal(sha(value.data), fixture.input_sha256);
      return value;
    };
    const check = (raw, fixture) => {
      assert.equal(raw.exception, fixture.expected_exception);
      assert.equal(raw.return_hex, fixture.expected_return_hex); assert.deepEqual(raw.logs, fixture.expected_logs);
    };
    for (const fixture of part.setup) {
      quiet(vm); const raw = serialize(await vm.evm.runCall(request(fixture))); quiet(vm);
      result.setup.push({name: fixture.name, raw}); persist(); check(raw, fixture); await unchanged();
    }
    const cases = [...part.calls];
    if (part.role_selector) {
      for (const fork of ['shanghai', 'paris']) {
        const roles = part.role_names.map(name => addresses.get(fork + '-' + name));
        assert.equal(new Set(roles).size, 8); assert(roles.every(address => /^0x[0-9a-f]{40}$/.test(address)));
        const input = part.role_selector + roles.map(address => address.slice(2).padStart(64, '0')).join('');
        cases.push({name: 'actual-role-set-' + fork, method: 'acceptsRoles', module_id: 'SemanticHelperControls',
          observe: true, input_hex: input, input_sha256: sha(bin(input)), expected_return_hex: '0'.repeat(63) + '1',
          expected_exception: null, expected_logs: [], role_addresses: roles, role_code_profile: fork});
      }
    }
    assert.equal(cases.length, part.expected_calls);
    const parity = new Map();
    for (const fixture of cases) {
      let observer, pc = null, rawResult;
      try {
        if (fixture.observe) { observer = fixedPcObserver(vm.evm, images); observer.begin(part.id + ':' + fixture.name); }
        rawResult = await vm.evm.runCall({...request(fixture), isStatic: true});
        if (observer) { pc = observer.finish(); assert(pc.complete && pc.failure === null); }
      } finally { if (observer) observer.close(); }
      quiet(vm);
      const raw = serialize(rawResult); result.calls.push({fixture, raw, pc}); persist(); check(raw, fixture);
      const module = modules.get(fixture.module_id);
      const outcome = {exception: raw.exception, return_hex: raw.return_hex, logs: raw.logs};
      if (module.build === 'product') parity.set(module.contract + ':' + fixture.name, outcome);
      if (module.build === 'control') assert.deepEqual(outcome, parity.get(module.contract + ':' + fixture.name));
      await unchanged();
    }
    assert.equal(result.calls.length, part.expected_calls); result.complete = true;
    fs.writeFileSync(new URL('evidence/' + part.id + '-result.json', here), JSON.stringify(result, null, 2) + '\n', {flag: 'wx'});
    console.log(JSON.stringify({part: part.id, normal_creates: result.deployments.length, setup_calls: result.setup.length,
      static_calls: result.calls.length, constructors_observed: false, operating_ready: false}));
  });
}
