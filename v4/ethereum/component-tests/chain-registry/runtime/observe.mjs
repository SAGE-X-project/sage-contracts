// Read-only local VM observations for owned unit cases. No write, RPC, signing,
// caller impersonation, code installation, transaction or Source implementation.
import assert from 'node:assert/strict';
import {keccak_256} from '@noble/hashes/sha3.js';

const mask = (1n << 256n) - 1n;
const word = value => Buffer.from((BigInt(value) & mask).toString(16).padStart(64, '0'), 'hex');
const hash = bytes => BigInt('0x' + Buffer.from(keccak_256(bytes)).toString('hex'));
const add = (base, offset) => (base + BigInt(offset)) & mask;
const addressNumber = value => { assert(/^0x[0-9a-f]{40}$/.test(value)); return BigInt(value); };

export function assertStoreLayout(layout) {
  const primitive = (encoding, numberOfBytes, label) => ({encoding, bytes: numberOfBytes, label});
  const bool = primitive('inplace', 1, 'bool'), address = primitive('inplace', 20, 'address');
  const u64 = primitive('inplace', 8, 'uint64'), uint = primitive('inplace', 32, 'uint256');
  const bytes32 = primitive('inplace', 32, 'bytes32');
  const string = primitive('bytes', 32, 'string'), bytes = primitive('bytes', 32, 'bytes');
  const enumeration = name => primitive('inplace', 1, 'enum RegistryJson.' + name);
  const field = (label, slot, offset, type) => ({label, slot: String(slot), offset, type});
  const structure = (name, size, members) => ({encoding: 'inplace', bytes: size, label: 'struct ' + name, members});
  const array = base => ({encoding: 'dynamic_array', bytes: 32, base});
  const mapping = (key, value) => ({encoding: 'mapping', bytes: 32, key, value});
  const keyInput = structure('IChainRegistry.KeyInput', 192, [field('name',0,0,string),field('alg',1,0,string),field('key',2,0,bytes),
    field('signer',3,0,string),field('proof',4,0,bytes),field('hasExpiry',5,0,bool),field('expires',5,1,u64)]);
  const key = structure('RegistryJson.Key',224,[field('input',0,0,keyInput),field('state',6,0,enumeration('KeyState'))]);
  const service = structure('IChainRegistry.ServiceInput',96,[field('name',0,0,string),field('serviceType',1,0,string),field('uri',2,0,string)]);
  const record = structure('RegistryJson.Record',160,[field('did',0,0,string),field('controller',1,0,address),field('keys',2,0,array(key)),
    field('services',3,0,array(service)),field('state',4,0,enumeration('RecordState')),field('version',4,1,u64)]);
  const grant = structure('RegistryJson.Grant',64,[field('operator',0,0,address),field('scope',1,0,string)]);
  const retained = structure('RegistryStore.Retained',96,[field('present',0,0,bool),field('history',1,0,bytes),field('command',2,0,bytes)]);
  const stored = structure('RegistryStore.Stored',352,[field('present',0,0,bool),field('value',1,0,record),field('grants',6,0,array(grant)),
    field('admitted',7,0,u64),field('canonicalRecord',8,0,bytes),field('canonicalGrants',9,0,bytes),field('items',10,0,mapping(u64,retained))]);
  const claim = structure('RegistryStore.Claim',64,[field('present',0,0,bool),field('consumed',0,1,bool),field('committed',1,0,uint)]);
  const normalize = id => {
    const type = layout.types[id]; assert(type);
    const out = {encoding: type.encoding, bytes: Number(type.numberOfBytes)};
    if (type.members) { out.label = type.label; out.members = type.members.map(member => field(member.label,member.slot,member.offset,normalize(member.type))); }
    else if (type.encoding === 'mapping') { out.key = normalize(type.key); out.value = normalize(type.value); }
    else if (type.encoding === 'dynamic_array') out.base = normalize(type.base);
    else out.label = type.label;
    return out;
  };
  assert.deepEqual(layout.storage.map(member => field(member.label,member.slot,member.offset,normalize(member.type))),
    [field('identity',0,0,string),field('claims',1,0,mapping(address,mapping(bytes32,claim))),field('records',2,0,mapping(string,stored))]);
  return {store_slots:3, claim_bytes:64, retained_bytes:96, stored_bytes:352, record_bytes:160, key_input_bytes:192, key_bytes:224, service_bytes:96, grant_bytes:64};
}

function reader(vm, store, context, onRead) {
  assert.equal(typeof onRead, 'function');
  let count = 0; const observations = [];
  const read = async slot => {
    const value = Buffer.from(await vm.stateManager.getStorage(store, word(slot)));
    assert(value.length <= 32);
    const normalized = Buffer.concat([Buffer.alloc(32-value.length),value]);
    const entry = {...context,store:store.toString(),read_index:count++,slot_hex:word(slot).toString('hex'),value_hex:normalized.toString('hex')};
    observations.push(entry); onRead(entry); // Persist the raw read BEFORE any assertion, including failed prefixes.
    return normalized;
  };
  const exactWord = async (slot, expected) => assert.equal((await read(slot)).toString('hex'),word(expected).toString('hex'));
  const exactBytes = async (slot, expected) => {
    expected = Buffer.from(expected);
    const first = await read(slot);
    if (expected.length <= 31) {
      const short = Buffer.alloc(32); expected.copy(short); short[31] = 2 * expected.length;
      assert.equal(first.toString('hex'),short.toString('hex')); return;
    }
    assert.equal(first.toString('hex'),word(2n*BigInt(expected.length)+1n).toString('hex'));
    const base = hash(word(slot));
    for (let offset=0;offset<expected.length;offset+=32) {
      const chunk = Buffer.alloc(32); expected.subarray(offset,offset+32).copy(chunk);
      assert.equal((await read(add(base,offset/32))).toString('hex'),chunk.toString('hex'));
    }
  };
  return {exactWord,exactBytes,count:()=>count,observations:()=>observations};
}

export async function observeClaim(vm, store, actor, digest, expected, onRead) {
  assert(Buffer.from(digest).length === 32);
  const r = reader(vm,store,{observer:'claim',actor,digest_hex:Buffer.from(digest).toString('hex')},onRead), actorSlot = hash(Buffer.concat([word(addressNumber(actor)),word(1n)]));
  const slot = hash(Buffer.concat([Buffer.from(digest),word(actorSlot)]));
  await r.exactWord(slot,(expected.present?1n:0n)|(expected.consumed?256n:0n));
  await r.exactWord(add(slot,1),expected.committed);
  return {scope:'Read-only owned unit claim storage; not Source',slot:word(slot).toString('hex'),reads:r.count(),raw_read_policy:'read_order_including_duplicates',raw_slot_reads:r.observations()};
}

export async function observeRecord(vm, store, identity, agentId, expected, onRead) {
  const r = reader(vm,store,{observer:'record',agent_id:agentId},onRead), slot = hash(Buffer.concat([Buffer.from(agentId,'utf8'),word(2n)]));
  await r.exactBytes(0n,Buffer.from(identity,'utf8'));
  await r.exactWord(slot,expected===null?0n:1n);
  if (expected===null) return {scope:'Read-only owned unit absent record; not Source',reads:r.count(),raw_read_policy:'read_order_including_duplicates',raw_slot_reads:r.observations()};
  const recordBytes = Buffer.from(expected.record), grantsBytes = Buffer.from(expected.grants);
  const record = JSON.parse(recordBytes), grants = JSON.parse(grantsBytes);
  assert(record.id==='did:sage:'+identity+':'+agentId);
  assert(record.keys.length<=128&&record.services.length<=16&&grants.length<=128);
  await r.exactBytes(add(slot,1),Buffer.from(record.id));
  await r.exactWord(add(slot,2),addressNumber(record.controller));
  await r.exactWord(add(slot,3),record.keys.length);
  const keyBase = hash(word(add(slot,3)));
  for (const [index,key] of record.keys.entries()) {
    const start = add(keyBase,index*7);
    for (const [offset,value] of [[0,Buffer.from(key.name)],[1,Buffer.from(key.alg)],[2,Buffer.from(key.key,'base64url')],
      [3,Buffer.from(key.proof.signer)],[4,Buffer.from(key.proof.value,'base64url')]]) await r.exactBytes(add(start,offset),value);
    const expiry = Object.hasOwn(key,'expires');
    await r.exactWord(add(start,5),(expiry?1n:0n)|((expiry?BigInt(key.expires):0n)<<8n));
    assert(['accepted','revoked'].includes(key.state)); await r.exactWord(add(start,6),key.state==='accepted'?0n:1n);
  }
  await r.exactWord(add(slot,4),record.services.length);
  const serviceBase = hash(word(add(slot,4)));
  for (const [index,service] of record.services.entries()) {
    for (const [offset,value] of [[0,service.name],[1,service.type],[2,service.uri]]) await r.exactBytes(add(serviceBase,index*3+offset),Buffer.from(value));
  }
  const state = ['created','active','deactivated'].indexOf(record.state); assert(state>=0);
  await r.exactWord(add(slot,5),BigInt(state)|(BigInt(record.version)<<8n));
  await r.exactWord(add(slot,6),grants.length);
  const grantBase = hash(word(add(slot,6)));
  for (const [index,grant] of grants.entries()) {
    await r.exactWord(add(grantBase,index*2),addressNumber(grant.operator));
    await r.exactBytes(add(grantBase,index*2+1),Buffer.from(grant.scope));
  }
  await r.exactWord(add(slot,7),expected.admitted);
  await r.exactBytes(add(slot,8),recordBytes); await r.exactBytes(add(slot,9),grantsBytes);
  for (const item of expected.history) {
    const base = hash(Buffer.concat([word(item.version),word(add(slot,10))]));
    await r.exactWord(base,1n); await r.exactBytes(add(base,1),item.history); await r.exactBytes(add(base,2),item.command);
  }
  return {scope:'Read-only owned unit fullStore current/retained storage; not Source',stored_slot:word(slot).toString('hex'),reads:r.count(),
    keys:record.keys.length,services:record.services.length,grants:grants.length,retained_versions:expected.history.length,
    raw_read_policy:'read_order_including_duplicates',raw_slot_reads:r.observations()};
}
