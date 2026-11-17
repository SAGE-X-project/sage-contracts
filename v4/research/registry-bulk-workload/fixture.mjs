// Ordinary public test fixture only. No Registry, network or transaction.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';


const ascii = s => Buffer.from(s, 'ascii');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const json = value => {
  if (Array.isArray(value)) return '[' + value.map(json).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + json(value[k])).join(',') + '}';
  return JSON.stringify(value);
};
export function fixture() {
const registry = 'eip155:' + '9'.repeat(32) + ':0x' + '1'.repeat(40);
const agent = 'a'.repeat(64), did = 'did:sage:' + registry + ':' + agent;
assert.equal(registry.length, 82); assert.equal(did.length, 156);
const lengthPrefixed = bytes => {
  assert(bytes.length <= 65535);
  const head = Buffer.alloc(2); head.writeUInt16BE(bytes.length); return Buffer.concat([head, bytes]);
};
const keys = [], proofs = [];
for (let i = 0; i < 128; ++i) {
  // Public deterministic test seed recipe only; never load or export credentials.
  const seed = crypto.createHash('sha256').update('SAGE ordinary bulk fixture public test seed ' + i).digest();
  const privateKey = crypto.createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8'});
  const publicKey = crypto.createPublicKey(privateKey), raw = publicKey.export({format: 'der', type: 'spki'}).subarray(-32);
  const name = 's' + String(i).padStart(31, '0');
  const challenge = Buffer.concat([ascii('sage-pop-0.10.0'), ...[ascii(registry), ascii(agent), ascii(name), ascii('Ed25519'), raw].map(lengthPrefixed)]);
  assert.equal(challenge.length, 242);
  const signature = crypto.sign(null, challenge, privateKey);
  assert(crypto.verify(null, challenge, publicKey, signature));
  assert.equal(raw.length, 32); assert.equal(signature.length, 64);
  keys.push({name, alg: 'Ed25519', key: b64(raw), proof: {signer: did + '#' + name, value: b64(signature)}, state: 'accepted'});
  proofs.push({name, key_hex: raw.toString('hex'), message_hex: challenge.toString('hex'), signature_hex: signature.toString('hex')});
}
assert.equal(new Set(keys.map(k => k.key)).size, 128);
assert.deepEqual(keys.map(k => k.name), keys.map(k => k.name).sort());
const services = Array.from({length: 16}, (_, i) => ({name: 'svc-' + String(i).padStart(2, '0'), type: 'fixture', uri: 'https://example.invalid/' + i + '/'}));
const record = {id: did, controller: '0x' + '2'.repeat(40), keys, services, state: 'created', version: '1'};
const targetBytes = 65513; // Future proposed headroom accounting; not an adopted admission.
let remaining = targetBytes - Buffer.byteLength(json(record)); assert(remaining >= 0);
for (const service of services) {
  const take = Math.min(remaining, 2048 - service.uri.length); service.uri += 'x'.repeat(take); remaining -= take;
}
assert.equal(remaining, 0); assert.equal(Buffer.byteLength(json(record)), targetBytes);
assert(services.every(s => s.uri.length <= 2048));
assert.equal(Buffer.byteLength(json({...record, state: 'deactivated', version: '18446744073709551615'})), 65536);
const result = {scope: 'ordinary owned public test data only; no registration, trusted Source, deployment or conformance verdict', message_domain: 'existing sage-pop-0.10.0 fixture; not a future binding', registry, agent_id: agent, record, record_jcs: json(record), record_sha256: sha(json(record)), proofs};
return result;
}
