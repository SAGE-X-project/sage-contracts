// Ordinary signatures with a disclosed test-only seed. No secret/user/network inputs.
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const raw = value => Buffer.from(value, 'hex');
const key = crypto.createPrivateKey({key: Buffer.concat([raw('302e020100300506032b657004220420'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8'});
const publicKey = crypto.createPublicKey(key), publicBytes = publicKey.export({type: 'spki', format: 'der'}).subarray(-32);
const rows = [];
const add = (name, message, expected, fields) => {
  const signature = crypto.sign(null, message, key);
  assert(crypto.verify(null, message, publicKey, signature));
  rows.push({name, group: 'owned-normal-runtime', contract: 'RegistryEd25519', method: 'verify(bytes,bytes,bytes)', key: publicBytes.toString('hex'), message: message.toString('hex'), signature: signature.toString('hex'), expected, ...(fields ? {pop_fields: fields.map(value => value.toString('hex'))} : {})});
};
for (const length of [292, 293]) add('owned-binary-' + length, Buffer.from(Array.from({length}, (_, i) => (i * 17) % 256)), length === 292);
const registry = Buffer.from('eip155:' + '9'.repeat(32) + ':0x' + '0'.repeat(39) + '1');
assert.equal(registry.length, 82);
for (const [algorithm, material] of [['ed25519', publicBytes], ['x25519', Buffer.alloc(32, 9)]]) {
  const fields = [registry, Buffer.from('a'.repeat(64)), Buffer.from('s'.repeat(32)), Buffer.from(algorithm), material];
  const framed = fields.map(value => { const length = Buffer.alloc(2); length.writeUInt16BE(value.length); return Buffer.concat([length, value]); });
  add('owned-pop-' + algorithm, Buffer.concat([Buffer.from('sage-pop-0.11.0'), ...framed]), true, fields);
}
fs.writeFileSync(new URL('owned-cases.json', import.meta.url), JSON.stringify({scope: 'Owned ordinary signatures; raw verifier controls, not Registry admission, KEM possession or handshake', cases: rows}, null, 2) + '\n');
