// Owned ordinary test signatures. Disclosed fixed test seeds only; no user keys,
// secret inputs, malformed producer, network client or submission path.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

export const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest();
export const base64url = bytes => Buffer.from(bytes).toString('base64url');
export const senderTestSeed = index => sha256(Buffer.from('SAGE owned constructor unit sender public recipe ' + index));
export function jcs(value) {
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => jcs(key) + ':' + jcs(value[key])).join(',') + '}';
  }
  assert(['string', 'number', 'boolean'].includes(typeof value) || value === null);
  if (typeof value === 'string') assert([...value].every(character => character.charCodeAt(0) <= 127));
  if (typeof value === 'number') assert(Number.isSafeInteger(value));
  return JSON.stringify(value);
}

function secret(index, kem = false) {
  const prefix = kem ? '302e020100300506032b656e04220420' : '302e020100300506032b657004220420';
  const seed = sha256(Buffer.from('SAGE owned constructor unit public key recipe ' + index + ' ' + kem));
  return crypto.createPrivateKey({key: Buffer.concat([Buffer.from(prefix, 'hex'), seed]), format: 'der', type: 'pkcs8'});
}

function lengthPrefixed(value) {
  const bytes = Buffer.from(value), length = Buffer.alloc(2);
  assert(bytes.length <= 65535);
  length.writeUInt16BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

export function ownedKey(registry, agentId, name, {index = 0, kem = false, signerName = name, expires = null} = {}) {
  assert(/^eip155:[1-9][0-9]*:0x[0-9a-f]{40}$/.test(registry));
  assert(/^[a-z0-9][a-z0-9._-]{0,63}$/.test(agentId));
  const signerSecret = secret(index), signerPublic = crypto.createPublicKey(signerSecret);
  const materialPublic = kem ? crypto.createPublicKey(secret(index, true)) : signerPublic;
  const key = materialPublic.export({type: 'spki', format: 'der'}).subarray(-32);
  const alg = kem ? 'x25519' : 'ed25519';
  const challenge = Buffer.concat([Buffer.from('sage-pop-0.11.0'), ...[registry, agentId, name, alg, key].map(lengthPrefixed)]);
  assert(challenge.length <= 292);
  const proof = crypto.sign(null, challenge, signerSecret);
  assert(crypto.verify(null, challenge, signerPublic, proof));
  const input = {name, alg, key, signer: 'did:sage:' + registry + ':' + agentId + '#' + signerName, proof, hasExpiry: expires !== null, expires: BigInt(expires ?? 0)};
  return {input, challenge, signerKey: signerPublic.export({type: 'spki', format: 'der'}).subarray(-32)};
}

export function publicKey(input, state = 'accepted') {
  return {...(input.hasExpiry ? {expires: Number(input.expires)} : {}), name: input.name, alg: input.alg, key: base64url(input.key), proof: {signer: input.signer, value: base64url(input.proof)}, state};
}

export const publicServices = values => values.map(({name, serviceType, uri}) => ({name, type: serviceType, uri}));
export function initialFixture(registry, agentId, controller) {
  const signing = ownedKey(registry, agentId, 'z-sign');
  const kem = ownedKey(registry, agentId, 'a-kem', {kem: true, signerName: signing.input.name});
  // KEM sorts before its signer: acceptance must still use the same record's
  // eligible signing key and complete signing verification before endorsements.
  const keys = [kem.input, signing.input];
  const services = [{name: 'svc', serviceType: 'fixture"\\', uri: 'https://example.invalid/owned/'}];
  const salt = sha256(Buffer.from('SAGE owned constructor unit public reveal salt ' + registry + ':' + agentId + ':' + controller));
  const record = {controller, id: 'did:sage:' + registry + ':' + agentId, keys: keys.map(input => publicKey(input)), services: publicServices(services), state: 'created', version: '1'};
  const claim = {registryId: registry, agentId, controller, keys: record.keys, services: record.services, salt: base64url(salt)};
  const commitment = sha256(Buffer.concat([Buffer.from('sage-claim-0.11.0'), Buffer.from([0]), Buffer.from(jcs(claim))]));
  return {keys, services, salt, record, claim, commitment, challenges: [kem.challenge, signing.challenge]};
}
