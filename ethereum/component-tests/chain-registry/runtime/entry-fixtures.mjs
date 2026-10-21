// Fixed ordinary owned unit fixtures only; no caller-selected signing service.
// No RPC, external keys, signature corruption or cryptographic search.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {ownedKey} from './owned-fixtures.mjs';

const sha256 = value => crypto.createHash('sha256').update(value).digest();
const prefixed = value => {
  const bytes = Buffer.from(value), prefix = Buffer.alloc(2);
  assert(bytes.length <= 65535);
  prefix.writeUInt16BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
};

export function entryFixtures(registry, agent) {
  assert.equal(agent, 'owned-entry-targets');
  assert(/^eip155:[1-9][0-9]*:0x[0-9a-f]{40}$/.test(registry));
  const normal = (name, options) => ownedKey(registry, agent, name, options);
  // KEM material and its legitimate signing key have separate fixed indices.
  // The shared helper deliberately couples these indices; keep its old callers
  // unchanged and construct these four disclosed unit fixtures separately.
  const endorsement = (name, materialIndex, signerIndex, signerName) => {
    assert([3, 4].includes(materialIndex) && [0, 1, 3].includes(signerIndex));
    const fixedSecret = (index, kem) => crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from(kem ? '302e020100300506032b656e04220420' : '302e020100300506032b657004220420', 'hex'),
        sha256(Buffer.from('SAGE owned constructor unit public key recipe ' + index + ' ' + kem))
      ]), format: 'der', type: 'pkcs8'
    });
    const signer = fixedSecret(signerIndex, false);
    const signerPublic = crypto.createPublicKey(signer);
    const key = crypto.createPublicKey(fixedSecret(materialIndex, true))
      .export({type: 'spki', format: 'der'}).subarray(-32);
    const challenge = Buffer.concat([Buffer.from('sage-pop-0.11.0'),
      ...[registry, agent, name, 'x25519', key].map(prefixed)]);
    assert(challenge.length <= 292);
    const proof = crypto.sign(null, challenge, signer);
    assert(crypto.verify(null, challenge, signerPublic, proof));
    return {input: {name, alg: 'x25519', key,
      signer: 'did:sage:' + registry + ':' + agent + '#' + signerName,
      proof, hasExpiry: false, expires: 0n}, challenge,
      signerKey: signerPublic.export({type: 'spki', format: 'der'}).subarray(-32)};
  };
  const fixtures = {
    expired: normal('e-expired', {index: 3, expires: 0}),
    added: normal('m-add', {index: 1}),
    kemAdded: normal('n-kem', {index: 1, kem: true, signerName: 'm-add'}),
    service: normal('svc', {index: 2}),
    guard: normal('g-ed', {index: 4}),
    initial: normal('z-sign', {index: 0}),
    reusedInitial: normal('m-copy', {index: 0}),
    reusedAdded: normal('w-copy', {index: 1}),
    kemGuard: endorsement('g-kem', 4, 0, 'z-sign'),
    kemExpired: endorsement('g-exp', 3, 3, 'e-expired'),
    kemRevokedAdded: endorsement('g-rev-m', 3, 1, 'm-add'),
    kemRevokedInitial: endorsement('g-rev-z', 3, 0, 'z-sign')
  };
  const retained = ['expired', 'added', 'kemAdded', 'service', 'initial']
    .map(name => fixtures[name].input.key.toString('hex'));
  retained.push(normal('a-kem', {index: 0, kem: true, signerName: 'z-sign'}).input.key.toString('hex'));
  assert.equal(new Set(retained).size, 6);
  for (const name of ['guard', 'kemGuard', 'kemExpired', 'kemRevokedAdded', 'kemRevokedInitial']) {
    assert(!retained.includes(fixtures[name].input.key.toString('hex')));
  }
  assert(fixtures.reusedInitial.input.key.equals(fixtures.initial.input.key));
  assert(fixtures.reusedAdded.input.key.equals(fixtures.added.input.key));
  assert(fixtures.kemGuard.signerKey.equals(fixtures.initial.input.key));
  assert(fixtures.kemExpired.signerKey.equals(fixtures.expired.input.key));
  assert(fixtures.kemRevokedAdded.signerKey.equals(fixtures.added.input.key));
  assert(fixtures.kemRevokedInitial.signerKey.equals(fixtures.initial.input.key));
  return fixtures;
}
