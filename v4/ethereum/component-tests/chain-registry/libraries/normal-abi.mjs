// Unit-only normal ABI encoding. No invalid-call generator or submission path.
import assert from 'node:assert/strict';
import {keccak_256} from '@noble/hashes/sha3.js';
export const word = value => {
  const integer = BigInt(value);
  assert(integer >= 0n && integer < (1n << 256n));
  return Buffer.from(integer.toString(16).padStart(64, '0'), 'hex');
};
const dynamic = type => ['string', 'bytes'].includes(type.type) || type.type.endsWith('[]') || type.type.startsWith('tuple');
const pad = bytes => Buffer.concat([bytes, Buffer.alloc((32 - bytes.length % 32) % 32)]);
export const canonical = type => type.type.startsWith('tuple')
  ? '(' + type.components.map(canonical).join(',') + ')' + type.type.slice(5) : type.type;
function tuple(types, values) {
  assert.equal(types.length, values.length);
  const heads = [], tails = [];
  let offset = types.length * 32;
  for (let index = 0; index < types.length; ++index) {
    const bytes = encode(types[index], values[index]);
    if (dynamic(types[index])) { heads.push(word(offset)); tails.push(bytes); offset += bytes.length; }
    else heads.push(bytes);
  }
  return Buffer.concat([...heads, ...tails]);
}
function encode(type, value) {
  if (type.type.endsWith('[]')) {
    assert(Array.isArray(value));
    const entry = {...type, type: type.type.slice(0, -2)};
    return Buffer.concat([word(value.length), tuple(value.map(() => entry), value)]);
  }
  if (type.type === 'tuple') return tuple(type.components, type.components.map(field => value[field.name]));
  if (['string', 'bytes'].includes(type.type)) {
    const bytes = Buffer.from(value);
    return Buffer.concat([word(bytes.length), pad(bytes)]);
  }
  if (type.type === 'address') { assert(/^0x[0-9a-f]{40}$/.test(value)); return word(BigInt(value)); }
  if (type.type === 'bool') { assert.equal(typeof value, 'boolean'); return word(value ? 1 : 0); }
  if (/^uint\d+$/.test(type.type)) { const number = BigInt(value); assert(number >= 0n && number < (1n << BigInt(type.type.slice(4)))); return word(number); }
  assert(/^bytes\d+$/.test(type.type));
  const bytes = Buffer.from(value); assert.equal(bytes.length, Number(type.type.slice(5))); return pad(bytes);
}
export const selector = signature => Buffer.from(keccak_256(Buffer.from(signature))).subarray(0, 4);
export function call(abi, name, values) {
  const methods = abi.filter(entry => entry.type === 'function' && entry.name === name);
  assert.equal(methods.length, 1);
  const method = methods[0];
  return Buffer.concat([selector(name + '(' + method.inputs.map(canonical).join(',') + ')'), tuple(method.inputs, values)]);
}
