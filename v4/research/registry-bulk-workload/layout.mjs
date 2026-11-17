// Exact authored storage-shape checker, not a runtime Registry validator.
import assert from 'node:assert/strict';
export const positions = {
  root: [['configuredChainId',0,0],['registryId',1,0],['records',2,0],['claims',3,0]],
  Key: [['name',0,0],['alg',1,0],['material',2,0],['signer',3,0],['proof',4,0],['hasExpiry',5,0],['expires',5,1],['revoked',5,9]],
  Service: [['name',0,0],['serviceType',1,0],['uri',2,0]],
  Grant: [['operator',0,0],['scope',0,20]],
  History: [['command',0,0],['entry',1,0]],
  Claim: [['commitBlock',0,0],['consumed',1,0],['present',1,1]],
  Record: [['controller',0,0],['version',0,20],['state',0,28],['admitted',1,0],['keys',2,0],['services',3,0],['grants',4,0],['usedNames',5,0],['usedMaterial',6,0],['history',7,0]],
};
const sizes = {Key:192, Service:96, Grant:32, History:64, Claim:64, Record:256};
const primitive = {address:20, bool:1, uint8:1, uint64:8, uint256:32, bytes32:32};
export function verifyLayout(output, expected) {
  assert.deepEqual(Object.keys(output.contracts), ['Storage.sol']);
  assert.deepEqual(Object.keys(output.contracts['Storage.sol']), ['StorageProbe']);
  const artifact = output.contracts['Storage.sol'].StorageProbe;
  assert.deepEqual(Object.keys(artifact).sort(), ['abi','storageLayout']);
  assert.deepEqual(artifact.abi, []);
  assert.deepEqual(Object.keys(expected).sort(), ['root','structs']);
  assert.deepEqual(Object.keys(expected.structs).sort(), Object.keys(sizes).sort());
  const layout = artifact.storageLayout, visited = new Set(), structs = new Set();
  const fields = (rows, ancestry, name) => {
    assert.deepEqual(rows.map(v=>[v.label,Number(v.slot),v.offset]), positions[name]);
    return rows.map(v=>[v.label, type(v.type, ancestry)]);
  };
  function type(ref, ancestry) {
    assert(!ancestry.has(ref) && Object.hasOwn(layout.types,ref), 'cyclic or missing type');
    visited.add(ref);
    const value=layout.types[ref], next=new Set([...ancestry,ref]);
    assert.equal(typeof value.numberOfBytes,'string'); assert(/^\d+$/.test(value.numberOfBytes));
    const size=Number(value.numberOfBytes);
    if(value.encoding==='mapping') { assert.equal(size,32); return 'mapping('+type(value.key,next)+'=>'+type(value.value,next)+')'; }
    if(value.encoding==='dynamic_array') { assert.equal(size,32); return type(value.base,next)+'[]'; }
    if(value.encoding==='bytes') { assert.equal(size,32); assert(['string','bytes'].includes(value.label)); return value.label; }
    assert.equal(value.encoding,'inplace');
    if(value.members) {
      assert(value.label.startsWith('struct StorageProbe.')); const name=value.label.slice(20);
      assert(Object.hasOwn(sizes,name)); structs.add(name); assert.equal(size,sizes[name]);
      assert.deepEqual(fields(value.members,next,name),expected.structs[name]); return name;
    }
    assert(Object.hasOwn(primitive,value.label)); assert.equal(size,primitive[value.label]); return value.label;
  }
  assert.deepEqual(fields(layout.storage,new Set(),'root'),expected.root);
  assert.deepEqual([...visited].sort(),Object.keys(layout.types).sort());
  assert.deepEqual([...structs].sort(),Object.keys(sizes).sort());
  assert.equal(visited.size,25);
  return {scope:'abstract type and slot/offset closure only; execution and conformance NOT_RUN', roots:4,structs:6,members:28,reachable_types:25};
}
