// Fixed standard ABI bytes[][] workload encoding, never a Registry command codec.
import assert from 'node:assert/strict';
export const word = n => { const value=BigInt(n); assert(value>=0n && value<(1n<<256n)); return Buffer.from(value.toString(16).padStart(64,'0'),'hex'); };
const dynamic = value => Buffer.concat([word(value.length),value,Buffer.alloc((32-value.length%32)%32)]);
export function encodeBatch(selector, arrays) {
  assert(/^[0-9a-f]{8}$/.test(selector)); assert.equal(arrays.length,3);
  const array = values => {
    let offset=values.length*32; const heads=[],tails=[];
    for(const value of values) { const tail=dynamic(value); heads.push(word(offset)); tails.push(tail); offset+=tail.length; }
    return Buffer.concat([word(values.length),...heads,...tails]);
  };
  const tails=arrays.map(array), heads=[]; let offset=96;
  for(const tail of tails) { heads.push(word(offset)); offset+=tail.length; }
  return Buffer.concat([Buffer.from(selector,'hex'),...heads,...tails]);
}
export function decodeBatch(data) {
  assert(data.length>=100); const body=data.subarray(4);
  const number = offset => { assert(offset>=0 && offset+32<=body.length); const n=BigInt('0x'+body.subarray(offset,offset+32).toString('hex')); assert(n<=BigInt(body.length)); return Number(n); };
  return [0,32,64].map(head=>{
    const start=number(head), count=number(start), origin=start+32;
    return Array.from({length:count},(_,i)=>{
      const start=origin+number(origin+i*32), length=number(start); assert(start+32+length<=body.length);
      return Buffer.from(body.subarray(start+32,start+32+length));
    });
  });
}
