// Test-only fixed-image PC bookkeeping. This module never calls or mutates a VM.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const addressPattern = /^0x[0-9a-f]{40}$/;
const digestPattern = /^[0-9a-f]{64}$/;
export const fixedPcPolicy = Object.freeze({max_images:30,max_frames:64,max_depth:16,
  max_creation_bytes:49152,max_runtime_bytes:24576,max_steps:12427383,
  first_memory_threshold:1048576,max_bitmap_bytes:129024,max_result_bytes:262144,
  max_frame_json_bytes:1024,max_image_json_bytes:512,max_root_json_bytes:8192});
const jsonBytes = value => Buffer.byteLength(JSON.stringify(value));
class ObservationError extends Error {
  constructor(code){super(code);this.code=code;}
}
const check = (value, code) => { if (!value) throw new ObservationError(code); };

function instructionFlags(code) {
  const flags=new Uint8Array(code.length);
  for(let pc=0;pc<code.length;) {
    flags[pc]=1;const op=code[pc];pc+=1+(op>=0x60&&op<=0x7f?op-0x5f:0);
  }
  return flags;
}

export function fixedPcObserver(evm, suppliedImages) {
  assert.equal(evm.DEBUG,false);
  for(const name of ['step','beforeMessage','afterMessage']) assert.equal(evm.events.listenerCount(name),0);
  assert(Array.isArray(suppliedImages)&&suppliedImages.length>0&&suppliedImages.length<=fixedPcPolicy.max_images);
  const images=[],byId=new Map(),runtime=new Map(),creation=new Map();let bitmapBytes=0;
  for(const supplied of suppliedImages) {
    assert(supplied&&typeof supplied.id==='string'&&/^[A-Za-z0-9:_-]{1,48}$/.test(supplied.id)&&!byId.has(supplied.id));
    assert(addressPattern.test(supplied.address)&&['creation','runtime'].includes(supplied.kind));
    assert(supplied.code instanceof Uint8Array&&supplied.code.length>0);
    assert(supplied.code.length<=(supplied.kind==='creation'?fixedPcPolicy.max_creation_bytes:fixedPcPolicy.max_runtime_bytes));
    const code=Uint8Array.from(supplied.code);assert(digestPattern.test(supplied.code_sha256)&&sha(code)===supplied.code_sha256);
    const identity={id:supplied.id,kind:supplied.kind,address:supplied.address,
      code_bytes:code.length,code_sha256:supplied.code_sha256};
    if(supplied.kind==='creation') {
      assert(digestPattern.test(supplied.input_sha256)&&digestPattern.test(supplied.return_runtime_sha256));
      assert(addressPattern.test(supplied.creator_address));
      assert(!creation.has(supplied.input_sha256+':'+supplied.creator_address));
      Object.assign(identity,{creator_address:supplied.creator_address,input_sha256:supplied.input_sha256,return_runtime_sha256:supplied.return_runtime_sha256});
    } else assert(!runtime.has(supplied.address));
    assert(jsonBytes(identity)<=fixedPcPolicy.max_image_json_bytes);
    const image={...identity,code,flags:instructionFlags(code)};
    images.push(image);byId.set(image.id,image);
    (image.kind==='creation'?creation:runtime).set(image.kind==='creation'?image.input_sha256+':'+image.creator_address:image.address,image);
    bitmapBytes+=Math.ceil(code.length/8);
  }
  assert(bitmapBytes<=fixedPcPolicy.max_bitmap_bytes);
  let active=false,closed=false,label=null,frames=[],stack=[],bits=new Map(),failure=null;
  let steps=0,maxMemory=0,maxStack=0,roots=0,event=0;
  const fail = code => { failure??=code;evm.events.removeListener('step',step); };
  const failureCode = error => error instanceof ObservationError?error.code:'OBSERVER_ERROR';
  const healthy = () => {
    check(evm.DEBUG===false,'DEBUG_CHANGED');
    const stepListeners=evm.events.listeners('step');
    check(stepListeners.length===1&&stepListeners[0]===step,'STEP_LISTENER_CHANGED');
    const beforeListeners=evm.events.listeners('beforeMessage'),afterListeners=evm.events.listeners('afterMessage');
    check(beforeListeners.length===1&&beforeListeners[0]===before&&afterListeners.length===1&&afterListeners[0]===after,'MESSAGE_LISTENER_CHANGED');
  };
  const before=(message,next)=>{
    try {
      if(!active||failure!==null)return;
      healthy();check(frames.length<fixedPcPolicy.max_frames,'FRAME_LIMIT');
      check(stack.length<fixedPcPolicy.max_depth,'DEPTH_LIMIT');
      check(Number.isInteger(message.depth)&&message.depth===stack.length,'DEPTH_MISMATCH');
      check(message.data instanceof Uint8Array&&message.data.length<=148804,'INPUT_BOUND');
      check(typeof message.isStatic==='boolean'&&typeof message.delegatecall==='boolean','MESSAGE_FLAGS');
      const isCreate=message.to===undefined;
      let image,codeAddress,actualAddress,kind,creatorAddress;
      if(isCreate) {
        check(message.data.length<=fixedPcPolicy.max_creation_bytes,'CREATION_INPUT_BOUND');
        check(message.caller&&typeof message.caller.toString==='function','CREATION_CALLER');
        creatorAddress=message.caller.toString();check(addressPattern.test(creatorAddress),'CREATION_CALLER');
        image=creation.get(sha(message.data)+':'+creatorAddress);check(image!==undefined,'UNKNOWN_INITCODE');
        check(message.data.length>=image.code.length,'SHORT_INITCODE');
        check(message.data.subarray(0,image.code.length).every((value,index)=>value===image.code[index]),'INITCODE_PREFIX');
        kind='creation';codeAddress=image.address;actualAddress=image.address;
      } else {
        actualAddress=message.to.toString();codeAddress=message.codeAddress.toString();
        check(addressPattern.test(actualAddress)&&addressPattern.test(codeAddress),'MESSAGE_ADDRESS');
        image=runtime.get(codeAddress);kind=image?'runtime':'precompile';
        check(image!==undefined||/^0x0{39}[1-9]$/.test(codeAddress),'UNKNOWN_RUNTIME');
      }
      if(stack.length===0){check(roots===0,'MULTIPLE_ROOTS');roots++;}
      const frame={sequence:frames.length,parent:stack.at(-1)??null,depth:message.depth,kind,
        image_id:image?.id??null,address:actualAddress,code_address:codeAddress,
        ...(isCreate?{creator_address:creatorAddress}:{}),
        is_static:message.isStatic,delegatecall:message.delegatecall,input_bytes:message.data.length,
        before_event:event++,steps:0,completed:false,step_code_address_source:null};
      check(jsonBytes(frame)<=fixedPcPolicy.max_frame_json_bytes,'FRAME_JSON_BOUND');
      frames.push(frame);stack.push(frame.sequence);
    }catch(error){fail(failureCode(error));}
    finally{next?.();}
  };
  const step=(entry,next)=>{
    try {
      if(!active||failure!==null)return;
      healthy();check(steps<fixedPcPolicy.max_steps,'STEP_LIMIT');
      check(entry.memory instanceof Uint8Array&&Array.isArray(entry.stack),'SNAPSHOT_TYPE');
      maxMemory=Math.max(maxMemory,entry.memory.length);maxStack=Math.max(maxStack,entry.stack.length);
      check(entry.memory.length<=fixedPcPolicy.first_memory_threshold,'MEMORY_SNAPSHOT_STOP');
      check(entry.stack.length<=1024,'STACK_BOUND');
      check(entry.eofSection===undefined&&entry.eofFunctionDepth===undefined,'EOF_UNSUPPORTED');
      check(stack.length>0,'STEP_WITHOUT_FRAME');
      const frame=frames[stack.at(-1)],image=byId.get(frame.image_id);
      check(image!==undefined&&frame.kind!=='precompile','PRECOMPILE_STEP');
      check(entry.depth===frame.depth,'STEP_DEPTH');
      check(entry.address.toString()===frame.address,'STEP_ADDRESS');
      const missingCodeAddress=entry.codeAddress===undefined;
      check(missingCodeAddress?frame.kind==='creation':entry.codeAddress.toString()===frame.code_address,'STEP_ADDRESS');
      const source=missingCodeAddress?'creation_address':'code_address';
      check(frame.step_code_address_source===null||frame.step_code_address_source===source,'CODE_ADDRESS_MODE_CHANGED');
      frame.step_code_address_source=source;
      check(Number.isInteger(entry.pc)&&entry.pc>=0&&entry.pc<image.code.length&&image.flags[entry.pc]===1,'INVALID_PC');
      check(entry.opcode?.code===image.code[entry.pc],'OPCODE_MISMATCH');
      bits.get(image.id)[entry.pc>>3]|=1<<(entry.pc&7);steps++;frame.steps++;
    }catch(error){fail(failureCode(error));}
    finally{next?.();}
  };
  const after=(result,next)=>{
    try {
      if(!active||failure!==null)return;
      healthy();check(stack.length>0,'UNMATCHED_AFTER');
      const frame=frames[stack.at(-1)],value=result.execResult;
      check(value&&value.returnValue instanceof Uint8Array&&value.returnValue.length<=262144,'RETURN_BOUND');
      if(frame.kind==='creation') {
        const image=byId.get(frame.image_id);
        check(result.createdAddress?.toString()===frame.address,'CREATED_ADDRESS');
        check(!value.exceptionError&&value.returnValue.length<=fixedPcPolicy.max_runtime_bytes,'CREATION_RESULT');
        check(sha(value.returnValue)===image.return_runtime_sha256,'CREATED_CODE');
      }
      Object.assign(frame,{completed:true,after_event:event++,return_bytes:value.returnValue.length,
        reverted:value.exceptionError!==undefined});
      check(jsonBytes(frame)<=fixedPcPolicy.max_frame_json_bytes,'FRAME_JSON_BOUND');stack.pop();
    }catch(error){fail(failureCode(error));}
    finally{next?.();}
  };
  evm.events.on('beforeMessage',before);evm.events.on('step',step);evm.events.on('afterMessage',after);
  return {
    begin(value) {
      assert(!closed&&!active&&typeof value==='string'&&Buffer.byteLength(value)<=256);
      healthy();label=value;frames=[];stack=[];failure=null;steps=0;maxMemory=0;maxStack=0;roots=0;event=0;
      bits=new Map(images.map(image=>[image.id,new Uint8Array(Math.ceil(image.code.length/8))]));active=true;
    },
    snapshot() {
      if(active&&failure===null){try{healthy();}catch(error){fail(failureCode(error));}}
      const complete=active&&failure===null&&stack.length===0&&roots===1&&frames.length>0;
      const metadata={scope:'Fixed owned PC bitmap observation only; partial roots excluded from coverage',
        label,policy:fixedPcPolicy,complete,failure,open_frames:[...stack],steps,
        max_observed_memory_snapshot_bytes:maxMemory,max_observed_stack_items:maxStack,
        upstream_snapshot_precedes_callback:true,root_messages:roots};
      assert(jsonBytes(metadata)<=fixedPcPolicy.max_root_json_bytes);
      const result={...metadata,frames:structuredClone(frames),images:images.map(image=>({
        ...Object.fromEntries(Object.entries(image).filter(([name])=>!['code','flags'].includes(name))),
        visited_bits_base64:Buffer.from(bits.get(image.id)??new Uint8Array(Math.ceil(image.code.length/8))).toString('base64')}))};
      assert(jsonBytes(result)<=fixedPcPolicy.max_result_bytes);
      return result;
    },
    finish() {assert(active&&!closed);const result=this.snapshot();active=false;return result;},
    close() {
      assert(!closed);active=false;closed=true;
      evm.events.removeListener('beforeMessage',before);evm.events.removeListener('step',step);evm.events.removeListener('afterMessage',after);
      for(const name of ['step','beforeMessage','afterMessage']) assert.equal(evm.events.listenerCount(name),0);
    }
  };
}
