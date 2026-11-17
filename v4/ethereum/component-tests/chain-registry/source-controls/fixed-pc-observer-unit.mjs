// Fixed inert event data only. No EthereumJS import, EVM, transaction or network.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {EventEmitter} from 'node:events';
import test from 'node:test';
import {fixedPcObserver,fixedPcPolicy} from './fixed-pc-observer.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const a='0x'+'1'.repeat(40),b='0x'+'2'.repeat(40),precompile='0x'+'0'.repeat(39)+'5';
const code=Uint8Array.of(0x60,0x01,0x00),init=Uint8Array.of(0x60,0x00,0x00);
const input=Uint8Array.from([...init,...new Uint8Array(32)]);
const addr=value=>({toString:()=>value});
const runtime=(address=a,id='runtime:Unit')=>({id,kind:'runtime',address,code,code_sha256:sha(code)});
const creation=()=>({id:'creation:Unit',kind:'creation',address:a,code:init,code_sha256:sha(init),
  creator_address:a,input_sha256:sha(input),return_runtime_sha256:sha(code)});
function setup(images=[runtime()]) {
  const evm={DEBUG:false,events:new EventEmitter()},observer=fixedPcObserver(evm,images);
  return {evm,observer};
}
function emit(evm,name,value) {
  const listeners=evm.events.listeners(name);let continuations=0;
  for(const listener of listeners)listener(value,()=>{continuations++;});
  assert.equal(continuations,listeners.length,'Each owned event callback must resume exactly once');
}
const message=(address=a,depth=0)=>({to:addr(address),codeAddress:addr(address),depth,caller:addr(a),data:new Uint8Array(),isStatic:false,delegatecall:false});
const entry=(address=a,depth=0,pc=0)=>({pc,depth,address:addr(address),codeAddress:addr(address),opcode:{code:code[pc]},
  memory:new Uint8Array(),stack:[]});
const returned=()=>({execResult:{returnValue:new Uint8Array()}});
function failureCase(name,prepare,expected) {
  test(name,()=>{
    const {evm,observer}=setup();observer.begin(name);emit(evm,'beforeMessage',message());
    try {
      prepare(evm,observer);
      const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,expected);
      assert.equal(evm.events.listenerCount('step'),0,'Stop collecting after the first failure');
      const steps=row.steps;emit(evm,'afterMessage',returned());assert.equal(observer.snapshot().steps,steps);
    }finally{observer.close();}
  });
}

test('complete runtime preserves only instruction bits and bounded scalar frames',()=>{
  const {evm,observer}=setup();observer.begin('normal');emit(evm,'beforeMessage',message());
  emit(evm,'step',entry(a,0,0));emit(evm,'step',entry(a,0,2));emit(evm,'afterMessage',returned());
  const row=observer.finish();assert.equal(row.complete,true);assert.equal(row.steps,2);
  assert.equal(Buffer.from(row.images[0].visited_bits_base64,'base64')[0],5);
  assert.equal(row.frames[0].completed,true);assert.equal(row.upstream_snapshot_precedes_callback,true);
  assert(!JSON.stringify(row).includes('"memory"'));assert(!JSON.stringify(row).includes('"stack"'));
  observer.close();assert.throws(()=>observer.begin('closed'));assert.throws(()=>observer.close());
});
test('creation code uses its own namespace and actual returned runtime hash',()=>{
  const {evm,observer}=setup([creation(),runtime()]);observer.begin('constructor');
  const value={depth:0,caller:addr(a),data:input,isStatic:false,delegatecall:false};
  Object.defineProperty(value,'codeAddress',{get(){throw new Error('Must not read absent creation codeAddress');}});
  emit(evm,'beforeMessage',value);const step=entry();step.opcode.code=init[0];emit(evm,'step',step);
  emit(evm,'afterMessage',{createdAddress:addr(a),execResult:{returnValue:code}});
  const row=observer.finish();assert.equal(row.complete,true);assert.equal(row.frames[0].kind,'creation');
  assert.equal(Buffer.from(row.images[0].visited_bits_base64,'base64')[0],1);
  assert.equal(Buffer.from(row.images[1].visited_bits_base64,'base64')[0],0);observer.close();
});
test('creation step permits absent code address only with exact actual creation address',()=>{
  const {evm,observer}=setup([creation()]);observer.begin('creation-undefined-code-address');
  emit(evm,'beforeMessage',{depth:0,caller:addr(a),data:input,isStatic:false,delegatecall:false});
  const step=entry();step.codeAddress=undefined;step.opcode.code=init[0];emit(evm,'step',step);
  emit(evm,'afterMessage',{createdAddress:addr(a),execResult:{returnValue:code}});
  const row=observer.finish();assert.equal(row.complete,true);assert.equal(row.steps,1);
  assert.equal(row.frames[0].step_code_address_source,'creation_address');observer.close();
});
failureCase('runtime step never borrows a missing creation code address',(evm)=>{
  const step=entry();step.codeAddress=undefined;emit(evm,'step',step);
},'STEP_ADDRESS');
test('creation step code address mode cannot change within the same frame',()=>{
  const {evm,observer}=setup([creation()]);observer.begin('creation-mode-change');
  emit(evm,'beforeMessage',{depth:0,caller:addr(a),data:input,isStatic:false,delegatecall:false});
  const step=entry();step.codeAddress=undefined;step.opcode.code=init[0];emit(evm,'step',step);
  emit(evm,'step',{...step,codeAddress:addr(a)});
  const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,'CODE_ADDRESS_MODE_CHANGED');
  assert.equal(row.steps,1);observer.close();
});
test('normal nested code and precompile preserve frame pairing',()=>{
  const {evm,observer}=setup([runtime(),runtime(b,'runtime:Second')]);observer.begin('nested');
  emit(evm,'beforeMessage',message());emit(evm,'beforeMessage',message(b,1));emit(evm,'step',entry(b,1));
  emit(evm,'beforeMessage',message(precompile,2));emit(evm,'afterMessage',returned());
  emit(evm,'afterMessage',returned());emit(evm,'afterMessage',returned());
  const row=observer.finish();assert.equal(row.complete,true);assert.deepEqual(row.frames.map(x=>x.parent),[null,0,1]);
  assert.equal(row.frames[2].kind,'precompile');assert.equal(row.frames[2].steps,0);observer.close();
});
test('inactive callbacks resume and an empty observation stays incomplete',()=>{
  const {evm,observer}=setup();emit(evm,'beforeMessage',message());emit(evm,'step',entry());emit(evm,'afterMessage',returned());
  assert.equal(observer.snapshot().complete,false);observer.begin('empty');assert.equal(observer.finish().complete,false);observer.close();
});
test('copied image bytes cannot change when the caller edits the original inert array',()=>{
  const original=Uint8Array.from(code),image={...runtime(),code:original};const {evm,observer}=setup([image]);
  original[0]=0;observer.begin('copied');emit(evm,'beforeMessage',message());emit(evm,'step',entry());emit(evm,'afterMessage',returned());
  assert.equal(observer.finish().complete,true);observer.close();
});
test('a clean observer may begin a second independent root',()=>{
  const {evm,observer}=setup();for(const label of ['one','two']){
    observer.begin(label);emit(evm,'beforeMessage',message());emit(evm,'step',entry());emit(evm,'afterMessage',returned());
    assert.equal(observer.finish().steps,1);
  }observer.close();
});

failureCase('PUSH operand cannot become an observed instruction',evm=>emit(evm,'step',entry(a,0,1)),'INVALID_PC');
failureCase('opcode must match the fixed actual code byte',evm=>{const value=entry();value.opcode.code=0;emit(evm,'step',value);},'OPCODE_MISMATCH');
failureCase('wrong step depth invalidates the whole root',evm=>emit(evm,'step',entry(a,1)),'STEP_DEPTH');
failureCase('wrong actual address invalidates the whole root',evm=>emit(evm,'step',entry(b)),'STEP_ADDRESS');
failureCase('EOF context is not silently treated as legacy bytecode',evm=>{const value=entry();value.eofSection=0;emit(evm,'step',value);},'EOF_UNSUPPORTED');
failureCase('unknown runtime is refused as evidence',evm=>emit(evm,'beforeMessage',message(b,1)),'UNKNOWN_RUNTIME');
failureCase('nonmatching message depth is incomplete evidence',evm=>emit(evm,'beforeMessage',message(a,2)),'DEPTH_MISMATCH');
failureCase('snapshot type must match the pinned event API',evm=>{const value=entry();value.memory={length:0};emit(evm,'step',value);},'SNAPSHOT_TYPE');
failureCase('stack bound is measured without retaining values',evm=>{const value=entry();value.stack=new Array(1025);emit(evm,'step',value);},'STACK_BOUND');
failureCase('first over-threshold snapshot is recorded and collection stops',evm=>{const value=entry();value.memory=new Uint8Array(fixedPcPolicy.first_memory_threshold+1);emit(evm,'step',value);},'MEMORY_SNAPSHOT_STOP');
failureCase('step limit stops at the fixed bound without throwing into a VM',evm=>{const value=entry();for(let i=0;i<=fixedPcPolicy.max_steps;i++)emit(evm,'step',value);},'STEP_LIMIT');
failureCase('depth limit rejects the next nested frame',evm=>{for(let depth=1;depth<=fixedPcPolicy.max_depth;depth++)emit(evm,'beforeMessage',message(a,depth));},'DEPTH_LIMIT');
failureCase('frame limit counts completed siblings as well as open depth',evm=>{
  for(let i=0;i<fixedPcPolicy.max_frames;i++){emit(evm,'beforeMessage',message(a,1));emit(evm,'afterMessage',returned());}
},'FRAME_LIMIT');
failureCase('DEBUG changes invalidate evidence',evm=>{evm.DEBUG=true;emit(evm,'step',entry());},'DEBUG_CHANGED');
failureCase('oversized return length does not become complete evidence',evm=>emit(evm,'afterMessage',{execResult:{returnValue:new Uint8Array(262145)}}),'RETURN_BOUND');
failureCase('a second top-level message cannot share one root receipt',evm=>{emit(evm,'afterMessage',returned());emit(evm,'beforeMessage',message());},'MULTIPLE_ROOTS');
test('unbalanced frames have no complete coverage result',()=>{
  const {evm,observer}=setup();observer.begin('unbalanced');emit(evm,'beforeMessage',message());emit(evm,'step',entry());
  const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,null);assert.deepEqual(row.open_frames,[0]);observer.close();
});
test('a step before any message is incomplete rather than a fabricated root',()=>{
  const {evm,observer}=setup();observer.begin('no-frame');emit(evm,'step',entry());
  const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,'STEP_WITHOUT_FRAME');observer.close();
});
test('unmatched completion cannot create a successful observation',()=>{
  const {evm,observer}=setup();observer.begin('no-before');emit(evm,'afterMessage',returned());
  assert.equal(observer.finish().failure,'UNMATCHED_AFTER');observer.close();
});
test('a precompile cannot contribute Solidity PCs',()=>{
  const {evm,observer}=setup();observer.begin('precompile');emit(evm,'beforeMessage',message(precompile));emit(evm,'step',entry(precompile));
  assert.equal(observer.finish().failure,'PRECOMPILE_STEP');observer.close();
});
test('creation output mismatch preserves an incomplete prefix',()=>{
  const {evm,observer}=setup([creation()]);observer.begin('bad-output');
  emit(evm,'beforeMessage',{depth:0,caller:addr(a),data:input,isStatic:false,delegatecall:false});
  emit(evm,'afterMessage',{createdAddress:addr(a),execResult:{returnValue:Uint8Array.of(0)}});
  assert.equal(observer.finish().failure,'CREATED_CODE');observer.close();
});
test('fixed configuration rejects missing identities and inconsistent hashes',()=>{
  const build=images=>fixedPcObserver({DEBUG:false,events:new EventEmitter()},images);
  assert.throws(()=>build([]));assert.throws(()=>build(new Array(29).fill(runtime())));
  assert.throws(()=>build([{...runtime(),code_sha256:'0'.repeat(64)}]));
  assert.throws(()=>build([runtime(),runtime()]));
  assert.throws(()=>build([{...runtime(),code:new Uint8Array(24577)}]));
  assert.throws(()=>build([{...runtime(),id:'invalid label'}]));
  assert.throws(()=>build([{...runtime(),address:'bad'}]));
  assert.throws(()=>build([{...creation(),input_sha256:'bad'}]));
  assert.throws(()=>build([creation(),{...creation(),id:'creation:Second'}]));
});
test('pre-existing observation listeners and DEBUG are rejected',()=>{
  const evm={DEBUG:true,events:new EventEmitter()};assert.throws(()=>fixedPcObserver(evm,[runtime()]));
  evm.DEBUG=false;const listener=()=>{};evm.events.on('step',listener);
  assert.throws(()=>fixedPcObserver(evm,[runtime()]));assert.equal(evm.events.listeners('step')[0],listener);
});
test('an unrelated listener is detected and is never removed as an owned hook',()=>{
  const {evm,observer}=setup();observer.begin('listener');emit(evm,'beforeMessage',message());
  const listener=(_value,next)=>{next?.();};evm.events.on('step',listener);emit(evm,'step',entry());
  assert.equal(observer.finish().failure,'STEP_LISTENER_CHANGED');assert.throws(()=>observer.close());
  assert.deepEqual(evm.events.listeners('step'),[listener]);evm.events.removeListener('step',listener);
  assert.equal(evm.events.listenerCount('beforeMessage'),0);assert.equal(evm.events.listenerCount('afterMessage'),0);
});
failureCase('unexpected callback exceptions preserve a fixed diagnostic and resume',evm=>{
  const value=entry();value.address={toString(){throw 7;}};emit(evm,'step',value);
},'OBSERVER_ERROR');
failureCase('message flags are validated as bookkeeping data',evm=>{
  const value=message(a,1);value.delegatecall=undefined;emit(evm,'beforeMessage',value);
},'MESSAGE_FLAGS');
failureCase('message input length remains explicitly bounded',evm=>{
  const value=message(a,1);value.data=new Uint8Array(148805);emit(evm,'beforeMessage',value);
},'INPUT_BOUND');
failureCase('invalid address presentation is incomplete evidence',evm=>{
  const value=message(a,1);value.to=addr('invalid');emit(evm,'beforeMessage',value);
},'MESSAGE_ADDRESS');
test('a memory snapshot exactly at the profile threshold is recorded',()=>{
  const {evm,observer}=setup();observer.begin('threshold');emit(evm,'beforeMessage',message());
  const value=entry();value.memory=new Uint8Array(fixedPcPolicy.first_memory_threshold);emit(evm,'step',value);
  emit(evm,'afterMessage',returned());const row=observer.finish();assert.equal(row.complete,true);
  assert.equal(row.max_observed_memory_snapshot_bytes,fixedPcPolicy.first_memory_threshold);observer.close();
});
test('invalid creation observations cannot borrow a runtime image',()=>{
  for(const [label,change,expected] of [
    ['unknown',()=>({depth:0,caller:addr(a),data:Uint8Array.of(0),isStatic:false,delegatecall:false}),'UNKNOWN_INITCODE'],
    ['oversize',()=>({depth:0,caller:addr(a),data:new Uint8Array(49153),isStatic:false,delegatecall:false}),'CREATION_INPUT_BOUND']
  ]) {
    const {evm,observer}=setup([creation()]);observer.begin(label);emit(evm,'beforeMessage',change());
    assert.equal(observer.finish().failure,expected);observer.close();
  }
});
test('creation prefix and full input hash are independent checks',()=>{
  for(const [bytes,expected] of [[Uint8Array.of(0),'INITCODE_PREFIX'],[new Uint8Array(40),'SHORT_INITCODE']]) {
    const image={...creation(),code:bytes,code_sha256:sha(bytes)};
    const {evm,observer}=setup([image]);observer.begin(expected);
    emit(evm,'beforeMessage',{depth:0,caller:addr(a),data:input,isStatic:false,delegatecall:false});
    assert.equal(observer.finish().failure,expected);observer.close();
  }
});
test('creation address and unsuccessful creation cannot pass as runtime identity',()=>{
  for(const [result,expected] of [
    [{createdAddress:addr(b),execResult:{returnValue:code}},'CREATED_ADDRESS'],
    [{createdAddress:addr(a),execResult:{returnValue:code,exceptionError:{error:'revert'}}},'CREATION_RESULT']
  ]) {
    const {evm,observer}=setup([creation()]);observer.begin(expected);
    emit(evm,'beforeMessage',{depth:0,caller:addr(a),data:input,isStatic:false,delegatecall:false});
    emit(evm,'afterMessage',result);assert.equal(observer.finish().failure,expected);observer.close();
  }
});

test('same-count step replacement cannot make empty PCs complete',()=>{
  for(const timing of ['before-event','before-finish']) {
    const {evm,observer}=setup();observer.begin(timing);emit(evm,'beforeMessage',message());
    if(timing==='before-finish'){emit(evm,'step',entry());emit(evm,'afterMessage',returned());}
    const owned=evm.events.listeners('step')[0],replacement=(_entry,next)=>{next?.();};
    evm.events.removeListener('step',owned);evm.events.on('step',replacement);
    if(timing==='before-event'){emit(evm,'step',entry());emit(evm,'afterMessage',returned());}
    const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,'STEP_LISTENER_CHANGED');
    assert.equal(row.steps,timing==='before-event'?0:1);assert.throws(()=>observer.close());
    assert.deepEqual(evm.events.listeners('step'),[replacement]);evm.events.removeListener('step',replacement);
  }
});
test('unexpected Error text is never copied to evidence diagnostics',()=>{
  const {evm,observer}=setup();observer.begin('fixed-error');emit(evm,'beforeMessage',message());
  const value=entry(),marker='unexpected inert marker';value.address={toString(){throw new Error(marker.repeat(1000));}};
  emit(evm,'step',value);const row=observer.finish();assert.equal(row.failure,'OBSERVER_ERROR');
  assert.equal(row.complete,false);assert(!JSON.stringify(row).includes(marker));observer.close();
});

test('authority policy keeps every bound except the two reviewed constants',()=>{
  assert.deepEqual(fixedPcPolicy,{max_images:30,max_frames:64,max_depth:16,
    max_creation_bytes:49152,max_runtime_bytes:24576,max_steps:12427383,
    first_memory_threshold:1048576,max_bitmap_bytes:129024,max_result_bytes:262144,
    max_frame_json_bytes:1024,max_image_json_bytes:512,max_root_json_bytes:8192});
});

const inertImages=count=>Array.from({length:count},(_,index)=>runtime(
  '0x'+BigInt(index+32).toString(16).padStart(40,'0'),'runtime:Fixed'+index));

test('thirtieth inert runtime image records only its own instruction',()=>{
  const images=inertImages(30),target=images.at(-1).address,{evm,observer}=setup(images);
  observer.begin('thirtieth');emit(evm,'beforeMessage',message(target));
  emit(evm,'step',entry(target));emit(evm,'afterMessage',returned());
  const row=observer.finish();assert.equal(row.complete,true);assert.equal(row.images.length,30);
  assert.equal(row.frames[0].image_id,'runtime:Fixed29');
  assert.deepEqual(row.images.map(image=>Buffer.from(image.visited_bits_base64,'base64')[0]),
    [...Array(29).fill(0),1]);observer.close();
});

test('thirty-first image is rejected before any event listener is attached',()=>{
  const evm={DEBUG:false,events:new EventEmitter()};
  assert.throws(()=>fixedPcObserver(evm,inertImages(31)));
  for(const name of ['step','beforeMessage','afterMessage'])assert.equal(evm.events.listenerCount(name),0);
});

const inertWalletImages=()=>[a,b].flatMap((address,index)=>{
  const bytes=Uint8Array.from([...init,...Array(32).fill(index)]),name=index?'OperatorWallet':'OwnerWallet';
  return [{id:'creation:'+name,kind:'creation',address,code:init,code_sha256:sha(init),
    creator_address:address,input_sha256:sha(bytes),return_runtime_sha256:sha(code)},runtime(address,'runtime:'+name)];
});
const inertWalletInput=index=>Uint8Array.from([...init,...Array(32).fill(index)]);
function inertCreation(evm,address,index){
  emit(evm,'beforeMessage',{...message(),to:undefined,caller:addr(address),data:inertWalletInput(index)});
  const value={...entry(address),codeAddress:undefined};emit(evm,'step',value);
}

test('two auxiliary creation hashes share a prefix but retain separate addresses',()=>{
  const {evm,observer}=setup(inertWalletImages());
  for(const [index,address]of [a,b].entries()){
    observer.begin(index?'operator-creation':'owner-creation');inertCreation(evm,address,index);
    emit(evm,'afterMessage',{createdAddress:addr(address),execResult:{returnValue:code}});
    const row=observer.finish();assert.equal(row.complete,true);
    assert.equal(row.frames[0].image_id,index?'creation:OperatorWallet':'creation:OwnerWallet');
    assert.equal(row.frames[0].step_code_address_source,'creation_address');
    assert.deepEqual(row.images.map(image=>Buffer.from(image.visited_bits_base64,'base64')[0]),
      index?[0,0,1,0]:[1,0,0,0]);
  }
  observer.close();
});

test('operator creation cannot complete with the owner creation address',()=>{
  const {evm,observer}=setup(inertWalletImages());observer.begin('wrong-fixed-return-address');
  inertCreation(evm,b,1);
  emit(evm,'afterMessage',{createdAddress:addr(a),execResult:{returnValue:code}});
  const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,'CREATED_ADDRESS');
  assert.equal(row.frames[0].completed,false);observer.close();
});

test('equal auxiliary runtime bytes cannot credit the other wallet address',()=>{
  const images=[runtime(a,'runtime:OwnerWallet'),runtime(b,'runtime:OperatorWallet')];
  const {evm,observer}=setup(images);observer.begin('operator-runtime');
  emit(evm,'beforeMessage',message(b));emit(evm,'step',entry(b));emit(evm,'afterMessage',returned());
  const row=observer.finish();assert.equal(row.complete,true);
  assert.deepEqual(row.images.map(image=>Buffer.from(image.visited_bits_base64,'base64')[0]),[0,1]);
  assert.equal(row.frames[0].image_id,'runtime:OperatorWallet');observer.close();
});

test('thirty maximum-width inert runtimes retain bounded serialized evidence',()=>{
  const bytes=new Uint8Array(fixedPcPolicy.max_runtime_bytes);
  const images=inertImages(30).map(image=>({...image,code:bytes,code_sha256:sha(bytes)}));
  const {evm,observer}=setup(images),target=images.at(-1).address;observer.begin('fixed-serialized-width');
  emit(evm,'beforeMessage',message(target));
  emit(evm,'step',{...entry(target),opcode:{code:0}});emit(evm,'afterMessage',returned());
  const row=observer.finish();assert.equal(row.complete,true);
  assert.equal(row.images.reduce((sum,image)=>sum+Buffer.from(image.visited_bits_base64,'base64').length,0),92160);
  assert(Buffer.byteLength(JSON.stringify(row))<=fixedPcPolicy.max_result_bytes);observer.close();
});

test('identical creation input is disambiguated by the exact creator account',()=>{
  const images=inertWalletImages().map(image=>image.kind==='creation'?{...image,input_sha256:sha(input)}:image);
  const {evm,observer}=setup(images);
  for(const [index,address]of [a,b].entries()){
    observer.begin('same-input-'+index);
    emit(evm,'beforeMessage',{...message(),to:undefined,caller:addr(address),data:input});
    emit(evm,'step',{...entry(address),codeAddress:undefined});
    emit(evm,'afterMessage',{createdAddress:addr(address),execResult:{returnValue:code}});
    const row=observer.finish();assert.equal(row.complete,true);assert.equal(row.frames[0].creator_address,address);
    assert.equal(row.frames[0].image_id,index?'creation:OperatorWallet':'creation:OwnerWallet');
    assert.deepEqual(row.images.map(image=>Buffer.from(image.visited_bits_base64,'base64')[0]),index?[0,0,1,0]:[1,0,0,0]);
  }
  observer.close();
});

test('same creator and identical creation input remain an ambiguous closed image set',()=>{
  const first=creation(),second={...first,id:'creation:Second',address:b};
  const evm={DEBUG:false,events:new EventEmitter()};assert.throws(()=>fixedPcObserver(evm,[first,second]));
  for(const name of ['step','beforeMessage','afterMessage'])assert.equal(evm.events.listenerCount(name),0);
});

test('unselected creator cannot use another account creation input identity',()=>{
  const {evm,observer}=setup([creation()]);observer.begin('unselected-fixed-creator');
  emit(evm,'beforeMessage',{...message(),to:undefined,caller:addr(b),data:input});
  const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,'UNKNOWN_INITCODE');
  assert.equal(row.steps,0);observer.close();
});

test('missing creation caller is rejected before any image credit',()=>{
  const {evm,observer}=setup([creation()]);observer.begin('missing-creator');
  emit(evm,'beforeMessage',{...message(),to:undefined,caller:undefined,data:input});
  const row=observer.finish();assert.equal(row.complete,false);assert.equal(row.failure,'CREATION_CALLER');
  assert.equal(row.steps,0);observer.close();
});
