// Inert callback bookkeeping data only; no compiler, VM or transaction.
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import test from 'node:test';
import {lateHeadroomMessageObserver as messageObserver,captureObservedRequest} from './late-headroom-message-observer.mjs';
const verifier='0x'+'1'.repeat(40),caller='0x'+'2'.repeat(40),other='0x'+'3'.repeat(40);
const address=value=>({toString:()=>value});
const message=(depth=0,selected=false,data=Buffer.from([1,2,3,4]))=>({
  to:address(selected?verifier:other),codeAddress:address(selected?verifier:other),caller:address(caller),
  depth,data,isStatic:selected,delegatecall:false});
const result=(data=Buffer.alloc(32),error=null)=>({execResult:{returnValue:data,exceptionError:error}});
function fixture() {
  const evm={DEBUG:false,events:new EventEmitter()},observer=messageObserver(evm,verifier);
  let resolved=0;
  const before=value=>evm.events.emit('beforeMessage',value,()=>++resolved);
  const after=value=>evm.events.emit('afterMessage',value,()=>++resolved);
  return {evm,observer,before,after,resolved:()=>resolved};
}
test('balanced inert messages, detached copies, callbacks and lifecycle',()=>{
  const f=fixture();f.before(message());f.after(result());
  assert.throws(()=>f.observer.finish(),/Incomplete/);
  f.observer.begin('ordinary');f.before(message());f.before(message(1,true));f.before(message(2));
  const copy=f.observer.snapshot();copy.frames.length=0;
  f.after(result());f.after(result());f.after(result());
  const observed=f.observer.finish();
  assert.equal(observed.frames.length,3);assert.equal(observed.frames[1].parent,0);
  assert.equal(observed.frames[2].parent,1);
  assert.deepEqual(observed.frames.map(x=>x.after_sequence),[2,1,0]);
  assert.deepEqual(observed.frames.map(x=>[x.before_event,x.after_event]),[[0,5],[1,4],[2,3]]);
  assert.equal(observed.frames[1].verifier_input_hex,'01020304');
  assert.equal(observed.frames[1].verifier_return_hex,'00'.repeat(32));
  f.before(message());f.after(result());assert.equal(f.resolved(),10);
  assert.throws(()=>f.observer.finish(),/Incomplete/);f.observer.close();
  assert.throws(()=>f.observer.begin('after-close'));
});
for (const [name,produce] of [
  ['frame limit',f=>{for(let i=0;i<160;++i){f.before(message());f.after(result());}f.before(message());f.after(result());}],
  ['stack limit',f=>{for(let i=0;i<17;++i)f.before(message(i));}],
  ['input bound',f=>f.before(message(0,false,Buffer.alloc(148805)))],
  ['copied input bound',f=>f.before(message(0,true,Buffer.alloc(1025)))],
  ['copied output bound',f=>{f.before(message(0,true));f.after(result(Buffer.alloc(33)));}],
  ['missing to',f=>f.before({...message(),to:undefined})],
  ['wrong depth',f=>f.before(message(1))],
  ['wrong input type',f=>f.before(message(0,false,'data'))],
  ['unmatched return',f=>f.after(result())],
  ['wrong return type',f=>{f.before(message());f.after(result('data'));}],
  ['missing return',f=>f.before(message())]
]) test('fixed inert refusal: '+name,()=>{
  const f=fixture();f.observer.begin(name);produce(f);
  const prefix=f.observer.snapshot();assert.equal(prefix.complete,false);
  assert.throws(()=>f.observer.finish(),/Incomplete/);f.observer.close();
});
test('existing trace context and invalid observer configuration are refused',()=>{
  assert.throws(()=>messageObserver({DEBUG:true,events:new EventEmitter()},verifier));
  const events=new EventEmitter();events.on('step',()=>{});
  assert.throws(()=>messageObserver({DEBUG:false,events},verifier));
  assert.throws(()=>messageObserver({DEBUG:false,events:new EventEmitter()},'bad'));
  for (const name of ['beforeMessage','afterMessage']) {
    const events=new EventEmitter();events.on(name,()=>{});
    assert.throws(()=>messageObserver({DEBUG:false,events},verifier));
  }
});

test('inert exception fact is retained without asserting protocol success',()=>{
  const f=fixture();f.observer.begin('fixed exception');f.before(message());
  f.after(result(Buffer.alloc(0),{error:'revert'}));
  assert.equal(f.observer.finish().frames[0].exception,'revert');f.observer.close();
});

for (const mode of ['success','operation failure','finish failure','persist failure','operation and persist failure'])
  test('root finally cleanup: '+mode,async()=>{
    const f=fixture(),original=new Error('original operation failure'),disk=new Error('fixed persistence failure');
    let saved;
    const operation=async()=>{
      f.before(message());
      if(mode.startsWith('operation'))throw original;
      if(mode!=='finish failure')f.after(result());
      return {ordinary:true};
    };
    const persist=value=>{
      saved=value;
      if(mode.includes('persist'))throw disk;
    };
    if(mode==='success') {
      const output=await captureObservedRequest(f.observer,mode,operation,persist);
      assert.equal(output.trace.complete,true);assert.equal(saved.root_validation_passed,true);
    } else {
      let error;
      try { await captureObservedRequest(f.observer,mode,operation,persist); }
      catch(value) { error=value; }
      assert(error);
      if(mode.startsWith('operation'))assert.equal(error,original);
      else if(mode==='persist failure')assert.equal(error,disk);
      else assert.match(String(error),/Incomplete/);
      if(mode==='operation and persist failure')assert.equal(saved.root_failure,String(original));
    }
    assert.equal(f.evm.events.listenerCount('beforeMessage'),0);
    assert.equal(f.evm.events.listenerCount('afterMessage'),0);
    assert.equal(f.evm.events.listenerCount('step'),0);
    assert.throws(()=>f.observer.begin('disposed'));
  });

// Synthetic callback bookkeeping only; not a Registry trace or negative-root verdict.
for(const count of [159,160,161]) test('separate fixed frame policy: '+count,()=>{
  const f=fixture();f.observer.begin('bounded '+count);
  f.before(message());
  for(let i=1;i<count;++i){f.before(message(1));f.after(result(Buffer.alloc(0)));}
  f.after(result(Buffer.alloc(0)));
  if(count<=160){
    const trace=f.observer.finish();assert.equal(trace.frames.length,count);
    assert.equal(trace.policy.max_frames,160);assert.equal(trace.complete,true);
  }else{
    assert.equal(f.observer.snapshot().complete,false);
    assert.throws(()=>f.observer.finish(),/Incomplete/);
  }
  f.observer.close();
});
test('exact other policy limits remain finite',()=>{
  const f=fixture();f.observer.begin('limits');
  f.before(message(0,false,Buffer.alloc(148804)));
  for(let depth=1;depth<16;++depth)f.before(message(depth,depth===15,Buffer.alloc(depth===15?1024:4)));
  for(let depth=15;depth>=0;--depth)f.after(result(Buffer.alloc(depth===15?32:0)));
  const t=f.observer.finish();assert.equal(t.frames.length,16);
  assert.deepEqual(t.policy,{max_frames:160,max_depth:16,max_hashed_input_bytes:148804,
    max_copied_verifier_input_bytes:1024,max_copied_verifier_output_bytes:32});
  assert.equal(t.frames[15].verifier_input_hex.length,2048);
  assert.equal(t.frames[15].verifier_return_hex.length,64);f.observer.close();
});
test('140 balanced inert frames retain expected root revert without observation failure',async()=>{
  const f=fixture();let saved;
  const captured=await captureObservedRequest(f.observer,'inert140',async()=>{
    f.before(message());
    for(let i=1;i<140;++i){
      f.before(message(1));f.after(result(Buffer.alloc(0),i===139?{error:'revert'}:null));
    }
    f.after(result(Buffer.alloc(0),{error:'revert'}));
    return {exception:'revert'};
  },value=>{saved=value;});
  assert.equal(captured.row.exception,'revert');assert.equal(saved.frames.length,140);
  assert.equal(saved.complete,true);assert.equal(saved.root_validation_passed,true);
  assert.equal(saved.failure,null);assert.equal(saved.root_failure,null);
  assert.equal(saved.frames[0].after_event,279);
  assert.equal(saved.frames[139].exception,'revert');
  assert.equal(saved.frames.filter(x=>x.verifier_input_hex!==undefined).length,0);
  assert.equal(f.evm.events.listenerCount('beforeMessage'),0);
  assert.equal(f.evm.events.listenerCount('afterMessage'),0);
});
