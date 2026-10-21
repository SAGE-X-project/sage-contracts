// Fixed-unit message observation only; no calls, step tracing or VM mutation.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const policy = {max_frames:128,max_depth:16,max_hashed_input_bytes:148804,
  max_copied_verifier_input_bytes:1024,max_copied_verifier_output_bytes:32};
export function messageObserver(evm, verifier) {
  assert.equal(evm.DEBUG,false);
  assert.equal(evm.events.listenerCount('step'),0);
  assert(/^0x[0-9a-f]{40}$/.test(verifier));
  assert.equal(evm.events.listenerCount('beforeMessage'),0);
  assert.equal(evm.events.listenerCount('afterMessage'),0);
  let active=false,closed=false,label=null,frames=[],stack=[],failure=null,event=0;
  const fail = error => { failure??=String(error); };
  const before = (message,next) => {
    try {
      if (!active || failure!==null) return;
      assert(frames.length<policy.max_frames,'message frame limit');
      assert(stack.length<policy.max_depth,'message stack limit');
      assert(message.to,'This fixed call unit contains no CREATE message');
      assert(Number.isInteger(message.depth)&&message.depth===stack.length);
      assert(message.data instanceof Uint8Array && message.data.length<=policy.max_hashed_input_bytes);
      const to=message.to.toString(),code=message.codeAddress.toString();
      assert(/^0x[0-9a-f]{40}$/.test(to)&&/^0x[0-9a-f]{40}$/.test(code));
      const selected=code===verifier;
      if (selected) assert(message.data.length<=policy.max_copied_verifier_input_bytes);
      const row={sequence:frames.length,before_event:event++,parent:stack.at(-1)??null,depth:message.depth,
        caller:message.caller.toString(),to,code_address:code,delegatecall:message.delegatecall,
        is_static:message.isStatic,input_bytes:message.data.length,input_sha256:hash(message.data),
        selector_hex:Buffer.from(message.data.subarray(0,4)).toString('hex'),
        ...(selected?{verifier_input_hex:Buffer.from(message.data).toString('hex')}:{}),completed:false};
      frames.push(row);stack.push(row.sequence);
    } catch(error) { fail(error); }
    finally { next?.(); }
  };
  const after = (result,next) => {
    try {
      if (!active || failure!==null) return;
      assert(stack.length>0,'unmatched afterMessage');
      const row=frames[stack.pop()];
      assert(result.execResult.returnValue instanceof Uint8Array);
      const selected=row.code_address===verifier;
      if (selected) assert(result.execResult.returnValue.length<=policy.max_copied_verifier_output_bytes);
      Object.assign(row,{completed:true,after_event:event++,return_bytes:result.execResult.returnValue.length,
        exception:result.execResult.exceptionError?.error??null,after_sequence:frames.filter(value=>value.completed).length,
        ...(selected?{verifier_return_hex:Buffer.from(result.execResult.returnValue).toString('hex')}:{} )});
    } catch(error) { fail(error); }
    finally { next?.(); }
  };
  evm.events.on('beforeMessage',before);evm.events.on('afterMessage',after);
  return {
    begin(value) {
      assert(!closed&&!active&&typeof value==='string');
      assert.equal(evm.events.listenerCount('step'),0);
      active=true;label=value;frames=[];stack=[];failure=null;event=0;
    },
    snapshot() {
      return structuredClone({scope:'Bounded fixed message pairs only; no PC/consensus/operating qualification',
        label,policy,complete:active&&failure===null&&stack.length===0&&frames.length>0,
        failure,open_frames:stack,frames});
    },
    finish() {
      const result=this.snapshot();active=false;
      assert(result.complete,'Incomplete message observation: '+(failure??'unbalanced or empty frames'));
      assert.equal(evm.events.listenerCount('step'),0);
      return result;
    },
    close() {
      assert(!closed);active=false;closed=true;
      evm.events.removeListener('beforeMessage',before);evm.events.removeListener('afterMessage',after);
      assert.equal(evm.events.listenerCount('beforeMessage'),0);
      assert.equal(evm.events.listenerCount('afterMessage'),0);
      assert.equal(evm.events.listenerCount('step'),0);
    }
  };
}

// Test-only root request lifecycle. Preserve the original failure, retain the
// available prefix first, and always detach both listeners before returning.
export async function captureObservedRequest(observer,label,operation,persist) {
  let row,trace,firstError;
  try {
    observer.begin(label);
    row=await operation();
    trace=observer.finish();
  } catch(error) { firstError=error; }
  finally {
    try {
      persist({...(trace??observer.snapshot()),root_validation_passed:firstError===undefined,
        root_failure:firstError===undefined?null:String(firstError)});
    } catch(error) { firstError??=error; }
    try { observer.close(); } catch(error) { firstError??=error; }
  }
  if(firstError!==undefined) throw firstError;
  return {row,trace};
}
