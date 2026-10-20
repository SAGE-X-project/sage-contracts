import test from 'node:test';
import './unit.mjs';
// One test entry prevents the runner's alphabetical file sorting from starting
// the workload before its separately named unit compiler/trace evidence exists.
test('ordinary isolated state workloads and combined mapped coverage',async()=>{
 await import('./evaluate.mjs');
});
