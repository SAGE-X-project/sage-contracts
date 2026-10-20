"""Run compiler-data unit controls and preserve measured helper coverage."""
from pathlib import Path
import hashlib
import json
import sys
import trace
import unittest

root = Path(__file__).resolve().parent
tracker = trace.Trace(count=True, trace=False)
suite = tracker.runfunc(unittest.defaultTestLoader.discover, str(root), 'test_prepare.py')
result = tracker.runfunc(unittest.TextTestRunner(verbosity=2).run, suite)
source = root / 'prepare.py'
executable = set(trace._find_executable_linenos(str(source)))
hit = {line for (name, line), count in tracker.results().counts.items()
       if Path(name).resolve() == source and count and line in executable}
percent = 100 * len(hit) / len(executable) if executable else 0
value = {'scope': 'Compiler-data helper source lines only; no Registry or compiler-code coverage',
         'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'python': sys.version,
         'executable_lines': sorted(executable), 'covered_lines': sorted(hit),
         'total': len(executable), 'covered': len(hit), 'percent': percent,
         'tests_run': result.testsRun, 'unit_success': result.wasSuccessful()}
(root / 'evidence').mkdir(exist_ok=True)
(root / 'evidence/python-coverage.json').write_text(json.dumps(value, indent=2) + '\n')
print(json.dumps(value))
if not result.wasSuccessful() or result.testsRun != 5 or percent < 90:
    raise SystemExit('Compiler-data unit or coverage gate failed')
