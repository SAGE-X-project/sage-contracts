"""Inert lifecycle regressions: no real child, signals, compiler or VM."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from owned_child import run_owned_child


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
    def sleep(self, value): self.now += value


class Child:
    pid = 123
    def __init__(self, statuses=()):
        self.statuses = list(statuses)
        self.returncode = None
        self.kills = 0
        self.kill_error = None
        self.wait_error = None
        self.wait_result = None
        self.poll_error = None
    def poll(self):
        if self.poll_error:
            error, self.poll_error = self.poll_error, None
            raise error
        if self.statuses:
            self.returncode = self.statuses.pop(0)
        return self.returncode
    def kill(self):
        self.kills += 1
        if self.kill_error: raise self.kill_error
        self.returncode = -9
    def wait(self, timeout):
        if timeout != 5: raise ValueError('Wrong cleanup grace')
        if self.wait_error: raise self.wait_error
        return self.returncode if self.wait_result is None else self.wait_result


class OwnedChildUnits(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.clock = Clock()
        self.child = Child([0])
        self.spawns = []
        self.checks = 0
        self.notices = []
    def factory(self, command, **kwargs):
        self.spawns.append((command, kwargs))
        return self.child
    def check(self): self.checks += 1
    def run_child(self, **overrides):
        args = dict(command=['fixed'], cwd=self.root, log=self.root/'child.log', seconds=0.2,
            check_files=self.check, on_spawn=self.notices.append, popen=self.factory,
            clock=self.clock, sleep=self.clock.sleep)
        args.update(overrides)
        return run_owned_child(**args)
    def test_success_reaps_only_its_owned_child(self):
        r = self.run_child()
        self.assertTrue(r['complete'] and r['cleanup_confirmed'])
        self.assertEqual(r['child_returncode'], 0)
        self.assertEqual(self.child.kills, 0)
        self.assertIs(self.spawns[0][1]['start_new_session'], False)
        self.assertEqual(self.notices[0]['pid'], 123)
    def test_live_poll_samples_files_and_uses_remaining_budget(self):
        self.child.statuses = [None, 0]
        r = self.run_child()
        self.assertTrue(r['complete'])
        self.assertEqual(self.checks, 3)
        self.assertEqual(self.clock.now, 0.1)
    def test_nonzero_exit_is_preserved(self):
        self.child.statuses = [7]
        r = self.run_child()
        self.assertFalse(r['complete'])
        self.assertEqual(r['failure_type'], 'ChildProcessError')
        self.assertEqual(r['child_returncode'], 7)
    def test_timeout_kills_and_reaps_the_direct_child(self):
        self.child.statuses = []
        r = self.run_child()
        self.assertEqual(r['failure_type'], 'TimeoutExpired')
        self.assertEqual(r['child_returncode'], -9)
        self.assertEqual(self.child.kills, 1)
        self.assertTrue(r['cleanup_confirmed'])
    def test_no_spawn_after_preparation_exhausts_budget(self):
        def check(): self.clock.now = 1
        r = self.run_child(check_files=check)
        self.assertEqual(r['failure_type'], 'TimeoutExpired')
        self.assertFalse(self.spawns)
        self.assertTrue(r['cleanup_confirmed'])
    def test_fast_child_after_deadline_is_not_complete(self):
        def notice(_): self.clock.now = 1
        r = self.run_child(on_spawn=notice)
        self.assertEqual(r['failure_type'], 'TimeoutExpired')
        self.assertEqual(r['child_returncode'], 0)
    def test_failed_spawn_has_no_outstanding_child(self):
        def factory(*args, **kwargs): raise OSError('inert spawn failure')
        r = self.run_child(popen=factory)
        self.assertEqual(r['failure_type'], 'OSError')
        self.assertTrue(r['cleanup_confirmed'])
        self.assertIsNone(r['child_returncode'])
    def test_pid_notice_failure_still_cleans_up(self):
        self.child.statuses = []
        def notice(_): raise OSError('inert receipt failure')
        r = self.run_child(on_spawn=notice)
        self.assertEqual(r['failure_type'], 'OSError')
        self.assertTrue(r['cleanup_confirmed'])
        self.assertEqual(self.child.kills, 1)
    def test_preflight_quota_failure_never_spawns(self):
        def check(): raise ValueError('inert file bound')
        r = self.run_child(check_files=check)
        self.assertEqual(r['failure_type'], 'ValueError')
        self.assertFalse(self.spawns)
    def test_fast_exit_final_quota_failure_is_not_accepted(self):
        def check():
            self.checks += 1
            if self.checks == 2: raise ValueError('inert final bound')
        r = self.run_child(check_files=check)
        self.assertEqual(r['failure_type'], 'ValueError')
        self.assertTrue(r['cleanup_confirmed'])
    def test_live_quota_failure_stops_child(self):
        self.child.statuses = []
        def check():
            self.checks += 1
            if self.checks == 2: raise ValueError('inert live bound')
        r = self.run_child(check_files=check)
        self.assertEqual(r['child_returncode'], -9)
        self.assertTrue(r['cleanup_confirmed'])
    def test_permission_and_wait_failure_leave_cleanup_unconfirmed(self):
        self.child.statuses = []
        self.child.kill_error = PermissionError('inert permission error')
        self.child.wait_error = subprocess.TimeoutExpired(['fixed'], 5)
        r = self.run_child()
        self.assertEqual(r['failure_type'], 'TimeoutExpired')
        self.assertEqual(r['cleanup_errors'], ['PermissionError', 'TimeoutExpired'])
        self.assertFalse(r['cleanup_confirmed'])
        self.assertIsNone(r['child_returncode'])
    def test_failed_cleanup_poll_is_not_assumed_dead(self):
        self.child.statuses = []
        def notice(_): self.child.poll_error = PermissionError('inert poll error')
        r = self.run_child(on_spawn=notice)
        self.assertEqual(r['failure_type'], 'PermissionError')
        self.assertTrue(r['cleanup_confirmed'])
        self.assertEqual(self.child.kills, 1)
    def test_cleanup_poll_error_is_recorded_without_masking_timeout(self):
        self.child.statuses = []
        def clock():
            if self.clock.now >= .2: self.child.poll_error = PermissionError('inert cleanup poll')
            return self.clock.now
        r = self.run_child(clock=clock)
        self.assertEqual(r['failure_type'], 'TimeoutExpired')
        self.assertEqual(r['cleanup_errors'], ['PermissionError'])
        self.assertTrue(r['cleanup_confirmed'])
    def test_disappearing_child_is_reaped_after_lookup_error(self):
        self.child.statuses = []
        def kill():
            self.child.returncode = -9
            raise ProcessLookupError('inert child exit race')
        self.child.kill = kill
        r = self.run_child()
        self.assertEqual(r['failure_type'], 'TimeoutExpired')
        self.assertEqual(r['cleanup_errors'], ['ProcessLookupError'])
        self.assertTrue(r['cleanup_confirmed'])
        self.assertEqual(r['child_returncode'], -9)
    def test_nominal_exit_with_wait_failure_is_not_complete(self):
        self.child.wait_error = subprocess.TimeoutExpired(['fixed'], 5)
        r = self.run_child()
        self.assertEqual(r['failure_type'], 'CleanupUnconfirmed')
        self.assertFalse(r['complete'] or r['cleanup_confirmed'])
    def test_wait_result_mismatch_is_not_reaped_proof(self):
        self.child.wait_result = 'not an exit status'
        r = self.run_child()
        self.assertEqual(r['failure_type'], 'CleanupUnconfirmed')
        self.assertFalse(r['cleanup_confirmed'])
    def test_existing_log_is_preserved_before_spawn(self):
        (self.root/'child.log').write_text('keep')
        r = self.run_child()
        self.assertEqual(r['failure_type'], 'FileExistsError')
        self.assertFalse(self.spawns)
        self.assertEqual((self.root/'child.log').read_text(), 'keep')
    def test_invalid_commands_are_rejected(self):
        for command in [None, [], [''], ['bad\0argument'], [1]]:
            with self.subTest(command=command), self.assertRaises(ValueError): self.run_child(command=command)
        self.assertFalse(self.spawns)
    def test_new_explicit_budget_range_is_accepted(self):
        for seconds in [181, 600]:
            self.child = Child([0])
            r = self.run_child(seconds=seconds, log=self.root/(str(seconds)+'.log'))
            self.assertTrue(r['complete'] and r['cleanup_confirmed'])
            self.assertEqual(r['work_seconds'], seconds)
    def test_invalid_budgets_are_rejected(self):
        for seconds in [True, None, 0, -1, 601, float('nan'), float('inf')]:
            with self.subTest(seconds=seconds), self.assertRaises(ValueError): self.run_child(seconds=seconds)
        self.assertFalse(self.spawns)


if __name__ == '__main__': unittest.main()
