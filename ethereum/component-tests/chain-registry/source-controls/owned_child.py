"""Control one freshly spawned, fixed, non-forking child; never signal a group.

Callers pin the command and its imports and must stop/refrain from releasing
their lease when cleanup_confirmed is false. This does not supervise arbitrary
descendants or unrelated programs. File checks are sampled acceptance checks.
"""
import math
import subprocess
import time


def run_owned_child(command, cwd, log, seconds, check_files, on_spawn,
                    popen=subprocess.Popen, clock=time.monotonic, sleep=time.sleep):
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x and '\0' not in x for x in command):
        raise ValueError('Invalid fixed command')
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 600:
        raise ValueError('Child work budget must be finite and at most 600 seconds')
    record = {'command': list(command), 'work_seconds': seconds, 'complete': False,
              'cleanup_confirmed': False, 'cleanup_errors': [], 'child_returncode': None}
    process = None
    began = clock()
    deadline = began + seconds
    failure = None
    try:
        check_files()
        if clock() >= deadline:
            raise subprocess.TimeoutExpired(command, seconds)
        with log.open('xb') as stream:
            process = popen(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                            start_new_session=False)
            record['pid'] = process.pid
            on_spawn(dict(record))
            while process.poll() is None:
                remaining = deadline - clock()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, seconds)
                check_files()
                sleep(min(0.1, remaining))
            record['child_returncode'] = process.returncode
            check_files()
            if clock() >= deadline:
                raise subprocess.TimeoutExpired(command, seconds)
            if process.returncode != 0:
                raise ChildProcessError('Fixed child returned a nonzero status')
    except BaseException as error:
        failure = type(error).__name__
    finally:
        if process is None:
            record['cleanup_confirmed'] = True
        else:
            # Only the Popen object created in this call is eligible. No PID
            # parameter, killpg, signal-zero liveness check, or broad scan/kill.
            try:
                running = process.poll() is None
            except BaseException as error:
                record['cleanup_errors'].append(type(error).__name__)
                running = True
            if running:
                try:
                    process.kill()
                except BaseException as error:
                    record['cleanup_errors'].append(type(error).__name__)
            try:
                result = process.wait(timeout=5)
                record['child_returncode'] = process.returncode
                record['cleanup_confirmed'] = type(result) is int and result == process.returncode
            except BaseException as error:
                record['cleanup_errors'].append(type(error).__name__)
                record['child_returncode'] = process.returncode
        if failure is None and (not record['cleanup_confirmed'] or record['cleanup_errors']):
            failure = 'CleanupUnconfirmed'
        record['failure_type'] = failure
        record['complete'] = failure is None and record['child_returncode'] == 0 and record['cleanup_confirmed']
        record['elapsed_with_cleanup_seconds'] = clock() - began
    return record
