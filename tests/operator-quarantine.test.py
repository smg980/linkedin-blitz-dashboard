"""Synthetic Linux tests. Run as root in a disposable test environment only."""
import importlib.util
import json
import multiprocessing as mp
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'secure/operator-quarantine.py'
spec = importlib.util.spec_from_file_location('operator_quarantine', SOURCE)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def hold(control, pipe):
    admission = q.Admission(control, operator_uid=1)
    admission.acquire()
    pipe.send('admitted')
    pipe.recv()


def delayed_commit(pipe):
    pipe.send('dispatched')
    if pipe.recv() == 'complete':
        pipe.send('committed')


class QuarantineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise RuntimeError('requires disposable Linux root test environment; do not skip boundary tests')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='master-r4-', dir='/run')
        self.parent = Path(self.tmp.name)
        self.parent.chmod(0o755)
        self.control = self.parent / 'control'
        self.control.mkdir(mode=0o700)
        self.lock = self.control / q.Admission.LOCK
        self.lock.touch(mode=0o600)
        self.state = self.control / q.Admission.STATE
        self.state.write_text('{"version":1,"state":"CLEAN"}')
        self.state.chmod(0o600)
        for name in (self.lock, self.state):
            with name.open('rb') as f:
                os.fsync(f.fileno())
        self.a = q.Admission(str(self.control), operator_uid=1)

    def tearDown(self):
        self.a.close()
        self.tmp.cleanup()

    def refused(self, code='LOCK_QUARANTINED'):
        other = q.Admission(str(self.control), operator_uid=1)
        try:
            with self.assertRaises(q.QuarantineError) as error:
                other.acquire()
            self.assertEqual(error.exception.code, code)
        finally:
            other.close()

    def test_active_is_durable_before_admission(self):
        real_sync = os.fsync
        seen = []
        def sync(fd):
            real_sync(fd)
            seen.append(fd)
        with patch.object(q.os, 'fsync', side_effect=sync):
            session = self.a.acquire()
        self.assertEqual(len(seen), 2)
        self.assertEqual(json.loads(self.state.read_text()),
                         {'version': 1, 'state': 'ACTIVE', 'session': session})

    def test_overlap_and_release_never_unlinks_or_cleans(self):
        inode = self.lock.stat().st_ino
        self.a.acquire()
        self.refused('LOCK_HELD')
        self.a.release()
        self.assertEqual(inode, self.lock.stat().st_ino)
        self.refused()

    def test_worker_death_while_separate_commit_can_complete(self):
        ctx = mp.get_context('spawn')
        ready, child = ctx.Pipe()
        remote, remote_child = ctx.Pipe()
        worker = ctx.Process(target=hold, args=(str(self.control), child))
        server = ctx.Process(target=delayed_commit, args=(remote_child,))
        try:
            worker.start()
            self.assertTrue(ready.poll(10))
            self.assertEqual(ready.recv(), 'admitted')
            server.start()
            self.assertTrue(remote.poll(10))
            self.assertEqual(remote.recv(), 'dispatched')
            os.kill(worker.pid, signal.SIGKILL)
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertTrue(server.is_alive())
            self.refused()
            remote.send('complete')
            self.assertTrue(remote.poll(10))
            self.assertEqual(remote.recv(), 'committed')
            self.refused()
        finally:
            for proc in (worker, server):
                if proc.pid:
                    if proc.is_alive():
                        proc.kill()
                    proc.join(10)
            for pipe in (ready, child, remote, remote_child):
                pipe.close()

    def test_close_has_no_completion_attestation_or_clean_transition(self):
        for reason in ('IPC_LOST', 'OUTCOME_UNKNOWN', 'SHUTDOWN_FAILED', 'SHUTDOWN_TIMEOUT'):
            with self.subTest(reason=reason):
                # A fresh project for each case, never reset an admitted one.
                directory = self.parent / reason
                directory.mkdir(mode=0o700)
                (directory / 'operator.lock').touch(mode=0o600)
                state = directory / 'state.json'
                state.write_text('{"version":1,"state":"CLEAN"}')
                state.chmod(0o600)
                admission = q.Admission(str(directory), operator_uid=1)
                try:
                    admission.acquire()
                    admission.close()  # no attestation is accepted
                    again = q.Admission(str(directory), operator_uid=1)
                    try:
                        with self.assertRaisesRegex(q.QuarantineError, 'LOCK_QUARANTINED'):
                            again.acquire()
                    finally:
                        again.close()
                finally:
                    admission.close()

    def test_partial_write_and_file_sync_fail_before_grant(self):
        for call in ('write', 'fsync', 'rename'):
            with self.subTest(call=call):
                with patch.object(q.os, call, side_effect=OSError('synthetic')):
                    with self.assertRaises(q.QuarantineError) as error:
                        self.a.acquire()
                self.assertFalse(error.exception.cleanup_complete)
                self.assertIsNone(self.a.session)
                self.assertEqual(self.a.lock_fd, -1)
                self.assertEqual(json.loads(self.state.read_text())['state'], 'CLEAN')

    def test_directory_sync_failure_retains_active_without_grant(self):
        sync = os.fsync
        def fail_directory(fd):
            if fd == self.a.directory_fd:
                raise OSError('synthetic')
            sync(fd)
        with patch.object(q.os, 'fsync', side_effect=fail_directory):
            with self.assertRaises(q.QuarantineError):
                self.a.acquire()
        self.assertIsNone(self.a.session)
        self.refused()

    def test_close_failure_is_reported_without_clean(self):
        self.a.acquire()
        close = os.close
        def fail(fd):
            close(fd)
            raise OSError('synthetic')
        with patch.object(q.os, 'close', side_effect=fail):
            with self.assertRaises(q.QuarantineError) as error:
                self.a.release()
        self.assertFalse(error.exception.cleanup_complete)
        self.refused()

    def test_state_corruption_and_missing_state_refuse(self):
        for raw in ('', '{}', '{"version":true,"state":"CLEAN"}', '{"version":1,"state":"CLEAN","state":"ACTIVE"}',
                    '{"version":1,"state":"CLEAN","extra":0}', 'x' * 513):
            self.state.write_text(raw)
            other = q.Admission(str(self.control), operator_uid=1)
            try:
                with self.assertRaises(q.QuarantineError):
                    other.acquire()
            finally:
                other.close()
        self.state.unlink()
        self.refused('LOCK_ACQUIRE_UNCONFIRMED')

    def test_no_recovery_or_data_operations_exist(self):
        self.assertEqual({name for name in dir(q.Admission) if not name.startswith('_')},
                         {'LOCK', 'STATE', 'LIMIT', 'acquire', 'release', 'close'})
        self.a.acquire()
        self.a.release()
        self.refused()

    def test_wrong_owner_boundary_and_symlink_are_refused(self):
        with self.assertRaises(q.QuarantineError):
            q.Admission(str(self.control), operator_uid=os.geteuid())
        self.parent.chmod(0o777)
        with self.assertRaisesRegex(q.QuarantineError, 'LOCK_UNTRUSTED_ANCESTRY'):
            q.Admission(str(self.control), operator_uid=1)
        self.parent.chmod(0o755)
        self.lock.unlink()
        self.lock.symlink_to(self.state)
        self.refused('LOCK_ACQUIRE_UNCONFIRMED')

    def test_ordinary_identity_cannot_read_replace_or_reset_control(self):
        uid = pwd.getpwnam('daemon').pw_uid
        gid = pwd.getpwnam('daemon').pw_gid
        attack = '''import os,sys
for source,target in [(sys.argv[1],None),(sys.argv[2],None)]:
 try: os.open(source,os.O_RDWR)
 except PermissionError: pass
 else: sys.exit(2)
try: os.rename(sys.argv[1],sys.argv[1]+'.moved')
except PermissionError: pass
else: sys.exit(3)
'''
        child = subprocess.run([sys.executable, '-c', attack, str(self.state), str(self.lock)],
                               user=uid, group=gid, extra_groups=[], capture_output=True)
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_restricted_worker_identity_can_admit_but_operator_cannot_reset(self):
        worker = pwd.getpwnam('nobody')
        operator = pwd.getpwnam('daemon')
        directory = self.parent / 'worker-control'
        directory.mkdir(mode=0o700)
        lock = directory / 'operator.lock'
        state = directory / 'state.json'
        lock.touch(mode=0o600)
        state.write_text('{"version":1,"state":"CLEAN"}')
        state.chmod(0o600)
        for entry in (directory, lock, state):
            os.chown(entry, worker.pw_uid, worker.pw_gid)
        script = '''import importlib.util,sys
spec=importlib.util.spec_from_file_location('q',sys.argv[1])
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
a=q.Admission(sys.argv[2],operator_uid=int(sys.argv[3]))
a.acquire();a.close()
b=q.Admission(sys.argv[2],operator_uid=int(sys.argv[3]))
try: b.acquire()
except q.QuarantineError as e:
 assert e.code=='LOCK_QUARANTINED'
else: raise AssertionError('admitted twice')
finally: b.close()
'''
        result = subprocess.run([sys.executable, '-c', script, str(SOURCE),
                                 str(directory), str(operator.pw_uid)],
                                user=worker.pw_uid, group=worker.pw_gid,
                                extra_groups=[], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        attack = "import os,sys; os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC)"
        result = subprocess.run([sys.executable, '-c', attack, str(state)],
                                user=operator.pw_uid, group=operator.pw_gid,
                                extra_groups=[], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'PermissionError', result.stderr)
        self.assertEqual(json.loads(state.read_text())['state'], 'ACTIVE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
