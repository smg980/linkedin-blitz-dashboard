"""Disposable Linux/root integration tests; no Firebase/production resources."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]


class SupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise RuntimeError('disposable Linux root fixture required')
        cls.runtime = tempfile.TemporaryDirectory(prefix='master-r4-runtime-', dir='/opt')
        Path(cls.runtime.name).chmod(0o755)
        cls.node = Path(cls.runtime.name) / 'node'
        shutil.copyfile(shutil.which('node'), cls.node)
        cls.node.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.runtime.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='master-supervisor-', dir='/opt')
        self.base = Path(self.tmp.name)
        self.base.chmod(0o755)
        self.root = self.base / 'code'
        self.root.mkdir()
        for name in ('scripts', 'secure'):
            (self.root / name).mkdir()
        for name in ('scripts/trusted-executor-supervisor.py', 'secure/operator-quarantine.py'):
            shutil.copyfile(ROOT / name, self.root / name)
        self.caller = pwd.getpwnam('daemon')
        self.executor = pwd.getpwnam('bin')
        self.control = pwd.getpwnam('nobody')
        control = self.base / 'control'
        control.mkdir(mode=0o700)
        (control / 'operator.lock').touch(mode=0o600)
        self.state = control / 'state.json'
        self.state.write_text('{"version":1,"state":"CLEAN"}')
        self.state.chmod(0o600)
        for p in (control, self.state, control / 'operator.lock'):
            os.chown(p, self.control.pw_uid, self.control.pw_gid)
        self.config = self.base / 'config.json'
        self.config.write_text(json.dumps({
            'version': 1, 'caller_uid': self.caller.pw_uid,
            'executor_uid': self.executor.pw_uid, 'control_uid': self.control.pw_uid,
            'control': str(control), 'project': 'demo-executor',
            'node': str(self.node), 'home': self.executor.pw_dir,
        }))
        # This is a root-controlled test worker, never a client-selected program.
        # It uses real HTTP with a separately delayed server-side operation.
        (self.root / 'scripts/trusted-executor-worker.mjs').write_text('''
import readline from 'node:readline';
const input = readline.createInterface({input: process.stdin});
for await (const line of input) {
 const request=JSON.parse(line);
 const response=await fetch(request.env.TEST_ENDPOINT,{method:'POST'});
 await response.text();
 const settled=request.env.TEST_RESULT==='known';
 const completion=settled?{result:{outcome:'committed-verified'}}:{error:{code:'SYNTHETIC_UNKNOWN',outcome:'unknown'}};
 console.log(JSON.stringify({session:request.session,settled,completion}));
 process.exitCode=Number(request.env.TEST_EXIT||0);
}
''')
        self.children = []
        self.received = threading.Event()
        self.finish = threading.Event()
        self.completed = threading.Event()
        fixture = self
        class Server(BaseHTTPRequestHandler):
            def do_POST(self):
                fixture.received.set()
                if not fixture.finish.wait(15):
                    return
                fixture.completed.set()  # commit may finish even after socket loss
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(b'committed')
                except BrokenPipeError:
                    pass
            def log_message(self, *_args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Server)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        self.finish.set()
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=15)
            for stream in (child.stdout, child.stderr):
                if stream and not stream.closed:
                    stream.close()
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def start(self, result='known', operation='campaign', request=None, frontend=False):
        path = self.base / ('socket-' + str(len(self.children)))
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(path))
        path.chmod(0o666)
        listener.listen(1)
        script = '''import socket,json,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall((sys.argv[2]+'\\n').encode())
print(s.makefile('rb').readline().decode(),end='')
'''
        request = request or {'version': 1, 'operation': operation, 'args': [],
                   'env': {'TEST_ENDPOINT': f'http://127.0.0.1:{self.server.server_port}/Commit',
                           'TEST_RESULT': result}}
        command = [sys.executable, '-c', script, str(path), json.dumps(request)]
        environment = {'PATH': '/usr/bin:/bin', 'HOME': self.caller.pw_dir}
        if frontend:
            filename = 'blitz-campaign-store.mjs' if request['operation'] == 'campaign' else 'd0-owner-emulator.mjs'
            command = [str(self.node), str(self.root / 'scripts' / filename), *request['args']]
            environment = {'PATH': '/usr/bin:/bin', 'HOME': self.caller.pw_dir,
                           **request['env'], 'BLITZ_EXECUTOR_SOCKET': str(path)}
        client = subprocess.Popen(command, env=environment,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  user=self.caller.pw_uid, group=self.caller.pw_gid,
                                  extra_groups=[])
        self.children.append(client)
        connection, _ = listener.accept()
        listener.close()
        # Socket activation gives the root bootstrap only a connected socket.
        activate = 'import os,sys,runpy;os.dup2(int(sys.argv[1]),3);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")'
        supervisor = subprocess.Popen([sys.executable, '-I', '-c', activate, str(connection.fileno()), str(self.root / 'scripts/trusted-executor-supervisor.py'), str(self.config)],
                                      pass_fds=(connection.fileno(),),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(supervisor)
        connection.close()
        return client, supervisor

    def real_worker(self):
        if not (ROOT / 'node_modules/firebase-admin').is_dir():
            raise RuntimeError('locked npm dependencies required for actual SDK boundary tests')
        def link(source, target):
            if Path(target).exists():
                Path(target).unlink()
            info = os.stat(source)
            if info.st_uid == 0 and not info.st_mode & 0o022:
                os.link(source, target)
            else:
                shutil.copyfile(source, target)
                os.chmod(target, info.st_mode & 0o755)
        for name in ('scripts', 'secure', 'tests', 'node_modules', 'docs'):
            shutil.copytree(ROOT / name, self.root / name, symlinks=True,
                            copy_function=link, dirs_exist_ok=True)
        for base, dirs, _files in os.walk(self.root):
            for name in dirs:
                path = Path(base) / name
                if not path.is_symlink():
                    path.chmod(0o755)
        self.private = self.base / 'private'
        self.private.mkdir(mode=0o700)
        os.chown(self.private, self.executor.pw_uid, self.executor.pw_gid)
        self.sdk = subprocess.Popen([str(self.node), str(self.root / 'tests/helpers/executor-sdk-server.mjs'),
                                     str(self.private), str(self.executor.pw_uid), str(self.executor.pw_gid)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    bufsize=0, env={'PATH': '/usr/bin:/bin', 'HOME': str(self.base)})
        self.children.append(self.sdk)
        self.sdk_ready = self.sdk_event('ready')

    def sdk_event(self, expected):
        for _ in range(20):
            ready, _, _ = select.select([self.sdk.stdout], [], [], 15)
            if not ready:
                raise AssertionError(f'SDK server missing {expected}')
            line = self.sdk.stdout.readline()
            if not line:
                raise AssertionError(self.sdk.stderr.read().decode())
            message = json.loads(line)
            if message['event'] == expected:
                return message
        raise AssertionError(f'SDK server missing {expected}')

    def sdk_command(self, value):
        self.sdk.stdin.write((json.dumps(value) + '\n').encode())
        self.sdk.stdin.flush()

    def campaign_request(self):
        ready = self.sdk_ready
        return {'version': 1, 'operation': 'campaign', 'args': [
            'write', '--target', 'emulator', '--project', 'demo-executor',
            '--input', ready['input'], '--expect-current', 'none',
            '--receipt', str(self.private / 'receipt.json'), '--apply'], 'env': {
                'BLITZ_STORE_UID': ready['uid'], 'BLITZ_STORE_CONFIRM_UID': ready['uid'],
                'BLITZ_STORE_APPROVAL': 'WRITE:' + ready['digest'],
                'FIRESTORE_EMULATOR_HOST': ready['firestore'],
                'FIREBASE_AUTH_EMULATOR_HOST': ready['auth'],
            }}

    def test_actual_sdk_and_frontend_campaign_then_d0_repeat_safely(self):
        self.real_worker()
        # Apply validates private paths inside the protected worker. The normal
        # client cannot inspect service-private storage before admission.
        for backup, code in [
                (self.root / 'backup.json', 'STORE_BACKUP_INSIDE_REPOSITORY'),
                (Path(self.sdk_ready['input']), 'STORE_BACKUP_EXISTS'),
                (self.private / 'missing' / 'backup.json', 'STORE_BACKUP_DIRECTORY_MISSING')]:
            invalid = self.campaign_request()
            invalid['args'].extend(['--backup', str(backup)])
            client, supervisor = self.start(request=invalid)
            refused = self.response(client, supervisor)
            self.assertEqual(refused['error']['code'], code)
            self.assertEqual(refused['error']['outcome'], 'refused-before-write')
            self.assertEqual(refused['quarantine'], 'CLEAN')
        invalid = self.campaign_request()
        invalid['env']['BLITZ_STORE_APPROVAL'] = 'WRITE:wrong'
        client, supervisor = self.start(request=invalid)
        refused = self.response(client, supervisor)
        self.assertEqual(refused['error']['outcome'], 'refused-before-write')
        self.assertEqual(refused['quarantine'], 'CLEAN')
        client, supervisor = self.start(request=self.campaign_request(), frontend=True)
        result = self.response(client, supervisor)
        self.assertEqual(result['outcome'], 'committed-verified')
        self.assertEqual(result['quarantine'], 'CLEAN')
        request = {'version': 1, 'operation': 'd0', 'args': ['--grant', '--apply'], 'env': {
            'BLITZ_D0_PROJECT': 'demo-executor', 'BLITZ_D0_SYNTHETIC_UID': self.sdk_ready['uid'],
            'BLITZ_D0_CONFIRM_UID': self.sdk_ready['uid'], 'BLITZ_D0_APPROVAL': 'APPLY_SYNTHETIC_ONLY',
            'FIREBASE_AUTH_EMULATOR_HOST': self.sdk_ready['auth'],
        }}
        client, supervisor = self.start(request=request, frontend=True)
        result = self.response(client, supervisor)
        self.assertTrue(result['verified'])
        self.assertEqual(result['quarantine'], 'CLEAN')
        self.sdk_command({'status': True})
        status = self.sdk_event('status')
        self.assertEqual(status['commits'], 1)
        self.assertEqual(status['authWrites'], 1)

    def fault_shutdown(self, receipt_failure=False):
        # Offline, root-owned fixture instrumentation only. Break the hard link
        # first so this never changes the reviewed source or normal worker.
        path = self.root / 'scripts/trusted-executor-worker.mjs'
        source = path.read_text()
        path.unlink()
        prefix = '''import { createRequire } from 'node:module';
const testRequire=createRequire(import.meta.url);
const adminRequire=createRequire(testRequire.resolve('firebase-admin/firestore'));
const TestFirestore=testRequire(adminRequire.resolve('@google-cloud/firestore')).Firestore;
const realTerminate=TestFirestore.prototype.terminate;
TestFirestore.prototype.terminate=async function(){await realTerminate.call(this);throw new Error('synthetic shutdown unconfirmed');};
'''
        if receipt_failure:
            source = source.replace('main(request.args, env, { executorSession })',
                "main(request.args, env, { executorSession, privateFileHooks: { beforeRename: async () => { if (++testRenames === 2) throw new Error('synthetic receipt failure'); } } })")
            prefix += 'let testRenames=0;\n'
        path.write_text(prefix + source)

    def test_actual_cli_exit_10_preserves_committed_result_on_shutdown_failure(self):
        self.real_worker()
        self.fault_shutdown()
        client, supervisor = self.start(request=self.campaign_request(), frontend=True)
        stdout, stderr = client.communicate(timeout=30)
        supervisor.wait(timeout=30)
        self.assertEqual(client.returncode, 10, stderr)
        self.assertEqual(json.loads(stdout)['outcome'], 'committed-verified')
        self.assertIn(b'FIRESTORE_TERMINATE_FAILED', stderr)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_actual_cli_exit_11_preserves_pre_write_refusal_on_shutdown_failure(self):
        self.real_worker()
        self.fault_shutdown()
        request = self.campaign_request()
        request['env']['BLITZ_STORE_APPROVAL'] = 'WRITE:wrong'
        client, supervisor = self.start(request=request, frontend=True)
        _, stderr = client.communicate(timeout=30)
        supervisor.wait(timeout=30)
        self.assertEqual(client.returncode, 11, stderr)
        self.assertIn(b'STORE_REFUSED STORE_APPROVAL_REQUIRED', stderr)
        self.sdk_command({'status': True})
        self.assertEqual(self.sdk_event('status')['commits'], 0)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_actual_cli_exit_14_preserves_eligibility_changed_outcome(self):
        self.real_worker()
        self.fault_shutdown()
        self.sdk_command({'mode': 'eligibility-changed'})
        self.sdk_event('mode-set')
        client, supervisor = self.start(request=self.campaign_request(), frontend=True)
        _, stderr = client.communicate(timeout=30)
        supervisor.wait(timeout=30)
        self.assertEqual(client.returncode, 14, stderr)
        self.assertIn(b'STORE_ELIGIBILITY_CHANGED_DURING_COMMIT', stderr)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_actual_cli_exit_15_preserves_receipt_failure_after_commit(self):
        self.real_worker()
        self.fault_shutdown(receipt_failure=True)
        client, supervisor = self.start(request=self.campaign_request(), frontend=True)
        _, stderr = client.communicate(timeout=30)
        supervisor.wait(timeout=30)
        self.assertEqual(client.returncode, 15, stderr)
        self.assertIn(b'STORE_RECEIPT_FAILED_AFTER_COMMIT', stderr)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_actual_sdk_unknown_commit_keeps_quarantine(self):
        self.real_worker()
        self.sdk_command({'mode': 'unknown'})
        self.sdk_event('mode-set')
        client, supervisor = self.start(request=self.campaign_request(), frontend=True)
        _, stderr = client.communicate(timeout=30)
        supervisor.wait(timeout=30)
        self.assertEqual(client.returncode, 13, stderr)
        self.assertIn(b'STORE_UNRESOLVED STORE_OUTCOME_UNKNOWN', stderr)
        receipt = json.loads((self.private / 'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'OUTCOME_UNKNOWN')
        second, second_supervisor = self.start(request=self.campaign_request())
        result = self.response(second, second_supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.sdk_command({'status': True})
        self.assertEqual(self.sdk_event('status')['commits'], 1)

    def test_actual_sdk_worker_death_retains_active_until_after_delayed_commit(self):
        self.real_worker()
        self.sdk_command({'mode': 'delay'})
        self.sdk_event('mode-set')
        client, supervisor = self.start(request=self.campaign_request())
        self.sdk_event('commit-started')
        children = Path(f'/proc/{supervisor.pid}/task/{supervisor.pid}/children').read_text().split()
        self.assertEqual(len(children), 1)
        os.kill(int(children[0]), signal.SIGKILL)
        result = self.response(client, supervisor)
        self.assertEqual(result['error']['outcome'], 'unknown')
        self.sdk_command({'release': True})
        self.sdk_event('applied')
        second, second_supervisor = self.start(request=self.campaign_request())
        result = self.response(second, second_supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.sdk_command({'status': True})
        self.assertEqual(self.sdk_event('status')['commits'], 1)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_actual_sdk_supervisor_death_does_not_free_a_live_issuer(self):
        self.real_worker()
        self.sdk_command({'mode': 'delay'})
        self.sdk_event('mode-set')
        client, supervisor = self.start(request=self.campaign_request(), frontend=True)
        self.sdk_event('commit-started')
        children = Path(f'/proc/{supervisor.pid}/task/{supervisor.pid}/children').read_text().split()
        self.assertEqual(len(children), 1)
        supervisor.kill()
        supervisor.wait(timeout=10)
        _, stderr = client.communicate(timeout=15)
        self.assertEqual(client.returncode, 13, stderr)
        self.assertIn(b'STORE_OUTCOME_UNKNOWN', stderr)
        second, second_supervisor = self.start(request=self.campaign_request())
        result = self.response(second, second_supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.sdk_command({'release': True})
        self.sdk_event('applied')
        try:
            fd = os.pidfd_open(int(children[0]))
        except ProcessLookupError:
            fd = None
        if fd is not None:
            try:
                self.assertTrue(select.select([fd], [], [], 15)[0], 'old SDK child did not exit')
            finally:
                os.close(fd)
        self.sdk_command({'status': True})
        self.assertEqual(self.sdk_event('status')['commits'], 1)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def response(self, client, supervisor):
        stdout, stderr = client.communicate(timeout=15)
        supervisor.wait(timeout=15)
        self.assertEqual(client.returncode, 0, stderr)
        return json.loads(stdout)

    def test_known_terminal_worker_allows_repeated_admission(self):
        for _ in range(2):
            self.received.clear()
            self.finish.clear()
            client, supervisor = self.start()
            self.assertTrue(self.received.wait(10))
            self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')
            self.finish.set()
            result = self.response(client, supervisor)
            self.assertEqual(result['quarantine'], 'CLEAN')
            self.assertEqual(json.loads(self.state.read_text())['state'], 'CLEAN')

    def test_unknown_terminal_worker_retains_active(self):
        client, supervisor = self.start('unknown')
        self.assertTrue(self.received.wait(10))
        self.finish.set()
        result = self.response(client, supervisor)
        self.assertEqual(result['error']['outcome'], 'unknown')
        self.assertEqual(result['quarantine'], 'ACTIVE')
        second, second_supervisor = self.start()
        result = self.response(second, second_supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')

    def test_supervisor_dies_while_worker_commit_can_still_finish(self):
        client, supervisor = self.start()
        self.assertTrue(self.received.wait(10))
        os.kill(supervisor.pid, signal.SIGKILL)
        supervisor.wait(timeout=10)
        second, second_supervisor = self.start()
        result = self.response(second, second_supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.finish.set()
        self.assertTrue(self.completed.wait(10))
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_lost_client_connection_retains_active(self):
        client, supervisor = self.start()
        self.assertTrue(self.received.wait(10))
        client.kill()
        client.wait(timeout=10)
        self.finish.set()
        supervisor.wait(timeout=15)
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_sdk_worker_dies_after_dispatch_before_remote_completion(self):
        client, supervisor = self.start()
        self.assertTrue(self.received.wait(10))
        children = Path(f'/proc/{supervisor.pid}/task/{supervisor.pid}/children').read_text().split()
        self.assertEqual(len(children), 1)
        os.kill(int(children[0]), signal.SIGKILL)
        result = self.response(client, supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.finish.set()
        self.assertTrue(self.completed.wait(10))
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_no_ordinary_clean_operation(self):
        client, supervisor = self.start(operation='clean')
        result = self.response(client, supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.assertFalse(self.received.is_set())

    def test_control_namespace_cannot_be_hidden_under_code_git_directory(self):
        hidden = self.root / '.git'
        hidden.mkdir()
        control = hidden / 'control'
        control.mkdir(mode=0o700)
        os.chown(control, self.control.pw_uid, self.control.pw_gid)
        for name, value in [('operator.lock', ''), ('state.json', '{"version":1,"state":"CLEAN"}')]:
            entry = control / name
            entry.write_text(value)
            entry.chmod(0o600)
            os.chown(entry, self.control.pw_uid, self.control.pw_gid)
        config = json.loads(self.config.read_text())
        config['control'] = str(control)
        self.config.write_text(json.dumps(config))
        client, supervisor = self.start()
        result = self.response(client, supervisor)
        self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
        self.assertFalse(self.received.is_set())

    def test_known_outcome_survives_abnormal_exit_but_cannot_clean(self):
        request = {'version': 1, 'operation': 'campaign', 'args': [], 'env': {
            'TEST_ENDPOINT': f'http://127.0.0.1:{self.server.server_port}/Commit',
            'TEST_RESULT': 'known', 'TEST_EXIT': '1',
        }}
        client, supervisor = self.start(request=request)
        self.assertTrue(self.received.wait(10))
        self.finish.set()
        result = self.response(client, supervisor)
        self.assertEqual(result['result']['outcome'], 'committed-verified')
        self.assertFalse(result['cleanupComplete'])
        self.assertIn('EXECUTOR_TERMINATION_UNCONFIRMED', result['cleanupFailures'])
        self.assertEqual(result['quarantine'], 'ACTIVE')
        self.assertEqual(json.loads(self.state.read_text())['state'], 'ACTIVE')

    def test_clean_transition_failure_preserves_known_outcome(self):
        module = self.root / 'secure/operator-quarantine.py'
        source = module.read_text()
        # Offline immutable test copies only: no service request can inject a
        # fault or choose transition behavior. Exercise both sides of rename.
        for after in (False, True):
            with self.subTest(after_transition=after):
                self.state.write_text('{"version":1,"state":"CLEAN"}')
                self.received.clear()
                self.finish.clear()
                module.write_text(source + '\n_original = Admission._settled_by_trusted_executor\n'
                    'def _fail_transition(self):\n'
                    + ('    _original(self)\n' if after else '')
                    + '    raise OSError("synthetic persistence failure")\n'
                    'Admission._settled_by_trusted_executor = _fail_transition\n')
                client, supervisor = self.start()
                self.assertTrue(self.received.wait(10))
                self.finish.set()
                result = self.response(client, supervisor)
                self.assertEqual(result['result']['outcome'], 'committed-verified')
                self.assertFalse(result['cleanupComplete'])
                self.assertEqual(result['quarantine'], 'ACTIVE_OR_UNCONFIRMED')
                self.assertIn('QUARANTINE_CLEAN_UNCONFIRMED', result['cleanupFailures'])
                self.assertEqual(json.loads(self.state.read_text())['state'], 'CLEAN' if after else 'ACTIVE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
