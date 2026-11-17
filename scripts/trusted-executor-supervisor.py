#!/usr/bin/python3 -I
"""One socket-activated request. Root bootstrap drops all privileges before admission.

This is not an installer or a sudo rule. A reviewed OS service must supply a
connected Unix socket as fd 3 and a root-controlled configuration. Ordinary
clients cannot select a program, control path, identity or CLEAN operation.
"""
import sys
if not sys.flags.isolated:
    raise SystemExit('EXECUTOR_ISOLATED_PYTHON_REQUIRED')
sys.dont_write_bytecode = True
import importlib.util
import json
import errno
import os
from pathlib import Path
import pwd
import socket
import stat
import struct
import subprocess
import threading

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('quarantine', ROOT / 'secure/operator-quarantine.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
LIMIT = 4 * 1024 * 1024


class ExecutionUnconfirmed(Exception):
    def __init__(self, dispatched):
        self.dispatched = dispatched


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('EXECUTOR_CONFIG_UNTRUSTED')
    # npm's immutable .bin entries are file symlinks within this code tree.
    # Never accept directory symlinks or targets outside the reviewed tree.
    if path.is_symlink():
        if directory or path.lstat().st_uid != 0 or ROOT not in path.resolve().parents:
            raise ValueError('EXECUTOR_CONFIG_UNTRUSTED')
        for parent in path.parents:
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('EXECUTOR_CONFIG_UNTRUSTED')
        path = path.resolve(strict=True)
    for entry in [path, *path.parents]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('EXECUTOR_CONFIG_UNTRUSTED')
    if directory != path.is_dir():
        raise ValueError('EXECUTOR_CONFIG_UNTRUSTED')


def frame(stream):
    raw = stream.readline(LIMIT + 1)
    if not raw.endswith(b'\n') or len(raw) > LIMIT:
        raise ValueError('EXECUTOR_FRAME_INVALID')
    return json.loads(raw)


def serve(config_path, connection):
    if sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError('EXECUTOR_BOOTSTRAP_REQUIRED')
    trusted(config_path)
    trusted(ROOT, directory=True)
    # All service source/dependencies must be immutable to either unprivileged
    # identity. No writable NODE_PATH, loader, config or executable is accepted.
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d != '.git']
        for name in dirs + files:
            trusted(Path(base) / name, directory=(Path(base) / name).is_dir())
    config = json.loads(Path(config_path).read_text())
    allowed = {'version', 'caller_uid', 'executor_uid', 'control_uid', 'control',
               'project', 'node', 'home'}
    if set(config) != allowed or type(config['version']) is not int or config['version'] != 1:
        raise ValueError('EXECUTOR_CONFIG_INVALID')
    if not Path(config['control']).is_absolute() or Path(config['control']).resolve().is_relative_to(ROOT):
        raise ValueError('EXECUTOR_CONTROL_NAMESPACE_INVALID')
    identities = [config[k] for k in ('caller_uid', 'executor_uid', 'control_uid')]
    if len(set(identities)) != 3 or any(type(uid) is not int or uid <= 0 for uid in identities):
        raise ValueError('EXECUTOR_IDENTITIES_INVALID')
    peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if peer[1] != config['caller_uid']:
        raise ValueError('EXECUTOR_CALLER_DENIED')
    trusted(config['node'])
    if Path(config['node']).stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError('EXECUTOR_PRIVILEGED_RUNTIME')
    try:
        if os.getxattr(config['node'], 'security.capability'):
            raise ValueError('EXECUTOR_PRIVILEGED_RUNTIME')
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
    request = frame(connection.makefile('rb', buffering=0))
    if (not isinstance(request, dict) or set(request) != {'version', 'operation', 'args', 'env'}
            or type(request['version']) is not int or request['version'] != 1
            or request['operation'] not in ('campaign', 'd0')
            or not isinstance(request['args'], list) or len(request['args']) > 32
            or any(not isinstance(arg, str) or len(arg) > 4096 for arg in request['args'])
            or not isinstance(request['env'], dict)
            or any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 4096
                   for k, v in request['env'].items())):
        raise ValueError('EXECUTOR_REQUEST_INVALID')
    executor = pwd.getpwuid(config['executor_uid'])
    control = pwd.getpwuid(config['control_uid'])
    env = {'PATH': '/usr/bin:/bin', 'HOME': config['home'],
           'BLITZ_EXECUTOR_PROJECT': config['project'],
           'BLITZ_EXECUTOR_UID': str(executor.pw_uid)}
    # Spawn before dropping the bootstrap identity. The trusted worker is
    # blocked on its private stdin: it cannot initialize an SDK before ACTIVE.
    child = subprocess.Popen([config['node'], str(ROOT / 'scripts/trusted-executor-worker.mjs')],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, cwd=ROOT, env=env,
                             user=executor.pw_uid, group=executor.pw_gid,
                             extra_groups=[], close_fds=True)
    os.setgroups([])
    os.setgid(control.pw_gid)
    os.setuid(control.pw_uid)
    capabilities = Path('/proc/self/status').read_text().splitlines()
    for line in capabilities:
        if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:')) and int(line.split()[1], 16):
            raise ValueError('EXECUTOR_PRIVILEGE_DROP_UNCONFIRMED')
    admission = None
    lost = threading.Event()
    done = threading.Event()
    dispatched = False

    def monitor():
        try:
            # No further input frames are permitted, including a fake CLEAN.
            connection.recv(1)
        finally:
            if not done.is_set():
                lost.set()
                # Different identity: do not assume we can kill the child.
                # Even successful killing would not cancel a remote commit.
                try:
                    child.stdin.close()
                except OSError:
                    pass

    try:
        admission = q.Admission(config['control'], operator_uid=executor.pw_uid)
        session = admission.acquire()
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        dispatched = True
        child.stdin.write((json.dumps({**request, 'session': session}) + '\n').encode())
        child.stdin.flush()
        child.stdin.close()
        response = frame(child.stdout)
        # EOF and normal exit are necessary to exclude future issuance by this
        # child. They are never sufficient settlement evidence on their own.
        trailing = child.stdout.read(1)
        status = child.wait()
        if (not isinstance(response, dict)
                or set(response) != {'session', 'settled', 'completion'}
                or response['session'] != session or type(response['settled']) is not bool):
            raise ValueError('EXECUTOR_TERMINATION_UNCONFIRMED')
        completion = response['completion']
        if not isinstance(completion, dict) or set(completion) not in ({'result'}, {'error'}):
            raise ValueError('EXECUTOR_PROOF_INVALID')
        value = completion.get('error', completion.get('result'))
        if not isinstance(value, dict):
            raise ValueError('EXECUTOR_PROOF_INVALID')
        if response['settled'] and (value.get('outcome') not in (
                'committed-verified', 'committed-eligibility-changed', 'refused-before-write')
                or value.get('cleanupComplete') is False):
            raise ValueError('EXECUTOR_PROOF_INVALID')
        terminated = status == 0 and not trailing
        clean = response['settled'] and terminated and not lost.is_set()
        transition_failed = False
        if clean:
            try:
                admission._settled_by_trusted_executor()
                if lost.is_set():
                    admission._retain_active_after_lost_reply()
                    clean = False
            except Exception:
                # A durable-state error cannot erase an already known result.
                # The transition may have renamed before fsync failed, so do
                # not claim either on-disk state has been confirmed.
                transition_failed = True
                clean = False
        response = response['completion']
        response['quarantine'] = ('ACTIVE_OR_UNCONFIRMED' if transition_failed
                                  else 'CLEAN' if clean else 'ACTIVE')
        if not clean:
            response['cleanupComplete'] = False
            response['cleanupFailures'] = ['EXECUTOR_QUARANTINED']
            if transition_failed:
                response['cleanupFailures'].append('QUARANTINE_CLEAN_UNCONFIRMED')
            if not terminated:
                response['cleanupFailures'].append('EXECUTOR_TERMINATION_UNCONFIRMED')
            if lost.is_set():
                response['cleanupFailures'].append('EXECUTOR_CONNECTION_LOST')
        # Close confirmation must be included in the reply, not attempted after
        # reporting success. CLEAN is already durable and the child is settled
        # and gone; lost final delivery cannot enable an old request issuer.
        done.set()
        try:
            admission.close()
        except Exception as error:
            response['cleanupComplete'] = False
            response.setdefault('cleanupFailures', []).extend(
                getattr(error, 'cleanup_failures', ['LOCK_CLEANUP_UNCONFIRMED']))
            response['quarantine'] = 'ACTIVE_OR_UNCONFIRMED'
        connection.sendall((json.dumps(response) + '\n').encode())
    except Exception:
        raise ExecutionUnconfirmed(dispatched) from None
    finally:
        done.set()
        if child.poll() is None:
            try:
                child.stdin.close()
            except OSError:
                pass
        if admission:
            try:
                admission.close()  # never changes ACTIVE after a failure
            except Exception:
                raise ExecutionUnconfirmed(dispatched) from None


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('EXECUTOR_CONFIG_REQUIRED')
        conn = socket.socket(fileno=3)
        serve(sys.argv[1], conn)
    except Exception as error:
        # Fixed text only. No SDK messages, paths, identities or frame contents.
        try:
            refusal = {'code': 'EXECUTOR_UNCONFIRMED'}
            if getattr(error, 'dispatched', False):
                refusal['outcome'] = 'unknown'
            conn.sendall((json.dumps({'error': refusal, 'cleanupComplete': False,
                                     'quarantine': 'ACTIVE_OR_UNCONFIRMED'}) + '\n').encode())
        except Exception:
            pass
        sys.exit(1)
