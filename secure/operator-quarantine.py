"""R4 protected admission state. See R4_QUARANTINE.md.

Only a trusted service identity may import this module against its control
directory. Ordinary clients must never get these descriptors or filesystem
permissions. There is no ordinary-client CLEAN/reset/recovery operation.
"""
import fcntl
import json
import os
import secrets
import stat


class QuarantineError(RuntimeError):
    def __init__(self, code, *, cleanup_complete=True):
        super().__init__(code)
        self.code = code
        self.cleanup_complete = cleanup_complete


class Admission:
    """One pre-provisioned project, permanent flock inode, private state.

    CLEAN is not a lease. ACTIVE survives release and death. Only the protected
    supervisor's private settlement path can restore CLEAN for the current
    session. An abandoned ACTIVE session has no automatic recovery operation.
    """
    LOCK = 'operator.lock'
    STATE = 'state.json'
    LIMIT = 512

    def __init__(self, directory, *, operator_uid):
        self.directory_fd = -1
        self.lock_fd = -1
        self.session = None
        self.closed = False
        self.operator_uid = operator_uid
        self._open(directory)

    def _open(self, directory):
        # Walk from / through no-follow pinned descriptors. Every parent is
        # administrator owned and unwritable to unprivileged identities.
        if not isinstance(directory, str) or not directory.startswith('/'):
            raise QuarantineError('LOCK_CONTROL_PATH')
        parts = directory.split('/')[1:]
        if not parts or any(p in ('', '.', '..') for p in parts):
            raise QuarantineError('LOCK_CONTROL_PATH')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in parts:
                parent = os.fstat(fd)
                if parent.st_uid != 0 or parent.st_mode & 0o022:
                    raise QuarantineError('LOCK_UNTRUSTED_ANCESTRY')
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                old, fd = fd, child
                os.close(old)
            info = os.fstat(fd)
            if (info.st_uid != os.geteuid() or info.st_uid == self.operator_uid
                    or info.st_mode & 0o077):
                raise QuarantineError('LOCK_CONTROL_NOT_PRIVATE')
            self.directory_fd, fd = fd, -1
        finally:
            if fd >= 0:
                os.close(fd)

    def _regular(self, fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise QuarantineError('LOCK_CONTROL_FILE_UNSAFE')

    def _state(self):
        fd = os.open(self.STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.directory_fd)
        try:
            self._regular(fd)
            raw = os.read(fd, self.LIMIT + 1)
            if len(raw) > self.LIMIT:
                raise ValueError('oversize')
            # Duplicate keys and extra fields are never accepted as CLEAN.
            pairs = json.loads(raw, object_pairs_hook=list)
            if (pairs != [('version', 1), ('state', 'CLEAN')]
                    or type(pairs[0][1]) is not int):
                raise QuarantineError('LOCK_QUARANTINED')
        except (ValueError, TypeError, UnicodeError):
            raise QuarantineError('LOCK_STATE_INVALID') from None
        finally:
            os.close(fd)

    def acquire(self):
        if self.closed or self.lock_fd >= 0 or self.session is not None:
            raise QuarantineError('LOCK_SESSION_INVALID')
        fd = -1
        temp_fd = -1
        pending = None
        try:
            # Never create, truncate, rename or unlink the sentinel. Offline
            # provisioning is required; missing files fail closed.
            fd = os.open(self.LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.directory_fd)
            self._regular(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise QuarantineError('LOCK_HELD') from None
            self._state()
            token = secrets.token_hex(32)
            pending = '.active-' + token
            temp_fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                              dir_fd=self.directory_fd)
            payload = json.dumps({'version': 1, 'state': 'ACTIVE',
                                  'session': token}, separators=(',', ':')).encode()
            offset = 0
            while offset < len(payload):
                written = os.write(temp_fd, payload[offset:])
                if written <= 0:
                    raise OSError('short write')
                offset += written
            os.fsync(temp_fd)
            # Close must complete before rename/admission. Do not retry close:
            # after an error the descriptor number may have been reused.
            closing, temp_fd = temp_fd, -1
            os.close(closing)
            os.rename(pending, self.STATE, src_dir_fd=self.directory_fd,
                      dst_dir_fd=self.directory_fd)
            pending = None
            os.fsync(self.directory_fd)
            self.lock_fd, fd = fd, -1
            self.session = token
            return token  # the sole admission point, after durability
        except Exception as error:
            complete = True
            for descriptor in (temp_fd, fd):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        complete = False
            # Keep failed temporary files for inspection. They contain only a
            # random session identifier, no campaign or credential material.
            if isinstance(error, QuarantineError):
                error.cleanup_complete = error.cleanup_complete and complete
                raise
            raise QuarantineError('LOCK_ACQUIRE_UNCONFIRMED',
                                  cleanup_complete=False) from None

    def release(self):
        """Release only the kernel handle. ACTIVE is never cleared here."""
        if self.lock_fd >= 0:
            fd, self.lock_fd = self.lock_fd, -1
            try:
                os.close(fd)
            except OSError:
                raise QuarantineError('LOCK_RELEASE_UNCONFIRMED',
                                      cleanup_complete=False) from None

    def _settled_by_trusted_executor(self):
        """Service-internal only; never expose this method through client IPC.

        The supervisor must first validate its private child's settlement frame,
        successful shutdown and exit, and the live request connection. A PID or
        an ordinary client report alone cannot authorize this call.
        """
        if self.closed or self.lock_fd < 0 or self.session is None:
            raise QuarantineError('LOCK_SESSION_INVALID')
        fd = os.open(self.STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.directory_fd)
        try:
            self._regular(fd)
            raw = os.read(fd, self.LIMIT + 1)
            expected = {'version': 1, 'state': 'ACTIVE', 'session': self.session}
            if len(raw) > self.LIMIT or json.loads(raw) != expected:
                raise QuarantineError('LOCK_SESSION_INVALID')
        finally:
            os.close(fd)
        self._persist_trusted_state({'version': 1, 'state': 'CLEAN'})

    def _retain_active_after_lost_reply(self):
        if self.closed or self.lock_fd < 0 or self.session is None:
            raise QuarantineError('LOCK_SESSION_INVALID')
        self._persist_trusted_state({'version': 1, 'state': 'ACTIVE', 'session': self.session})

    def _persist_trusted_state(self, value):
        name = '.transition-' + secrets.token_hex(32)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory_fd)
        try:
            payload = json.dumps(value, separators=(',', ':')).encode()
            offset = 0
            while offset < len(payload):
                count = os.write(fd, payload[offset:])
                if count <= 0:
                    raise OSError('short write')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(name, self.STATE, src_dir_fd=self.directory_fd,
                  dst_dir_fd=self.directory_fd)
        os.fsync(self.directory_fd)

    def close(self):
        self.closed = True
        failures = []
        try:
            self.release()
        except Exception:
            failures.append('LOCK_RELEASE_UNCONFIRMED')
        if self.directory_fd >= 0:
            fd, self.directory_fd = self.directory_fd, -1
            try:
                os.close(fd)
            except OSError:
                failures.append('LOCK_DIRECTORY_CLOSE_UNCONFIRMED')
        if failures:
            error = QuarantineError('LOCK_CLEANUP_UNCONFIRMED', cleanup_complete=False)
            error.cleanup_failures = failures
            raise error
