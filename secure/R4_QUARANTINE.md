# R4 trusted executor — candidate for independent review

This change builds on `276928803a64814177c8ad4e18b1c8836d879f56`.
It does not approve production use or resolve R6.

## Authority and admission

Normal campaign apply and D0 apply submit a bounded v1 request to a root-owned
Unix socket beneath administrator-owned directories. There is no ordinary
completion, CLEAN, reset, lease expiry, stale-PID recovery or arbitrary-command
operation. Both supported mutators use the same project control directory.
The old manual hold/status command refuses: an external claim command could
outlive that holder, and pathname existence is not executor occupancy.

A socket-activated supervisor authenticates SO_PEERCRED against a fixed caller
UID. Its root-controlled configuration binds the project, executable, source,
control directory, executor UID and control UID. All three identities must be
distinct and unprivileged. Code, dependencies and executable are administrator
owned and unwritable to either service/client identity. Only immutable file
symlinks within the code tree are permitted; directory symlinks are refused.
No Node loader variables or caller-selected program are inherited.
Set-ID/capability-bearing Node executables are refused. Both service identities
must have no effective, permitted, inheritable or ambient capabilities after
the privilege drop; the actual child also checks its configured unprivileged UID.

Root is used only to launch a fixed child under the executor identity and drop
the supervisor to the control identity. The child initially waits on a private
pipe and cannot initialize SDK clients before receiving its admission frame.
After dropping privileges, the supervisor takes flock on the permanent inode,
atomically persists ACTIVE, and only then sends that frame. Control files live
under the control UID; backup/receipt operations run under the different
executor UID. The ordinary caller cannot traverse either private namespace or
forge a frame on the child/supervisor pipes.

The existing operator credential checks and R3/R5 client construction remain
unchanged. The executor identity must own the approved operator ADC and use
that operator home; the controller has no Google credentials. Configuration
and any future installation require separate human review. This work installs
no service, changes no credentials/IAM, and adds no sudo or autonomous rights.

## Settlement and CLEAN

The trusted child accepts only fixed campaign/D0 operations. It constructs and
owns the SDK clients. Application logic receives sealed, tracked facades,
never raw clients or raw DocumentSnapshot.ref handles. All request promises,
including nested transaction reads, are counted. The facade synchronously
refuses future issuance after the action ends. Existing transaction outcome
classification is retained separately from cleanup and quarantine status.

CLEAN requires: a recognized terminal outcome (or a confirmed pre-write
refusal), no outstanding requests, irreversible facade sealing, fulfilled
Firestore termination and Admin app deletion, a matching private settlement
frame, stdout EOF, and normal child exit. Exit is necessary to exclude future
issuance; it is never accepted as settlement evidence by itself. A refusal
before any SDK factory started is also safe to settle after child exit.

Firestore Commit/channel retries remain disabled by the approved R5 settings.
D0 emulator mutations use one-attempt core HTTP requests because the pinned
Admin Auth SDK silently retries connection resets, timeouts and 503 responses.
Read-only Auth lookups still use the SDK. Any unconfirmed mutating response
retains ACTIVE; a later readback is not used to erase that uncertainty.
There is no new production claim-mutation endpoint.

The authorized ACTIVE-to-CLEAN transition writes a new exclusive control file,
flushes/closes it, renames it relative to the held directory and fsyncs the
directory while flock remains held. No transition unlinks the lock inode.
Kernel-close confirmation is included before reporting a complete reply.
Unknown outcome, failed shutdown, observed connection loss before settlement,
missing/invalid proof, worker death or controller death retain ACTIVE.
A second admission remains blocked even if an old accepted server request can
finish after either process dies. Ordinary clients cannot recover that state.

The durable CLEAN transition is the settlement linearization point. Loss of
final reply delivery after that point does not resurrect an old issuer: it is
already shut down and gone, with a known outcome. The client reports unresolved
completion and must not automatically retry. A directory-fsync failure can
leave either old ACTIVE or already-safe CLEAN after reboot; no unacknowledged
admission can have issued a mutation. Physical power-cut testing is not claimed.

## Operational boundary and limitations

This is Linux-only. Control storage must be persistent local storage with the
reviewed fsync/rename/flock guarantees. Missing state refuses; startup must
never recreate CLEAN automatically. Protect ancestry, ACLs, mount aliases,
service identities and code integrity in the eventual deployment. The library
checks ownership/mode/identity but is not an installer or a complete mount/ACL
auditor. Do not use a checkout or a volatile runtime directory for real state.

The bootstrap requires isolated Python (`python3 -I`), an already connected
socket on fd 3 and an immutable configuration path as its sole argument. It
does not write bytecode into the code tree. No OS service/socket/sudo policy is
installed here. The configuration fields are version, caller_uid, executor_uid,
control_uid, control, project, node and home. Existing gcloud must be available
on the fixed trusted PATH for a production identity check. No credentials were
created, copied or changed to make a deployment work.

There must be exactly one authoritative control directory per project, and all
old writers must be reconciled before initial offline CLEAN provisioning.
All supported mutators must migrate together. Unmanaged Google admin calls,
compromised trusted identities, root/privileged tracing/mount changes and old
versions run outside this protocol remain outside the guarantee. Ordinary
clients are the separate caller UID; arbitrary code under a trusted service
identity is not an ordinary client. Read-only CLI inspection retains its prior
behavior and cannot authorize CLEAN. Quarantine recovery is deliberately absent
and requires a separately reviewed reconciliation design, not one readback,
a delay or a process check.

The existing in-process dependency hooks remain for trusted synthetic tests;
they are never deserialized from requests or enabled by argv/environment.
R6 directory code and its limitations are unchanged. Production remains NO-GO.

## Validation structure

Python admission tests cover persistence failures, corruption, partial grants,
kernel contention and UID separation. Supervisor tests run in disposable Linux
under real distinct caller/executor/control identities. They cover delayed
HTTP and actual pinned-SDK gRPC Commit servers, death of either process while
an accepted Commit can still finish, lost IPC, repeat admission, rejected reset
operations and actual CLI exits 10/11/13/14/15. Shutdown/receipt faults are
injected only into offline root-owned test copies, never through runtime flags.

Pinned SDK tests retain the approved production-credential and Commit-counting
coverage against local TLS endpoints. Emulator functional tests use private
in-process executor capabilities to exercise the owned SDK path without
requiring a privileged service installation. They do not substitute for the
separate real CLI/socket/OS boundary tests. Exact execution results and revision
identities belong in the accompanying review evidence; tests alone are not
independent approval of R4.
