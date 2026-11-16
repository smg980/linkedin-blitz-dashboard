# R4 admission core: review scope and remaining blocker

This is a deliberately incomplete R4 implementation for review, based on
`c59d11b65e8ca06c8b0d3c2f6e8ea9f3c9d45084`. It is not wired into the existing
campaign or D0 CLI. Those clients still use the old lock implementation and
must not be represented as remediated by this commit. R6 is untouched.

## Implemented transition

`operator-quarantine.py` consumes one offline-provisioned CLEAN state and
atomically replaces it with ACTIVE before returning admission. It writes a
new exclusive temporary file, completes all writes, fsyncs and closes it,
renames it over state.json relative to the pinned control directory, and
fsyncs that directory. A permanent pre-provisioned operator.lock inode is
held with nonblocking flock throughout admission. It is never removed,
replaced or created by this code. Missing or invalid control state refuses.

There is intentionally **no ACTIVE to CLEAN transition**. Kernel release,
worker death, client shutdown, failed shutdown, unknown outcome, a lost IPC
response, or process exit cannot reset quarantine. This guarantees the core
never admits a second mutation after an admitted session, even when a prior
process or server can still commit. It also blocks reuse after a clean run.
This availability cost is explicit; it is not a complete reusable lifecycle.

Partial acquisition never grants admission. A failure after rename can retain
ACTIVE even without a grant. A failure before rename can retain the previous
CLEAN state: no mutation was admitted, so a later attempt is safe. Data-file
fsync failure must not be confused with directory-fsync failure. If a crash
before directory durability leaves either old CLEAN or new ACTIVE, neither
permits overlap with an acknowledged grant, since acknowledgement occurs
only after directory fsync. This assumes the local filesystem honors fsync
and atomic same-directory rename; power-cut behavior was not tested.

I/O errors report fixed codes and cleanup confirmation separately. Kernel
close does not change quarantine. The core does not receive, rewrite or infer
any Firestore outcome. Actual CLI outcome mapping is unchanged and untested
by these Python tests.

## Control boundary

The API has only acquire/release/close; no file operations, arbitrary names,
reset, completion acknowledgement or recovery operation exists. There is one
control directory per pre-provisioned project, owned by the service identity
and mode 0700. The entire ancestry is walked through no-follow directory
descriptors and must be root-owned with no group/other write bits. The
operator UID must differ from the directory owner. File ownership, privacy,
regular type and single link are checked. Descriptors are close-on-exec.

The service identity is trusted; the operator must never receive its control
descriptors or write access. No ordinary data operation may be exposed under
this hierarchy. A future transport must not accept a caller-selected control
directory. There is no deployed transport here. ACLs, alternate mount access,
service-code integrity and supported local filesystem type remain deployment
preconditions, not properties verified by this library. Do not use this as a
standalone provisioning validator. Root/privileged interference and malicious
service code are outside the boundary. No runtime recovery command is provided.

## Why automatic CLEAN is still blocked

The previous design proposed accepting a classified outcome and a successful
SDK-shutdown report from Node. Under the stricter requirement that ordinary
clients cannot authorize CLEAN while an old Node process can issue or finish
a commit, that report is insufficient. A client could report completion too
early; killing it does not cancel a server-accepted commit. The service cannot
independently observe settlement through a credential-free filesystem API.

A reusable integration therefore needs a trusted executor that controls all
commit issuance, tracks authoritative terminal results and outstanding work,
and prevents further requests before authorizing CLEAN. Uncertain requests
must still remain ACTIVE after executor death. Merely adding pidfd monitoring,
leases, a shutdown timeout, or another ordinary-client message is insufficient.
Alternatively, retain one-shot admission indefinitely with no automatic reuse.
This commit implements only that conservative admission core and does not
silently choose a recovery authority or change the existing operator workflow.

Next engineering step: specify the trusted executor/settlement contract and
validate it with the actual pinned SDK and a delayed local synthetic Commit
transport. Then integrate campaign and D0 admission together, preserve
outcome/cleanup/quarantine as separate fields, and test real shutdown failure,
unknown Commit outcomes and CLI exits 10/11/13/14/15 before calling R4 fixed.
No production, deployment, credential or IAM activity is needed for that work.

## Executed tests

`sudo -n python3 tests/operator-quarantine.test.py` in a disposable Linux
environment, not on an operator or production machine. The suite fails rather
than skipping when Linux/root boundary-test prerequisites are missing.

Coverage: actual cross-process kernel contention; SIGKILL of a worker while
a separate simulated server remains able to finish; quarantine after release;
file write/fsync/rename and close failures; directory-fsync failure after
replacement; corrupt, missing and duplicate-key state; absent recovery/data
APIs; unsafe ancestry and symlink refusal; and admission under nobody while
daemon is denied access to the control files. The completion-label test checks
only the absence of a client completion/reset API. It does not execute SDK
shutdown or IPC. No tests in this suite use Firebase or real campaign data.

Full Node unit and emulator suites have not been run for this isolated core.
All pre-existing repository files remain unchanged; approved F1/R1/R2/R3/R5
implementation is preserved byte for byte. No PR should call this an R4 fix.
