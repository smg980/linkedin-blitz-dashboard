import { isEnvelope } from './envelope.mjs';

export const State = {
  SignedOut: 'signed-out',
  SigningIn: 'signing-in',
  NotAuthorized: 'not-authorized',
  Locked: 'locked',
  WrongPassphrase: 'wrong-passphrase',
  Unlocked: 'unlocked',
};

// Every transition that changes who is signed in, which envelope is loaded, or
// whether the campaign is open advances the epoch. An unlock started under one
// epoch can only settle under that same epoch, against that same envelope
// object; anything else is a stale result and is dropped without effect.
export function createSession() {
  let state = State.SignedOut;
  let plaintext = null;
  let ciphertext = null;
  let reason = null;
  let epoch = 0;
  let pending = null;
  const invalidate = () => {
    epoch += 1;
    pending = null;
  };
  const current = (ticket) => ticket != null
    && ticket === pending
    && ticket.epoch === epoch
    && ticket.envelope === ciphertext
    && (state === State.Locked || state === State.WrongPassphrase);
  return {
    state: () => state,
    plaintext: () => plaintext,
    ciphertext: () => ciphertext,
    reason: () => reason,
    epoch: () => epoch,
    unlockPending: () => pending !== null,
    // context carries the caller's own bindings (auth generation, uid). They are
    // frozen into the ticket so the caller can re-check them on settle.
    beginUnlock(context = {}) {
      if (state !== State.Locked && state !== State.WrongPassphrase) throw new Error('Unlock requires a locked session');
      if (!ciphertext) throw new Error('Unlock requires ciphertext');
      if (pending) throw new Error('An unlock is already pending');
      pending = Object.freeze({ ...context, epoch, envelope: ciphertext });
      return pending;
    },
    isCurrentUnlock: (ticket) => current(ticket),
    finishUnlock(ticket, data) {
      if (!current(ticket)) return false;
      if (data == null || typeof data !== 'object') throw new Error('Unlocked state requires plaintext');
      pending = null;
      plaintext = data;
      state = State.Unlocked;
      reason = null;
      return true;
    },
    failUnlock(ticket) {
      if (!current(ticket)) return false;
      pending = null;
      plaintext = null;
      state = State.WrongPassphrase;
      return true;
    },
    signInStart() {
      invalidate();
      plaintext = null;
      ciphertext = null;
      reason = null;
      state = State.SigningIn;
    },
    notAuthorized(why) {
      invalidate();
      plaintext = null;
      ciphertext = null;
      reason = why || 'denied';
      state = State.NotAuthorized;
    },
    locked(blob) {
      if (!blob) throw new Error('Locked state requires ciphertext');
      invalidate();
      plaintext = null;
      ciphertext = blob;
      reason = null;
      state = State.Locked;
    },
    wrongPassphrase() {
      plaintext = null;
      if (!ciphertext) throw new Error('Wrong passphrase requires ciphertext');
      pending = null;
      state = State.WrongPassphrase;
    },
    unlocked(data) {
      if (data == null || typeof data !== 'object') throw new Error('Unlocked state requires plaintext');
      pending = null;
      plaintext = data;
      state = State.Unlocked;
      reason = null;
    },
    lock() {
      plaintext = null;
      if (!ciphertext) throw new Error('Lock requires ciphertext');
      invalidate();
      state = State.Locked;
      reason = null;
    },
    signOut() {
      invalidate();
      plaintext = null;
      ciphertext = null;
      reason = null;
      state = State.SignedOut;
    },
  };
}

export function applyDocumentRead(session, result) {
  if (result?.status === 'ok' && isEnvelope(result.envelope)) {
    session.locked(result.envelope);
    return session.state();
  }
  session.notAuthorized(result?.status === 'missing' ? 'missing' : 'denied');
  return session.state();
}
