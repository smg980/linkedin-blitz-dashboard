import { isEnvelope } from './envelope.mjs';

export const State = {
  SignedOut: 'signed-out',
  SigningIn: 'signing-in',
  NotAuthorized: 'not-authorized',
  Locked: 'locked',
  WrongPassphrase: 'wrong-passphrase',
  Unlocked: 'unlocked',
};

export function createSession() {
  let state = State.SignedOut;
  let plaintext = null;
  let ciphertext = null;
  let reason = null;
  return {
    state: () => state,
    plaintext: () => plaintext,
    ciphertext: () => ciphertext,
    reason: () => reason,
    signInStart() {
      plaintext = null;
      ciphertext = null;
      reason = null;
      state = State.SigningIn;
    },
    notAuthorized(why) {
      plaintext = null;
      ciphertext = null;
      reason = why || 'denied';
      state = State.NotAuthorized;
    },
    locked(blob) {
      if (!blob) throw new Error('Locked state requires ciphertext');
      plaintext = null;
      ciphertext = blob;
      reason = null;
      state = State.Locked;
    },
    wrongPassphrase() {
      plaintext = null;
      if (!ciphertext) throw new Error('Wrong passphrase requires ciphertext');
      state = State.WrongPassphrase;
    },
    unlocked(data) {
      if (data == null || typeof data !== 'object') throw new Error('Unlocked state requires plaintext');
      plaintext = data;
      state = State.Unlocked;
      reason = null;
    },
    lock() {
      plaintext = null;
      if (!ciphertext) throw new Error('Lock requires ciphertext');
      state = State.Locked;
      reason = null;
    },
    signOut() {
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
