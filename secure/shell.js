import { initializeApp } from 'firebase/app';
import {
  browserSessionPersistence,
  connectAuthEmulator,
  getAuth,
  getRedirectResult,
  GoogleAuthProvider,
  inMemoryPersistence,
  onAuthStateChanged,
  setPersistence,
  signInWithPopup,
  signInWithRedirect,
  signOut,
} from 'firebase/auth';
import { isPopupUnavailable, redirectCanComplete, shouldUseRedirectFirst } from './auth-flow.mjs';
import { decryptEnvelope } from './envelope.mjs';
import { readPrivateDocument } from './firestore-get.mjs';
import { renderPrivateView } from './private-view.mjs';
import { applyDocumentRead, createSession } from './session.mjs';
import { wipePrivateRoot } from './wipe.mjs';

const COPY = {
  'signed-out': {
    title: 'LinkedIn Blitz',
    message: 'Private campaign shell. Sign in with Google. Campaign data is not stored in this site.',
  },
  'signing-in': {
    title: 'Signing in',
    message: 'Signing in with Google…',
  },
  'not-authorized': {
    title: 'Not authorized',
    message: 'This sign-in cannot open the private campaign. The document is missing or access was denied.',
  },
  locked: {
    title: 'Campaign locked',
    message: 'Enter the passphrase. Decryption happens in this browser only.',
  },
  'wrong-passphrase': {
    title: 'Passphrase did not match',
    message: 'That passphrase did not decrypt the campaign. Try again.',
  },
};

const config = globalThis.BLITZ_SECURE_CONFIG;
const session = createSession();
let auth = null;
let generation = 0;
let loadedFor = '';
const inflight = new Map();

function $(id) { return document.getElementById(id); }

function firestoreOrigin() {
  if (config?.useEmulators) return `http://${config.emulators.firestoreHost}:${config.emulators.firestorePort}`;
  return 'https://firestore.googleapis.com';
}

function clearPrivate() {
  wipePrivateRoot($('private-view'));
  const banner = $('example-banner');
  banner.hidden = true;
  banner.textContent = '';
  $('subtitle').textContent = '';
  $('private-foot').textContent = '';
}

// The button reflects only the unlock bound to the current session. A stale
// unlock never writes to it; the transition that made it stale re-renders.
function renderUnlockButton() {
  const button = $('unlock-btn');
  const pending = session.unlockPending();
  button.disabled = pending;
  button.textContent = pending ? 'Checking…' : 'Unlock';
}

// Advances the authentication generation. Every document read and unlock that
// started before this call is stale and may not change state or the DOM.
function invalidateAuth() {
  generation += 1;
  loadedFor = '';
  inflight.clear();
}

function render() {
  const state = session.state();
  document.body.dataset.state = state;
  const unlocked = state === 'unlocked';
  $('lock').hidden = unlocked;
  $('app').hidden = !unlocked;
  const copy = COPY[state];
  if (copy) {
    $('gate-title').textContent = copy.title;
    $('gate-message').textContent = copy.message;
  }
  const showForm = state === 'locked' || state === 'wrong-passphrase';
  $('unlock-form').hidden = !showForm;
  renderUnlockButton();
  document.querySelector('[data-action="sign-in"]').hidden = state !== 'signed-out';
  document.querySelector('#lock [data-action="sign-out"]').hidden = !(state === 'not-authorized' || showForm);
  const error = $('gate-error');
  if (state === 'wrong-passphrase') {
    error.hidden = false;
    error.textContent = 'Incorrect passphrase.';
  } else {
    error.hidden = true;
    error.textContent = '';
  }
  if (!unlocked) {
    clearPrivate();
    if (showForm) $('pass').focus();
    return;
  }
  const data = session.plaintext();
  clearPrivate();
  if (!data) return;
  renderPrivateView($('private-view'), data);
  const banner = $('example-banner');
  banner.hidden = !data.example;
  banner.textContent = data.example ? 'EXAMPLE DATA — design preview only. Not real contacts.' : '';
  $('subtitle').textContent = `${data.campaign?.name || 'Campaign'} · read only`;
  $('private-foot').textContent = 'Prep only · decrypted in this browser · not sent';
}

function redirectContext() {
  return {
    authDomain: config?.firebase?.authDomain,
    hostname: globalThis.location?.hostname,
    useEmulators: config?.useEmulators === true,
  };
}

function googleProvider() {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  return provider;
}

function loadDocument(user) {
  if (!user?.uid) return Promise.resolve();
  if (loadedFor === user.uid && ['locked', 'wrong-passphrase', 'unlocked'].includes(session.state())) return Promise.resolve();
  const running = inflight.get(user.uid);
  if (running && running.gen === generation) return running.promise;
  const gen = ++generation;
  const promise = readSignedInDocument(user, gen).finally(() => {
    if (inflight.get(user.uid)?.promise === promise) inflight.delete(user.uid);
  });
  inflight.set(user.uid, { gen, promise });
  return promise;
}

async function readSignedInDocument(user, gen) {
  // The read belongs to this generation and to the user Firebase reports now.
  const current = () => gen === generation && auth?.currentUser?.uid === user.uid;
  loadedFor = '';
  session.signInStart();
  render();
  try {
    // One forced refresh so a claim granted after the first token is visible.
    const token = await user.getIdToken(true);
    if (!current()) return;
    const result = await readPrivateDocument({
      origin: firestoreOrigin(),
      projectId: config.firebase.projectId,
      uid: user.uid,
      token,
    });
    if (!current()) return;
    applyDocumentRead(session, result);
    if (session.state() === 'locked') loadedFor = user.uid;
  } catch {
    if (!current()) return;
    session.notAuthorized('denied');
  }
  render();
}

async function onSignIn() {
  if (!auth || session.state() === 'signing-in') return;
  session.signInStart();
  render();
  const provider = googleProvider();
  const redirectFirst = shouldUseRedirectFirst(navigator.userAgent, redirectContext());
  try {
    if (redirectFirst) {
      await signInWithRedirect(auth, provider);
      return;
    }
    // Call the popup directly from the click so the browser still treats it as a user gesture.
    const credential = await signInWithPopup(auth, provider);
    if (credential?.user) await loadDocument(credential.user);
  } catch (error) {
    if (!redirectFirst && isPopupUnavailable(error)) {
      if (!redirectCanComplete(redirectContext())) {
        // A redirect could not return a result here; ask for the popup instead.
        session.signOut();
        render();
        $('gate-message').textContent = 'Allow pop-ups for this site, then sign in again.';
        return;
      }
      try {
        await setPersistence(auth, browserSessionPersistence);
        await signInWithRedirect(auth, provider);
        return;
      } catch {
        session.signOut();
        render();
        return;
      }
    }
    session.signOut();
    render();
  }
}

async function onSignOut() {
  invalidateAuth();
  session.signOut();
  $('pass').value = '';
  render();
  if (!auth) return;
  try { await signOut(auth); } catch { /* already signed out */ }
}

function onLock() {
  if (session.state() !== 'unlocked' && session.state() !== 'wrong-passphrase') return;
  session.lock();
  $('pass').value = '';
  render();
}

// An unlock is bound to the auth generation, the signed-in uid, the session
// epoch and the exact envelope object it started with. Lock, sign-out, an
// account change or a new document read invalidates it.
function unlockStillCurrent(ticket) {
  return ticket.generation === generation
    && ticket.uid !== ''
    && ticket.uid === loadedFor
    && auth?.currentUser?.uid === ticket.uid
    && session.isCurrentUnlock(ticket);
}

async function onUnlock(event) {
  event.preventDefault();
  const input = $('pass');
  if (session.unlockPending()) return;
  if (!session.ciphertext() || !loadedFor) {
    session.notAuthorized('missing');
    render();
    return;
  }
  if (session.state() !== 'locked' && session.state() !== 'wrong-passphrase') return;
  const ticket = session.beginUnlock({ generation, uid: loadedFor });
  const chars = Array.from(input.value);
  input.value = '';
  const passphrase = chars.join('');
  chars.fill('');
  renderUnlockButton();
  await new Promise((resolve) => setTimeout(resolve, 0));
  let data = null;
  let ok = false;
  try {
    if (unlockStillCurrent(ticket)) {
      data = await decryptEnvelope(ticket.envelope, passphrase);
      ok = true;
    }
  } catch {
    ok = false;
  }
  // A result from an earlier sign-in, session or envelope is dropped here with
  // no state change and no DOM write.
  if (!unlockStillCurrent(ticket)) return;
  if (ok) session.finishUnlock(ticket, data);
  else session.failUnlock(ticket);
  render();
}

async function boot() {
  if (!config?.firebase?.apiKey || !config.firebase.projectId || !config.firebase.authDomain || !config.firebase.appId) {
    $('gate-message').textContent = 'This shell has no Firebase configuration.';
    document.querySelector('[data-action="sign-in"]').hidden = true;
    document.body.dataset.booted = 'yes';
    return;
  }
  const app = initializeApp(config.firebase);
  auth = getAuth(app);
  if (config.useEmulators) {
    const emu = config.emulators;
    connectAuthEmulator(auth, `http://${emu.authHost}:${emu.authPort}`, { disableWarnings: true });
  }
  onAuthStateChanged(auth, (user) => {
    if (user) {
      loadDocument(user);
      return;
    }
    // No user: nothing started for an earlier sign-in may still land.
    invalidateAuth();
    if (session.state() !== 'signing-in' && session.state() !== 'signed-out') {
      session.signOut();
      $('pass').value = '';
      render();
    }
  });
  await setPersistence(auth, browserSessionPersistence);
  let redirected = null;
  try {
    redirected = await getRedirectResult(auth);
  } catch {
    redirected = null;
  }
  if (!redirected?.user && !shouldUseRedirectFirst(navigator.userAgent, redirectContext())) {
    await setPersistence(auth, inMemoryPersistence);
  }
  if (redirected?.user) await loadDocument(redirected.user);
  document.body.dataset.booted = 'yes';
}

document.addEventListener('click', (event) => {
  const action = event.target.closest('[data-action]')?.dataset.action;
  if (action === 'sign-in') onSignIn();
  else if (action === 'sign-out') onSignOut();
  else if (action === 'lock') onLock();
});
$('unlock-form').addEventListener('submit', onUnlock);

boot().catch(() => {
  session.signOut();
  render();
  $('gate-message').textContent = 'Sign-in could not be started.';
  document.body.dataset.booted = 'yes';
});
