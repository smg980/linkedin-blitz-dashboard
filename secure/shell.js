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
import { isPopupUnavailable, shouldUseRedirectFirst } from './auth-flow.mjs';
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

function googleProvider() {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  return provider;
}

function loadDocument(user) {
  if (!user?.uid) return Promise.resolve();
  if (loadedFor === user.uid && ['locked', 'wrong-passphrase', 'unlocked'].includes(session.state())) return Promise.resolve();
  if (inflight.has(user.uid)) return inflight.get(user.uid);
  const gen = ++generation;
  const promise = readSignedInDocument(user, gen).finally(() => inflight.delete(user.uid));
  inflight.set(user.uid, promise);
  return promise;
}

async function readSignedInDocument(user, gen) {
  loadedFor = '';
  session.signInStart();
  render();
  try {
    // One forced refresh so a claim granted after the first token is visible.
    const token = await user.getIdToken(true);
    if (gen !== generation) return;
    const result = await readPrivateDocument({
      origin: firestoreOrigin(),
      projectId: config.firebase.projectId,
      uid: user.uid,
      token,
    });
    if (gen !== generation) return;
    applyDocumentRead(session, result);
    if (session.state() === 'locked') loadedFor = user.uid;
  } catch {
    if (gen !== generation) return;
    session.notAuthorized('denied');
  }
  render();
}

async function onSignIn() {
  if (!auth || session.state() === 'signing-in') return;
  session.signInStart();
  render();
  const provider = googleProvider();
  const redirectFirst = shouldUseRedirectFirst(navigator.userAgent);
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
  generation += 1;
  loadedFor = '';
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

async function onUnlock(event) {
  event.preventDefault();
  const input = $('pass');
  const button = $('unlock-btn');
  if (!session.ciphertext()) {
    session.notAuthorized('missing');
    render();
    return;
  }
  const chars = Array.from(input.value);
  input.value = '';
  const passphrase = chars.join('');
  chars.fill('');
  button.disabled = true;
  button.textContent = 'Checking…';
  await new Promise((resolve) => setTimeout(resolve, 0));
  try {
    const data = await decryptEnvelope(session.ciphertext(), passphrase);
    session.unlocked(data);
    render();
  } catch {
    session.wrongPassphrase();
    render();
  } finally {
    button.disabled = false;
    button.textContent = 'Unlock';
  }
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
    if (user) loadDocument(user);
    else if (session.state() !== 'signing-in' && session.state() !== 'signed-out') {
      generation += 1;
      loadedFor = '';
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
  if (!redirected?.user && !shouldUseRedirectFirst(navigator.userAgent)) {
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
