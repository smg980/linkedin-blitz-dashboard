const OTHER_IOS_BROWSER = /CriOS|FxiOS|EdgiOS|OPiOS|DuckDuckGo/;

export function isIosSafari(userAgent) {
  const ua = String(userAgent || '');
  return /iP(hone|ad|od)/.test(ua) && /WebKit/.test(ua) && !OTHER_IOS_BROWSER.test(ua);
}

// signInWithRedirect reads the result back through an iframe on authDomain.
// Safari 16.1+ (and Chrome/Firefox with storage partitioning) block that
// third-party storage, so getRedirectResult returns null when authDomain is
// not the host serving the app. Redirect is only used where it can complete:
// the loopback emulator, or an authDomain equal to the page's own host.
export function redirectCanComplete({ authDomain, hostname, useEmulators } = {}) {
  if (useEmulators === true) return true;
  if (typeof authDomain !== 'string' || typeof hostname !== 'string') return false;
  const domain = authDomain.trim().toLowerCase();
  return domain !== '' && domain === hostname.trim().toLowerCase();
}

export function shouldUseRedirectFirst(userAgent, context) {
  return isIosSafari(userAgent) && redirectCanComplete(context);
}

const POPUP_FALLBACK = new Set([
  'auth/popup-blocked',
  'auth/operation-not-supported-in-this-environment',
]);

export function isPopupUnavailable(error) {
  return POPUP_FALLBACK.has(error?.code);
}
