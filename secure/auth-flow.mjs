const OTHER_IOS_BROWSER = /CriOS|FxiOS|EdgiOS|OPiOS|DuckDuckGo/;

export function shouldUseRedirectFirst(userAgent) {
  const ua = String(userAgent || '');
  return /iP(hone|ad|od)/.test(ua) && /WebKit/.test(ua) && !OTHER_IOS_BROWSER.test(ua);
}

const POPUP_FALLBACK = new Set([
  'auth/popup-blocked',
  'auth/operation-not-supported-in-this-environment',
]);

export function isPopupUnavailable(error) {
  return POPUP_FALLBACK.has(error?.code);
}
