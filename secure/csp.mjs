export function productionCsp() {
  return [
    "default-src 'self'",
    "script-src 'self' https://apis.google.com https://www.gstatic.com",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://firestore.googleapis.com https://firebase.googleapis.com https://www.googleapis.com https://firebaseinstallations.googleapis.com https://apis.google.com",
    "frame-src https://accounts.google.com https://*.firebaseapp.com https://*.web.app https://apis.google.com",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    'upgrade-insecure-requests',
  ].join('; ');
}

export function emulatorCsp({ authOrigin, firestoreOrigin }) {
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(authOrigin)) throw new Error('Emulator auth origin must be loopback');
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(firestoreOrigin)) throw new Error('Emulator Firestore origin must be loopback');
  return [
    "default-src 'self'",
    "script-src 'self' https://apis.google.com https://www.gstatic.com",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${authOrigin} ${firestoreOrigin} https://apis.google.com`,
    `frame-src ${authOrigin} https://apis.google.com`,
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; ');
}
