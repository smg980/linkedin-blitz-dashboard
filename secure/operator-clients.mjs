// R3: production Auth and Firestore clients for Step D, built from the one
// checked operator credential (assertOperatorCredential) in a form the pinned
// SDKs actually accept.
//
// firebase-admin 13.5.0 builds its Firestore client only from a service-account
// certificate or from generic Application Default Credentials; it throws
// firestore/invalid-credential for admin.refreshToken(...). Generic ADC would
// search the environment, which F4 forbids. So this module:
//   - builds one google-auth-library UserRefreshClient from the checked fields
//     only (no file path, no environment search),
//   - hands that client to @google-cloud/firestore as `authClient`, so GAX never
//     resolves credentials itself, and
//   - wraps the same client as the Admin SDK credential used by Auth.
// Both libraries are resolved from firebase-admin's own dependency graph, so the
// versions are exactly the ones package-lock.json pins for the Admin SDK.
import { createRequire } from 'node:module';
import { StoreRefusal } from './campaign-store.mjs';

const localRequire = createRequire(import.meta.url);

function pinnedModules() {
  const adminRequire = createRequire(localRequire.resolve('firebase-admin/firestore'));
  const firestoreEntry = adminRequire.resolve('@google-cloud/firestore');
  const firestoreRequire = createRequire(firestoreEntry);
  const { Firestore } = firestoreRequire('@google-cloud/firestore');
  // The google-auth-library that google-gax (and so Firestore) uses.
  const gaxRequire = createRequire(firestoreRequire.resolve('google-gax'));
  const { UserRefreshClient } = gaxRequire('google-auth-library');
  return { Firestore, UserRefreshClient };
}

// R5: runTransaction({ maxAttempts: 1 }) only stops the transaction runner.
// Transaction.commit() sends Commit with no per-call retry, so the GAPIC
// default applies: firestore_client_config.json gives Commit the
// "resource_exhausted_unavailable" codes with exponential backoff for up to
// 600 s. A Commit that applied but lost its acknowledgement (UNAVAILABLE) was
// therefore sent again. Commit is given an empty retry-code list, so GAX
// sends it once. GAX (constructRetry/mergeRetryOptions) resolves an override's
// retry_codes_name only in the override's own retry_codes table; naming the
// base config's "non_idempotent" list is silently ignored, which the counting
// regression in tests/operator-clients.test.mjs demonstrated.
export const COMMIT_NO_RETRY_CLIENT_CONFIG = Object.freeze({
  interfaces: Object.freeze({
    'google.firestore.v1.Firestore': Object.freeze({
      retry_codes: Object.freeze({ blitz_commit_never_retry: Object.freeze([]) }),
      methods: Object.freeze({
        Commit: Object.freeze({ retry_codes_name: 'blitz_commit_never_retry' }),
      }),
    }),
  }),
});

// The transport settings production uses. Tests may add an endpoint override
// (servicePath/port) through `testTransport`; nothing else is configurable.
export function firestoreSettings({ projectId, authClient }) {
  const settings = {
    projectId,
    // gRPC, explicitly: FIRESTORE_PREFER_REST must not change the transport.
    preferRest: false,
    clientConfig: COMMIT_NO_RETRY_CLIENT_CONFIG,
    // R5: and no gRPC-level retry either: grpc-js transparent retries and any
    // retry policy a DNS service config could supply are both turned off.
    'grpc.enable_retries': 0,
    'grpc.service_config_disable_resolution': 1,
  };
  if (authClient) settings.authClient = authClient;
  return settings;
}

// Admin SDK Credential interface over the same refresh client.
function adminCredential(authClient) {
  return {
    async getAccessToken() {
      const { token } = await authClient.getAccessToken();
      if (typeof token !== 'string' || token.length === 0) throw new Error('no access token');
      const expiry = Number(authClient.credentials?.expiry_date) || 0;
      return { access_token: token, expires_in: Math.max(0, Math.floor((expiry - Date.now()) / 1000)) };
    },
  };
}

// adc: the object returned by assertOperatorCredential (already checked).
// testTransport (tests only): { tokenTransporter, servicePath, port }.
export function createOperatorClients({ adc, projectId, testTransport } = {}) {
  if (!adc || adc.type !== 'authorized_user') throw new StoreRefusal('STORE_ADC_NOT_USER_CREDENTIAL');
  const { Firestore, UserRefreshClient } = pinnedModules();
  const authClient = new UserRefreshClient({
    clientId: adc.client_id,
    clientSecret: adc.client_secret,
    refreshToken: adc.refresh_token,
    ...(testTransport?.tokenTransporter ? { transporter: testTransport.tokenTransporter } : {}),
  });
  if (adc.quota_project_id) authClient.quotaProjectId = adc.quota_project_id;
  const settings = firestoreSettings({ projectId, authClient });
  if (testTransport?.servicePath) {
    settings.servicePath = testTransport.servicePath;
    settings.port = testTransport.port;
  }
  return {
    authClient,
    credential: adminCredential(authClient),
    firestore: new Firestore(settings),
  };
}

// The emulator target keeps no credential: the emulators ignore it.
export function createEmulatorFirestore({ projectId }) {
  const { Firestore } = pinnedModules();
  return new Firestore(firestoreSettings({ projectId }));
}
