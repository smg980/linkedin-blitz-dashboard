import { initializeApp, deleteApp } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

export async function writeSyntheticEnvelope({ projectId, uid, envelope }) {
  const app = initializeApp({ projectId }, `synthetic-${uid}`);
  try {
    const db = getFirestore(app);
    await db.doc(`linkedinBlitzPrivate/${uid}`).set(envelope);
  } finally {
    await Promise.race([
      deleteApp(app),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
  }
}
