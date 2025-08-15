import admin from 'firebase-admin';
import serviceAccount from './serviceAccountKey.json' assert { type: 'json' };

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://zltnew-e9f7d.firebaseio.com" // optional if using Realtime DB
});

export const db = admin.firestore(); // for Firestore
