import express from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import serverless from 'serverless-http';
import dotenv from 'dotenv';
// --- Firebase setup ---
dotenv.config();


admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    clientId: process.env.FIREBASE_CLIENT_ID,
    authUri: process.env.FIREBASE_AUTH_URI,
    tokenUri: process.env.FIREBASE_TOKEN_URI,
    authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_CERT_URL,
    clientC509CertUrl: process.env.FIREBASE_CLIENT_CERT_URL,
    universeDomain: process.env.FIREBASE_UNIVERSE_DOMAIN
  }),
});

const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

// --- Express setup ---
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const accessToken = process.env.ACCESS_TOKEN;
const phoneNumberId = process.env.phoneNumberId;
const verifyToken = process.env.verifyToken;

// --- Helper: send WhatsApp messages via fetch (native in Node 18+) ---
async function sendTextMessage(to, message) {
  await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to,
      text: { body: message }
    })
  });
}

async function sendButtonMessage(to, text, buttons) {
  await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to,
      type: 'interactive',
      interactive: {
        type: 'button',
        body: { text },
        action: { buttons }
      }
    })
  });
}

// --- Webhook verification ---
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === verifyToken) {
      console.log('✅ Webhook verified!');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  } else {
    res.sendStatus(400);
  }
});

// --- Webhook POST ---
app.post('/webhook', async (req, res) => {
  const body = req.body;

  if (body.object && body.entry?.[0].changes?.[0].value.messages) {
    const message = body.entry[0].changes[0].value.messages[0];
    const from = message.from;
    const text = message.text?.body?.trim() || '';

    const userRef = db.collection('users').doc(from);
    const userSnap = await userRef.get();

    if (userSnap.exists) {
      const userData = userSnap.data();
      await sendTextMessage(from, `Welcome back, ${userData.firstName}! 🎉`);
    } else {
      const flowRef = db.collection('flows').doc(from);
      const flowSnap = await flowRef.get();
      const flowData = flowSnap.data();

      if (!flowSnap.exists) {
        await sendTextMessage(from, 'Welcome to Zlt Topup! Please enter your FIRST NAME:');
        await flowRef.set({ step: 1 });
      } else if (flowData.step === 1) {
        await flowRef.update({ firstName: text, step: 2 });
        await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
      } else if (flowData.step === 2) {
        await flowRef.update({ lastName: text, step: 3 });
        await sendTextMessage(from, 'Almost done! Please enter your EMAIL:');
      } else if (flowData.step === 3) {
        const { firstName, lastName } = flowData;
        const email = text;

        if (!firstName || !lastName || !email) {
          await sendTextMessage(from, 'Error: Missing information. Please restart registration.');
          return;
        }

        const pinToken = crypto.randomBytes(16).toString('hex');
        const expiresAt = admin.firestore.Timestamp.fromDate(new Date(Date.now() + 5 * 60 * 1000));

        await db.collection('pinTokens').doc(pinToken).set({
          phone: from,
          firstName,
          lastName,
          email,
          expiresAt
        });

        const pinUrl = `https://whatsapbot.vercel.app/set-pin/${pinToken}`;
        await sendTextMessage(from, `Almost done! Please set your PIN securely here: ${pinUrl} (expires in 5 minutes)`);

        await flowRef.update({ step: 4 });
      }
    }
  }

  res.sendStatus(200);
});

// --- PIN setup ---
app.get('/set-pin/:token', async (req, res) => {
  const tokenRef = db.collection('pinTokens').doc(req.params.token);
  const tokenSnap = await tokenRef.get();

  if (!tokenSnap.exists) return res.send('Invalid or expired token.');

  const tokenData = tokenSnap.data();
  if (tokenData.expiresAt.toMillis() < admin.firestore.Timestamp.now().toMillis()) {
    await tokenRef.delete();
    return res.send('Token expired. Please restart registration.');
  }

  res.send(`
    <html>
    <head>
        <title>Set Zlt Topup PIN</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f8; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 100%; }
            h2 { color: #2c3e50; margin-bottom: 30px; }
            input[type="password"] { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 8px; font-size: 16px; }
            button { width: 100%; padding: 12px; background-color: #27ae60; color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: background 0.3s; }
            button:hover { background-color: #219150; }
            p { font-size: 14px; color: #7f8c8d; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Set your Zlt Topup PIN</h2>
            <form method="POST" action="/set-pin/${token}">
                <input type="password" name="pin" placeholder="Enter 4-digit PIN" maxlength="4" required />
                <button type="submit">Set PIN</button>
            </form>
            <p>PIN will expire in 5 minutes. Keep it secure!</p>
        </div>
    </body>
    </html>
`);
});

app.post('/set-pin/:token', async (req, res) => {
  const token = req.params.token;
  const pin = req.body.pin;

  const tokenRef = db.collection('pinTokens').doc(token);
  const tokenSnap = await tokenRef.get();
  if (!tokenSnap.exists) return res.send('Invalid or expired token.');

  const { phone, firstName, lastName, email } = tokenSnap.data();

  await db.collection('users').doc(phone).set({
    firstName,
    lastName,
    phone,
    email,
    pin,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  await tokenRef.delete();
  await db.collection('flows').doc(phone).delete();

  try {
    // Create Paystack customer
    const customerResponse = await axios.post(
      "https://api.paystack.co/customer",
      { email, first_name: firstName, last_name: lastName, phone },
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
    );

    const customerCode = customerResponse.data.data.customer_code;

    // Create dedicated account
    const accountResponse = await axios.post(
      "https://api.paystack.co/dedicated_account",
      { customer: customerCode, preferred_bank: "wema-bank" },
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
    );

    const accountData = accountResponse.data.data;

    await sendTextMessage(phone,
      `🎉 ${firstName} ${lastName}, your account is ready!\n` +
      `🏦 Bank: ${accountData.bank.name}\n` +
      `💳 Account Name: ${accountData.account_name}\n` +
      `🔢 Account Number: ${accountData.account_number}`
    );

    res.json({ status: true, message: 'PIN set successfully!', customer: customerResponse.data.data, dedicated_account: accountData });
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { message: err.message });
  }
});

// --- Export serverless handler ---
export const handler = serverless(app);
