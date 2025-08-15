import express from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';

dotenv.config();

// --- Firebase setup ---
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
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const accessToken = process.env.ACCESS_TOKEN;
const phoneNumberId = process.env.phoneNumberId;
const verifyToken = process.env.verifyToken;

// --- WhatsApp helpers ---
async function sendTextMessage(to, message) {
  const res = await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
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
  return await res.json();
}

async function sendButtonMessage(to, text, buttons) {
  const res = await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
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
  return await res.json();
}

// --- Webhook verification ---
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === verifyToken) {
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

  try {
    if (body.object && body.entry?.[0].changes?.[0].value.messages) {
      const message = body.entry[0].changes[0].value.messages[0];
      const from = message.from;
      const text = message.text?.body?.trim() || '';
      const buttonReply = message.button?.text?.trim();

      const greetings = ['hi', 'hello', 'hey', 'yo', 'sup'];

      // --- Check if user exists ---
      const userRef = db.collection('users').doc(from);
      const userSnap = await userRef.get();

      if (userSnap.exists) {
        const userData = userSnap.data();

        // If greeting → send menu
        if (greetings.includes(text.toLowerCase())) {
          await sendTextMessage(from, `Welcome back, ${userData.firstName}! 🎉`);
          await sendButtonMessage(from, 'Please choose an option:', [
            { type: 'reply', reply: { id: 'buy_airtime', title: 'Buy Airtime' } },
            { type: 'reply', reply: { id: 'buy_data', title: 'Buy Data' } },
            { type: 'reply', reply: { id: 'check_balance', title: 'Check Balance' } },
            { type: 'reply', reply: { id: 'view_account', title: 'View Account Details' } }
          ]);
          return res.sendStatus(200);
        }

        // Handle button responses
        if (buttonReply) {
          switch (buttonReply) {
            case 'Buy Airtime':
              await sendTextMessage(from, 'You selected Buy Airtime. Please enter the amount:');
              break;
            case 'Buy Data':
              await sendTextMessage(from, 'You selected Buy Data. Please choose a data plan:');
              break;
            case 'Check Balance':
              await sendTextMessage(from, 'Fetching your balance... 💰');
              break;
            case 'View Account Details':
              await sendTextMessage(from, `🏦 Bank: ${userData.bank.name}\n💳 Account Name: ${userData.bank.accountName}\n🔢 Account Number: ${userData.bank.accountNumber}`);
              break;
            default:
              await sendTextMessage(from, 'Invalid selection.');
          }
          return res.sendStatus(200);
        }
      }

      // --- New user registration flow ---
      const flowRef = db.collection('flows').doc(from);
      const flowSnap = await flowRef.get();
      const flowData = flowSnap.data() || {};

      if (!flowSnap.exists) {
        if (greetings.includes(text.toLowerCase())) {
          await sendTextMessage(from, 'Welcome to Zlt Topup! Please enter your FIRST NAME:');
          await flowRef.set({ step: 1 });
          return res.sendStatus(200);
        } else if (/^[a-zA-Z]+$/.test(text)) {
          await flowRef.set({ firstName: text, step: 2 });
          await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
          return res.sendStatus(200);
        } else {
          await sendTextMessage(from, 'Please enter a valid FIRST NAME:');
          await flowRef.set({ step: 1 });
          return res.sendStatus(200);
        }
      }

      if (flowData.step === 1) {
        if (/^[a-zA-Z]+$/.test(text)) {
          await flowRef.update({ firstName: text, step: 2 });
          await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
        } else {
          await sendTextMessage(from, 'Please enter a valid FIRST NAME:');
        }
        return res.sendStatus(200);
      }

      if (flowData.step === 2) {
        if (/^[a-zA-Z]+$/.test(text)) {
          await flowRef.update({ lastName: text, step: 3 });
          await sendTextMessage(from, 'Almost done! Please enter your EMAIL:');
        } else {
          await sendTextMessage(from, 'Please enter a valid LAST NAME:');
        }
        return res.sendStatus(200);
      }

      if (flowData.step === 3) {
        const { firstName, lastName } = flowData;
        const email = text;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
          await sendTextMessage(from, 'Please enter a valid EMAIL address:');
          return res.sendStatus(200);
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
        return res.sendStatus(200);
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook POST error:', err);
    res.status(500).json({ error: err.message });
  }
});


app.get('/set-pin/:token', async (req, res) => {
  const tokenRef = db.collection('pinTokens').doc(req.params.token);
  const tokenSnap = await tokenRef.get();

  if (!tokenSnap.exists) return res.send('Invalid or expired token.');

  const tokenData = tokenSnap.data();
  if (tokenData.expiresAt.toMillis() < Date.now()) {
    await tokenRef.delete();
    return res.send('Token expired. Please restart registration.');
  }

  // Serve simple HTML form
  res.send(`
    <html>
    <head>
      <title>Set Zlt Topup PIN</title>
      <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f4f6f8; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 100%; }
        input[type="password"] { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 8px; font-size: 16px; }
        button { width: 100%; padding: 12px; background-color: #27ae60; color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: background 0.3s; }
        button:hover { background-color: #219150; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Set your Zlt Topup PIN</h2>
        <form method="POST" action="/set-pin/${req.params.token}" enctype="application/x-www-form-urlencoded">
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
  console.log('POST /set-pin body:', req.body);

  const token = req.params.token;
  const pin = req.body.pin;

  const tokenRef = db.collection('pinTokens').doc(token);
  const tokenSnap = await tokenRef.get();
  if (!tokenSnap.exists) return res.send('Invalid or expired token.');

  const { phone, firstName, lastName, email } = tokenSnap.data();

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

    // Save user with PIN and account details
    await db.collection('users').doc(phone).set({
      firstName,
      lastName,
      phone,
      email,
      pin,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      bank: {
        name: accountData.bank.name,
        accountName: accountData.account_name,
        accountNumber: accountData.account_number,
        customerCode: customerCode
      }
    });

    // Clean up token and flow
    await tokenRef.delete();
    await db.collection('flows').doc(phone).delete();

    // Send WhatsApp confirmation
    const whatsappMessage =
      `🎉 ${firstName} ${lastName}, your account is ready!\n` +
      `🏦 Bank: ${accountData.bank.name}\n` +
      `💳 Account Name: ${accountData.account_name}\n` +
      `🔢 Account Number: ${accountData.account_number}`;

    await sendTextMessage(phone, whatsappMessage);

    res.send(`
      <html>
        <body style="font-family:sans-serif;text-align:center;padding:50px">
          <h2>🎉 PIN set successfully!</h2>
          <p>${firstName} ${lastName}, your account is ready.</p>
          <p>🏦 Bank: ${accountData.bank.name}</p>
          <p>💳 Account Name: ${accountData.account_name}</p>
          <p>🔢 Account Number: ${accountData.account_number}</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('Paystack error:', err.response?.data || err.message);
    res.send('Error creating account. Please try again later.');
  }
});



app.listen(3000, () => {
  console.log(`🚀 Server running on http://localhost:${3000}`);
});



