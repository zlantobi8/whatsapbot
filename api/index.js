import express from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';

dotenv.config();

// ---------- Firebase ----------
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

// ---------- Express ----------
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ---------- ENV ----------
const accessToken = process.env.ACCESS_TOKEN;
const phoneNumberId = process.env.phoneNumberId; // Ensure this matches your .env key
const verifyToken = process.env.verifyToken;

// ---------- Helpers ----------
const greetings = ['hi', 'hello', 'hey', 'yo', 'sup', 'menu'];

function isValidName(s) {
  // allows letters, spaces, hyphens, apostrophes; 2–32 chars
  return /^[A-Za-z][A-Za-z\s'-]{1,31}$/.test((s || '').trim());
}
function isValidEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test((s || '').trim());
}
function isValidPin(s) {
  return /^\d{4}$/.test((s || '').trim());
}

// Safely extract interactive reply id/title
function getInteractiveReply(message) {
  if (message?.type !== 'interactive') return null;
  const ir = message.interactive || {};
  if (ir.button_reply) {
    return { id: ir.button_reply.id, title: ir.button_reply.title };
  }
  if (ir.list_reply) {
    return { id: ir.list_reply.id, title: ir.list_reply.title };
  }
  return null;
}

// WhatsApp senders
async function sendTextMessage(to, message) {
  try {
    const res = await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', to, text: { body: message } })
    });
    const data = await res.json();
    if (data.error) console.error('WA Text Error:', data.error);
    return data;
  } catch (e) {
    console.error('WA Text Exception:', e);
    return { error: e.message };
  }
}

async function sendButtonMessage(to, text, buttons /* [{id,title}] max 3 */) {
  const payload = {
    messaging_product: 'whatsapp',
    to,
    type: 'interactive',
    interactive: {
      type: 'button',
      body: { text },
      action: {
        buttons: buttons.slice(0, 3).map(b => ({
          type: 'reply',
          reply: { id: b.id, title: b.title }
        }))
      }
    }
  };
  try {
    const res = await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.error) console.error('WA Button Error:', data.error, 'Payload:', JSON.stringify(payload));
    return data;
  } catch (e) {
    console.error('WA Button Exception:', e, 'Payload:', JSON.stringify(payload));
    return { error: e.message };
  }
}

// ---------------- Webhook Verification ----------------
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === verifyToken) {
      console.log('✅ Webhook verified');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  } else {
    res.sendStatus(400);
  }
});

// ---------------- Webhook POST ----------------
app.post('/webhook', async (req, res) => {
  const body = req.body;

  try {
    if (!(body.object && body.entry?.[0].changes?.[0].value.messages)) {
      return res.sendStatus(200); // No valid message
    }

    const message = body.entry[0].changes[0].value.messages[0];
    const from = message.from;
    const text = message.text?.body?.trim() || '';
    const lowerText = text.toLowerCase();
    const greetings = ['hi', 'hello', 'hey', 'yo', 'sup'];
    const userRef = db.collection('users').doc(from);
    const flowRef = db.collection('flows').doc(from);

    const [userSnap, flowSnap] = await Promise.all([
      userRef.get(),
      flowRef.get()
    ]);

    // ---------- EXISTING USER ----------
    if (userSnap.exists) {
      const userData = userSnap.data();

      // Greeting → Show menu
      if (greetings.includes(lowerText)) {
        await sendTextMessage(from, `Welcome back, ${userData.firstName}! 🎉`);
        await sendTextMessage(
          from,
          `Please choose an option:\n1️⃣ Buy Airtime\n2️⃣ Buy Data\n3️⃣ Check Balance\n4️⃣ View Account Details`
        );
        return res.sendStatus(200);
      }

      // Menu choice handling
      switch (lowerText) {
        case '1':
          await sendTextMessage(from, 'You selected Buy Airtime. Please enter the amount:');
          break;
        case '2':
          await sendTextMessage(from, 'You selected Buy Data. Please choose a data plan:');
          break;
        case '3':
          await sendTextMessage(from, 'Fetching your balance... 💰');
          break;
        case '4':
          if (userData.bank) {
            await sendTextMessage(
              from,
              `🏦 Bank: ${userData.bank.name}\n💳 Account Name: ${userData.bank.accountName}\n🔢 Account Number: ${userData.bank.accountNumber}`
            );
          } else {
            await sendTextMessage(from, 'Sorry, your bank details are not available.');
          }
          break;
        default:
          await sendTextMessage(from, 'Invalid selection. Please reply with 1, 2, 3, or 4.');
      }
      return res.sendStatus(200);
    }

    // ---------- NEW USER REGISTRATION ----------
    let flowData = flowSnap.data() || {};

    // Step 0: Start registration
    if (!flowSnap.exists) {
      if (greetings.includes(lowerText)) {
        await flowRef.set({ step: 1 });
        await sendTextMessage(from, 'Welcome to Zlt Topup! Please enter your FIRST NAME:');
        return res.sendStatus(200);
      } else {
        await flowRef.set({ firstName: text, step: 2 });
        await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
        return res.sendStatus(200);
      }
    }

    // Step 1: First name
    if (flowData.step === 1) {
      if (greetings.includes(lowerText) || !/^[a-zA-Z]+$/.test(text)) {
        await sendTextMessage(from, 'Please enter a valid FIRST NAME:');
        return res.sendStatus(200);
      }
      await flowRef.update({ firstName: text, step: 2 });
      await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
      return res.sendStatus(200);
    }

    // Step 2: Last name
    if (flowData.step === 2) {
      if (greetings.includes(lowerText) || !/^[a-zA-Z]+$/.test(text)) {
        await sendTextMessage(from, 'Please enter a valid LAST NAME:');
        return res.sendStatus(200);
      }
      await flowRef.update({ lastName: text, step: 3 });
      await sendTextMessage(from, 'Almost done! Please enter your EMAIL:');
      return res.sendStatus(200);
    }

    // Step 3: Email
    if (flowData.step === 3) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(text)) {
        await sendTextMessage(from, '❌ Invalid email. Please enter a valid EMAIL:');
        return res.sendStatus(200);
      }

      const { firstName, lastName } = flowData;
      const email = text;
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

      // Save final user
      await userRef.set({ firstName, lastName, email });
      await flowRef.delete(); // Clear registration flow
      return res.sendStatus(200);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook POST error:', err);
    res.status(500).json({ error: err.message });
  }
});


// ---------------- PIN Pages ----------------
app.get('/set-pin/:token', async (req, res) => {
  const tokenRef = db.collection('pinTokens').doc(req.params.token);
  const tokenSnap = await tokenRef.get();

  if (!tokenSnap.exists) return res.send('Invalid or expired token.');

  const tokenData = tokenSnap.data();
  if (tokenData.expiresAt.toMillis() < Date.now()) {
    await tokenRef.delete();
    return res.send('Token expired. Please restart registration.');
  }

  res.send(`
    <html>
    <head>
      <title>Set Zlt Topup PIN</title>
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #f4f6f8; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); text-align: center; max-width: 420px; width: 100%; }
        input[type="password"] { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 8px; font-size: 16px; letter-spacing: 0.3em; text-align: center; }
        button { width: 100%; padding: 12px; background-color: #27ae60; color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: background 0.2s; }
        button:hover { background-color: #219150; }
        .hint { color: #555; font-size: 14px; }
        .error { color: #c0392b; margin-bottom: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Set your Zlt Topup PIN</h2>
        <form method="POST" action="/set-pin/${req.params.token}" enctype="application/x-www-form-urlencoded">
          <input type="password" name="pin" placeholder="Enter 4-digit PIN" maxlength="4" required />
          <button type="submit">Set PIN</button>
        </form>
        <p class="hint">PIN expires in 5 minutes. Keep it secure!</p>
      </div>
    </body>
    </html>
  `);
});

app.post('/set-pin/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const pin = (req.body.pin || '').trim();

    const tokenRef = db.collection('pinTokens').doc(token);
    const tokenSnap = await tokenRef.get();
    if (!tokenSnap.exists) return res.send('Invalid or expired token.');

    if (!isValidPin(pin)) {
      return res.send('PIN must be exactly 4 digits.');
    }

    const { phone, firstName, lastName, email, expiresAt } = tokenSnap.data();
    if (expiresAt.toMillis() < Date.now()) {
      await tokenRef.delete();
      return res.send('Token expired. Please restart registration.');
    }

    // Create Paystack customer
    const customerResponse = await axios.post(
      'https://api.paystack.co/customer',
      { email, first_name: firstName, last_name: lastName, phone },
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
    );
    const customerCode = customerResponse.data.data.customer_code;

    // Create dedicated account
    const accountResponse = await axios.post(
      'https://api.paystack.co/dedicated_account',
      { customer: customerCode, preferred_bank: 'wema-bank' },
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
    );
    const accountData = accountResponse.data.data;

    // ⚠️ Security note: consider hashing the PIN in production
    await db.collection('users').doc(phone).set({
      firstName,
      lastName,
      phone,
      email,
      pin, // store hashed in real apps
      balance: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      bank: {
        name: accountData.bank.name,
        accountName: accountData.account_name,
        accountNumber: accountData.account_number,
        customerCode
      }
    });

    // Clean up
    await tokenRef.delete();
    await db.collection('flows').doc(phone).delete();

    // WhatsApp confirmation + immediate menu
    const whatsappMessage =
      `🎉 ${firstName} ${lastName}, your account is ready!\n` +
      `🏦 Bank: ${accountData.bank.name}\n` +
      `💳 Account Name: ${accountData.account_name}\n` +
      `🔢 Account Number: ${accountData.account_number}`;

    await sendTextMessage(phone, whatsappMessage);

    // Show main menu (split across 2 messages to respect 3-button limit)
    await sendButtonMessage(phone, 'What would you like to do next?', [
      { id: 'buy_airtime', title: 'Buy Airtime' },
      { id: 'buy_data', title: 'Buy Data' },
      { id: 'check_balance', title: 'Check Balance' },
    ]);
    await sendButtonMessage(phone, 'More options:', [
      { id: 'view_account', title: 'View Account Details' }
    ]);

    // HTML response
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
    console.error('PIN route error:', err.response?.data || err.message);
    res.send('Error creating account. Please try again later.');
  }
});

// ---------------- Server ----------------
app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
