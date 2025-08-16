// server.js
import express from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';

dotenv.config();

/* ---------------- Firebase ---------------- */
admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
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

/* ---------------- Express ---------------- */
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

/* ---------------- ENV ---------------- */
const accessToken   = "EAAPYD7d0GSsBPDY3fQqANBDIuhZCGhmBfxSHG3kFDtAd7VqCHZAjIZCATViJBjzFcQTaIJeg5bXjTDZCpUg3ZC356ii478Gx7bThRQSHl6DAdoyrgfU3T2TmPAhGeWYpxKd3DtSsozZC19jHvKzzKTpjamQ5UHBZA82IKEeohB6rY6epgSWt06GTt2qXMadQURQ36jF1vYHWCIsgAcyiSCqakgsMPByrid3ZAOhwZA6jZAH9w9ZBVgZD";
const phoneNumberId = process.env.phoneNumberId;   // ensure this key matches your .env
const verifyToken   = process.env.verifyToken;

/* ---------------- Helpers ---------------- */
const GREETINGS = ['hi', 'hello', 'hey', 'yo', 'sup', 'menu'];

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

// (Optional but recommended) Hash PIN before storing
function hashPin(pin) {
  return crypto.createHash('sha256').update(pin).digest('hex');
}

async function sendTextMessage(to, message) {
  try {
    const res = await fetch(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', to, text: { body: message } })
    });
    const data = await res.json();
    if (data.error) console.error('WA Text Error:', data.error, 'Payload:', message);
    return data;
  } catch (e) {
    console.error('WA Text Exception:', e);
    return { error: e.message };
  }
}

async function sendMainMenu(to, firstName) {
  if (firstName) {
    await sendTextMessage(to, `Welcome back, ${firstName}! 🎉`);
  }
  return sendTextMessage(
    to,
    `Please choose an option:\n` +
    `1️⃣ Buy Airtime\n` +
    `2️⃣ Buy Data\n` +
    `3️⃣ Check Balance\n` +
    `4️⃣ View Account Details`
  );
}

async function handleMenuChoice(lowerText, from, userData) {
  switch (lowerText) {
    case '1':
      await sendTextMessage(from, 'You selected Buy Airtime. Please enter the amount:');
      return;
    case '2':
      await sendTextMessage(from, 'You selected Buy Data. Please choose a data plan:');
      return;
    case '3':
      // Example: read balance from Firestore (default 0)
      await sendTextMessage(from, `Your current balance is: ₦${Number(userData?.balance || 0).toLocaleString()}`);
      return;
    case '4':
      if (userData?.bank) {
        await sendTextMessage(
          from,
          `🏦 Bank: ${userData.bank.name}\n` +
          `💳 Account Name: ${userData.bank.accountName}\n` +
          `🔢 Account Number: ${userData.bank.accountNumber}`
        );
      } else {
        await sendTextMessage(from, 'Sorry, your bank details are not available.');
      }
      return;
    default:
      await sendTextMessage(from, 'Invalid selection. Please reply with 1, 2, 3, or 4.');
      return;
  }
}

/* ---------------- Webhook Verification ---------------- */
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === verifyToken) {
      console.log('✅ Webhook verified');
      return res.status(200).send(challenge);
    }
    return res.sendStatus(403);
  }
  return res.sendStatus(400);
});

/* ---------------- Webhook POST ---------------- */
app.post('/webhook', async (req, res) => {
  const body = req.body;
  try {
    const hasMsg = body.object && body.entry?.[0].changes?.[0].value?.messages;
    if (!hasMsg) return res.sendStatus(200);

    const message = body.entry[0].changes[0].value.messages[0];
    const from = message.from;
    const text = (message.text?.body || '').trim();
    const lowerText = text.toLowerCase();

    const userRef = db.collection('users').doc(from);
    const flowRef = db.collection('flows').doc(from);

    const [userSnap, flowSnap] = await Promise.all([userRef.get(), flowRef.get()]);
    const userExists = userSnap.exists;
    const userData = userExists ? userSnap.data() : null;
    const flowData = flowSnap.exists ? (flowSnap.data() || {}) : {};

    /* ---------- EXISTING USER: show menu / handle menu ---------- */
    if (userExists) {
      // Any greeting or the word "menu" => show menu
      if (GREETINGS.includes(lowerText)) {
        await sendMainMenu(from, userData.firstName);
        return res.sendStatus(200);
      }
      // Handle menu choice by number
      await handleMenuChoice(lowerText, from, userData);
      return res.sendStatus(200);
    }

    /* ---------- NEW USER REGISTRATION FLOW ---------- */

    // If no flow yet, start it. Reject greetings as first name.
    if (!flowSnap.exists) {
      if (GREETINGS.includes(lowerText) || !isValidName(text)) {
        await flowRef.set({ step: 1 });
        await sendTextMessage(from, 'Welcome to Zlt Topup! Please enter your FIRST NAME:');
        return res.sendStatus(200);
      }
      // Non-greeting and valid name: accept as first name
      await flowRef.set({ step: 2, firstName: text });
      await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
      return res.sendStatus(200);
    }

    // Step 1: Expect FIRST NAME
    if (flowData.step === 1) {
      if (GREETINGS.includes(lowerText) || !isValidName(text)) {
        await sendTextMessage(from, 'Please enter a valid FIRST NAME (letters only):');
        return res.sendStatus(200);
      }
      await flowRef.update({ step: 2, firstName: text });
      await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
      return res.sendStatus(200);
    }

    // Step 2: Expect LAST NAME
    if (flowData.step === 2) {
      if (GREETINGS.includes(lowerText) || !isValidName(text)) {
        await sendTextMessage(from, 'Please enter a valid LAST NAME (letters only):');
        return res.sendStatus(200);
      }
      await flowRef.update({ step: 3, lastName: text });
      await sendTextMessage(from, 'Almost done! Please enter your EMAIL:');
      return res.sendStatus(200);
    }

    // Step 3: Expect EMAIL -> generate PIN token + link
    if (flowData.step === 3) {
      if (!isValidEmail(text)) {
        await sendTextMessage(from, '❌ Invalid email. Please enter a valid EMAIL:');
        return res.sendStatus(200);
      }

      const { firstName, lastName } = flowData;
      const email = text;
      const pinToken = crypto.randomBytes(16).toString('hex');
      const expiresAt = admin.firestore.Timestamp.fromDate(new Date(Date.now() + 5 * 60 * 1000));

      await db.collection('pinTokens').doc(pinToken).set({
        phone: from, firstName, lastName, email, expiresAt
      });

      const pinUrl = `https://whatsapbot.vercel.app/set-pin/${pinToken}`;
      await sendTextMessage(
        from,
        `Almost done! Please set your 4-digit PIN here within 5 minutes:\n${pinUrl}`
      );

      // Keep flow so user can resume if needed; do not write to users yet
      await flowRef.update({ step: 4, awaitingPin: true });
      return res.sendStatus(200);
    }

    // Step 4: Waiting for PIN to be set via link — if they text here, guide them.
    if (flowData.step === 4) {
      await sendTextMessage(
        from,
        `Please open the link we sent to set your PIN. If it expired, reply "restart" to start again.`
      );
      return res.sendStatus(200);
    }

    return res.sendStatus(200);
  } catch (err) {
    console.error('Webhook POST error:', err);
    return res.status(500).json({ error: err.message });
  }
});

/* ---------------- PIN Pages ---------------- */
app.get('/set-pin/:token', async (req, res) => {
  const tokenRef = db.collection('pinTokens').doc(req.params.token);
  const tokenSnap = await tokenRef.get();
  if (!tokenSnap.exists) return res.send('Invalid or expired token.');

  const tokenData = tokenSnap.data();
  if (tokenData.expiresAt.toMillis() < Date.now()) {
    await tokenRef.delete();
    return res.send('Token expired. Please restart registration in WhatsApp.');
  }

  res.send(`
    <html>
    <head>
      <title>Set Zlt Topup PIN</title>
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
        body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: #f4f6f8; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
        .card { background:#fff; padding:32px; border-radius:12px; box-shadow:0 8px 24px rgba(0,0,0,0.1); width:100%; max-width:420px; text-align:center; }
        input { width:100%; padding:12px; font-size:16px; border:1px solid #d0d7de; border-radius:8px; margin:12px 0 20px; letter-spacing:0.35em; text-align:center; }
        button { width:100%; padding:12px; font-size:16px; border:0; border-radius:8px; background:#27ae60; color:#fff; cursor:pointer; }
        button:hover { background:#1f8f50; }
        .muted { color:#6b7280; font-size:14px; margin-top:8px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Set your Zlt Topup PIN</h2>
        <form method="POST" action="/set-pin/${req.params.token}" enctype="application/x-www-form-urlencoded">
          <input type="password" name="pin" placeholder="Enter 4-digit PIN" maxlength="4" required />
          <button type="submit">Set PIN</button>
        </form>
        <p class="muted">PIN expires in 5 minutes. Keep it secure!</p>
      </div>
    </body>
    </html>
  `);
});

app.post('/set-pin/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const pin = (req.body.pin || '').trim();

    if (!isValidPin(pin)) {
      return res.send('PIN must be exactly 4 digits.');
    }

    const tokenRef = db.collection('pinTokens').doc(token);
    const tokenSnap = await tokenRef.get();
    if (!tokenSnap.exists) return res.send('Invalid or expired token.');

    const { phone, firstName, lastName, email, expiresAt } = tokenSnap.data();

    if (expiresAt.toMillis() < Date.now()) {
      await tokenRef.delete();
      return res.send('Token expired. Please restart registration in WhatsApp.');
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

    // Save user with hashed PIN + starting balance
    await db.collection('users').doc(phone).set({
      firstName,
      lastName,
      phone,
      email,
      pinHash: hashPin(pin),          // storing hashed PIN (recommended)
      // pin: pin,                    // if you really need raw PIN, uncomment (NOT recommended)
      balance: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      bank: {
        name: accountData.bank.name,
        accountName: accountData.account_name,
        accountNumber: accountData.account_number,
        customerCode
      }
    });

    // Clean up token and any flow
    await tokenRef.delete();
    await db.collection('flows').doc(phone).delete().catch(() => {});

    // WhatsApp confirmation + show TEXT MENU (not buttons)
    const whatsappMessage =
      `🎉 ${firstName} ${lastName}, your account is ready!\n` +
      `🏦 Bank: ${accountData.bank.name}\n` +
      `💳 Account Name: ${accountData.account_name}\n` +
      `🔢 Account Number: ${accountData.account_number}`;
    await sendTextMessage(phone, whatsappMessage);
    await sendMainMenu(phone); // no buttons; text menu only

    // HTML response
    res.send(`
      <html>
        <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;text-align:center;padding:48px">
          <h2>🎉 PIN set successfully!</h2>
          <p>${firstName} ${lastName}, your account is ready.</p>
          <p>🏦 Bank: ${accountData.bank.name}</p>
          <p>💳 Account Name: ${accountData.account_name}</p>
          <p>🔢 Account Number: ${accountData.account_number}</p>
          <p style="color:#6b7280;margin-top:24px">You can now return to WhatsApp and reply with 1, 2, 3 or 4 from the menu I sent.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('PIN route error:', err.response?.data || err.message);
    res.send('Error creating account. Please try again later.');
  }
});



app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

// ✅ Verify Paystack Signature
function verifyPaystackSignature(req, res, next) {
  const paystackSignature = req.headers['x-paystack-signature'];
  const hash = crypto
    .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
    .update(req.rawBody)
    .digest('hex');

  if (hash !== paystackSignature) {
    console.error('❌ Invalid Paystack signature');
    return res.status(401).send('Invalid signature');
  }
  next();
}
// 
app.post('/webhook/paystack', verifyPaystackSignature, async (req, res) => {
  try {
    const { event, data } = req.body;

    if (event !== 'charge.success') {
      return res.sendStatus(200); // Ignore other events
    }

    // ✅ Ensure it's a DVA payment
    if (data.authorization?.channel !== 'dedicated_nuban') {
      return res.sendStatus(200);
    }

    const accountNumber = data.authorization.receiver_bank_account_number;
    const amount = data.amount / 100; // kobo → naira
    const txRef = data.reference;

    // ✅ Prevent duplicate processing
    const txRefDoc = db.collection('transactions').doc(txRef);
    const txRefSnap = await txRefDoc.get();
    if (txRefSnap.exists) {
      console.log('⚠️ Duplicate webhook ignored:', txRef);
      return res.sendStatus(200);
    }

    // ✅ Find matching user by reserved account number
    const userQuery = await db.collection('users')
      .where('bank.accountNumber', '==', accountNumber)
      .limit(1)
      .get();

    if (userQuery.empty) {
      console.error('❌ No matching user found for account:', accountNumber);
      return res.sendStatus(404);
    }

    const userDoc = userQuery.docs[0];
    const userData = userDoc.data();

    // ✅ Credit balance
    await userDoc.ref.update({
      balance: admin.firestore.FieldValue.increment(amount)
    });

    // ✅ Record transaction
    await txRefDoc.set({
      userId: userDoc.id,
      amount,
      type: 'credit',
      source: 'Paystack DVA',
      accountNumber,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // ✅ WhatsApp Notification (template)

    const templateParams = {
      name: userData.firstName,
      amount: amount.toFixed(2),
      balance: (userData.balance + amount).toFixed(2)
    };

   const whatsappMessage =
      `🎉 ${templateParams.name} , your account as been credited with!\n` +
      `🏦 Amount: ${templateParams.amount}\n` +
      `💳 Balance: ${templateParams.balance}\n` +
    await sendTextMessage(userData.phone, whatsappMessage);

    console.log(`✅ Payment of ₦${amount} credited to ${userData.firstName}`);
    res.sendStatus(200);

  } catch (err) {
    console.error('❌ Paystack Webhook Error:', err);
    res.sendStatus(500);
  }
});



/* ---------------- Server ---------------- */
app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
