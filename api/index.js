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

/* ---------------- ENV ------------ */

const accessToken = "EAAPYD7d0GSsBPGnmLRG4GSEuCxeGqfEEwinhmssu6Sg4VepSE3HbxEhaRiuHZCHwwO9rkvwAOAaMuQ8WAVTeXZAKp7bfu2s2tHUYssBWO60GSpXmqYIQ9suMXY9nbCkNg4WwEjg6UPf0IeUSyFzCLlJlnYnixHlx1natkwRmbZCRJYpUes1xettSRQGZBxrnzcxXPi9pgliJJfIH31NIpr6EKY9KSOp5BvZBzi6pojQxXsAZDZD";
const phoneNumberId = process.env.phoneNumberId;   // ensure this key matches your .env
const verifyToken = process.env.verifyToken;

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
const FLOW_EXPIRATION_MS = 15 * 60 * 1000; // 15 minutes
const PIN_EXPIRATION_MS = 5 * 60 * 1000;   // 5 minutes

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

    // ---------- CLEANUP EXPIRED FLOWS ----------
    const flowSnap = await flowRef.get();
    let flowData = flowSnap.exists ? flowSnap.data() : null;

    if (flowData?.updatedAt) {
      const now = Date.now();
      const updatedTime = flowData.updatedAt.toMillis();
      if (now - updatedTime > FLOW_EXPIRATION_MS) {
        await flowRef.delete();
        flowData = null;
        await sendTextMessage(from, '⏰ Your previous signup session expired. Don’t worry, let’s start fresh!');
      }
    }

    // ---------- CLEANUP EXPIRED PIN TOKENS ----------
    const pinTokensSnap = await db.collection('pinTokens')
      .where('phone', '==', from)
      .get();

    pinTokensSnap.forEach(async (doc) => {
      const tokenData = doc.data();
      if (tokenData.expiresAt.toMillis() < Date.now()) {
        await db.collection('pinTokens').doc(doc.id).delete();
      }
    });

    const userSnap = await userRef.get();
    const userExists = userSnap.exists;

    /* ---------- EXISTING USER ---------- */
    if (userExists) {
      if (GREETINGS.includes(lowerText)) {
        await sendMainMenu(from, userSnap.data().firstName);
        return res.sendStatus(200);
      }
      await handleMenuChoice(lowerText, from, userSnap.data());
      return res.sendStatus(200);
    }

    /* ---------- NEW USER FLOW ---------- */
    if (!flowData) {
      await flowRef.set({ step: 1, updatedAt: admin.firestore.Timestamp.now() });
      await sendTextMessage(
        from,
        `👋 Hello and welcome to *Zlt Topup*! \n\nWe are super excited to have you on board. To get started, let's create your account step by step. 🛡️\n\nFirst, may I know your *FIRST NAME*?`
      );
      return res.sendStatus(200);
    }

    /* ---------- STEP 1: FIRST NAME ---------- */
    if (flowData.step === 1) {
      if (GREETINGS.includes(lowerText) || !isValidName(text)) {
        await sendTextMessage(from, '❌ Please enter a valid FIRST NAME (letters only, no numbers or symbols):');
        return res.sendStatus(200);
      }
      await flowRef.update({ step: 2, firstName: text.trim(), updatedAt: admin.firestore.Timestamp.now() });
      await sendTextMessage(from, `🌟 Great, *${text.trim()}*! Now, what is your *LAST NAME*?`);
      return res.sendStatus(200);
    }

    /* ---------- STEP 2: LAST NAME ---------- */
    if (flowData.step === 2) {
      if (GREETINGS.includes(lowerText) || !isValidName(text)) {
        await sendTextMessage(from, '❌ Please enter a valid LAST NAME (letters only, no numbers or symbols):');
        return res.sendStatus(200);
      }

      const firstName = flowData.firstName.trim();
      const lastName = text.trim();

      const nameExistsQuery = await db.collection('users')
        .where('firstName', '==', firstName)
        .where('lastName', '==', lastName)
        .limit(1)
        .get();

      if (!nameExistsQuery.empty) {
        await sendTextMessage(from, '⚠️ Someone with this name already exists. Please enter a different LAST NAME:');
        return res.sendStatus(200);
      }

      await flowRef.update({ step: 3, lastName, updatedAt: admin.firestore.Timestamp.now() });
      await sendTextMessage(from, `Awesome! Almost done. Now, please provide your *EMAIL* so we can secure your account. ✉️`);
      return res.sendStatus(200);
    }

    /* ---------- STEP 3: EMAIL ---------- */
    if (flowData.step === 3) {
      if (!isValidEmail(text)) {
        await sendTextMessage(from, '❌ Invalid email format. Please enter a valid EMAIL:');
        return res.sendStatus(200);
      }

      const email = text.toLowerCase().trim();
      const { firstName, lastName } = flowData;

      await db.runTransaction(async (tx) => {
        const emailQuery = await tx.get(db.collection('users').where('email', '==', email).limit(1));
        if (!emailQuery.empty) throw new Error('email_exists');

        const nameQuery = await tx.get(db.collection('users')
          .where('firstName', '==', firstName)
          .where('lastName', '==', lastName)
          .limit(1));
        if (!nameQuery.empty) throw new Error('name_exists');

        const pinToken = crypto.randomBytes(16).toString('hex');
        const expiresAt = admin.firestore.Timestamp.fromDate(new Date(Date.now() + PIN_EXPIRATION_MS));

        tx.set(db.collection('pinTokens').doc(pinToken), {
          phone: from, firstName, lastName, email, expiresAt
        });

        await sendTextMessage(
          from,
          `🎉 Perfect! You're almost ready. Please set your 4-digit PIN using this secure link within 5 minutes:\nhttps://whatsapbot.vercel.app/set-pin/${pinToken}`
        );

        tx.update(flowRef, { step: 4, awaitingPin: true, updatedAt: admin.firestore.Timestamp.now() });
      }).catch(async (err) => {
        if (err.message === 'email_exists') {
          await sendTextMessage(from, '❌ This email is already registered. Please enter a different EMAIL:');
        } else if (err.message === 'name_exists') {
          await sendTextMessage(from, '⚠️ Someone with this name already exists. Please enter a different LAST NAME:');
          await flowRef.update({ step: 2, updatedAt: admin.firestore.Timestamp.now() });
        } else {
          console.error(err);
          await sendTextMessage(from, '❌ An error occurred. Please try again.');
        }
      });

      return res.sendStatus(200);
    }

    /* ---------- STEP 4: PIN ---------- */
    if (flowData.step === 4) {
      await sendTextMessage(
        from,
        `🔒 Please open the secure link we sent to set your PIN. If it expired, reply "restart" to start again.`
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
    await db.collection('flows').doc(phone).delete().catch(() => { });

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


/* ---------------- Paystack Webhook ---------------- */
app.post('/webhook/paystack', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const paystackSignature = req.headers['x-paystack-signature'];

    // Verify signature
    const hash = crypto
      .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
      .update(req.body)
      .digest('hex');

    if (hash !== paystackSignature) {
      console.warn('⚠️ Invalid Paystack signature');
      return res.sendStatus(400);
    }

    // Respond immediately to avoid 504
    res.sendStatus(200);

    // Parse webhook payload
    const event = JSON.parse(req.body.toString());

    // Only handle successful charges on dedicated accounts
    if (event.event !== 'charge.success' || event.data.channel !== 'dedicated_nuban') return;

    const data = event.data;
    const receiverAccount = data.metadata?.receiver_account_number;
    if (!receiverAccount) return console.warn('No receiver account in metadata.');

    const amount = data.amount / 100; // Convert kobo → Naira
    const reference = data.reference;
    const senderName = data.authorization?.sender_name || 'Unknown';
    const senderBank = data.authorization?.sender_bank || 'Unknown';
    const paidAt = new Date(data.paid_at);

    console.log(`💰 Deposit received for account: ${receiverAccount}, reference: ${reference}`);

    // Process Firestore asynchronously
    (async () => {
      try {
        const userSnap = await db.collection('users')
          .where('bank.accountNumber', '==', receiverAccount)
          .limit(1)
          .get();

        if (userSnap.empty) return console.warn(`No user found for account ${receiverAccount}.`);

        const userDoc = userSnap.docs[0];
        const userRef = userDoc.ref;

        // Idempotency check
        const existingTxSnap = await userRef.collection('transactions')
          .where('reference', '==', reference)
          .limit(1)
          .get();

        if (!existingTxSnap.empty) {
          console.log(`✅ Transaction ${reference} already processed. Skipping.`);
          return;
        }

        // Firestore transaction to update balance and log transaction
        const newBalance = await db.runTransaction(async (tx) => {
          const userData = (await tx.get(userRef)).data();
          const updatedBalance = (userData.balance || 0) + amount;

          tx.update(userRef, { balance: updatedBalance });
          tx.set(userRef.collection('transactions').doc(reference), {
            type: 'deposit',
            amount,
            reference,
            senderName,
            senderBank,
            receiverAccount,
            paidAt: admin.firestore.Timestamp.fromDate(paidAt),
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            status: 'success'
          });

          return updatedBalance;
        });

        // Send WhatsApp receipt (async, don't block webhook)
        try {
          const message =
            `💰 *Payment Received!*\n\n` +
            `Amount: ₦${amount.toLocaleString()}\n` +
            `From: ${senderName} (${senderBank})\n` +
            `Reference: ${reference}\n` +
            `Paid At: ${paidAt.toLocaleString()}\n` +
            `\n🏦 New Balance: ₦${newBalance.toLocaleString()}\n` +
            `Thank you for using Zlt Topup!`;

          await sendTextMessage(userDoc.data().phone, message);
          console.log(`📲 WhatsApp receipt sent to ${userDoc.data().phone}`);
        } catch (waErr) {
          console.error('🔥 WhatsApp sending error:', waErr);
        }

      } catch (err) {
        console.error('🔥 Error processing Paystack webhook:', err);
      }
    })();

  } catch (err) {
    console.error('🚨 Paystack webhook error:', err);
    // Already responded to avoid 504
  }
});


/* ---------------- Server ---------------- */
app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
