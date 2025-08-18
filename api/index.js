// server.js
import express from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';

dotenv.config();

/* ---------------- Firebase --------------- */
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


/* ---------------- ENV ------------ */

const accessToken = "EAAPYD7d0GSsBPKcq0e0rw7lV4LNrhZBZCrY69cKyUazXn3o0jU6dTF4ZBgQlBkFqz4k38zt3PGBKmxOXBiryA5eSTzawK6tOrSKJBqpauFQfcNB3vZABvwZCZCmZAYl4QUEdFvyPvkUogmBrT5jYyRj4TMsCqjBZAarbHjnuFNZBxyK78BkWCzWk04xhVbbR3Y2Um"
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






const networkNames = { 1: 'MTN', 2: 'Airtel', 3: 'Glo', 4: '9Mobile' };

// Utility: Compare plain PIN with hashed PIN
function checkPin(pin, pinHash) {
  const hash = crypto.createHash('sha256').update(pin).digest('hex');
  return hash === pinHash;
}

// GET route: Show PIN entry page
app.get('/verify-pin/:token', async (req, res) => {
  const tokenRef = db.collection('pinTokens').doc(req.params.token);
  const tokenSnap = await tokenRef.get();

  if (!tokenSnap.exists) return res.send('Invalid or expired link.');

  const { expiresAt } = tokenSnap.data();
  if (expiresAt.toMillis() < Date.now()) {
    await tokenRef.delete();
    return res.send('Link expired. Please start the top-up process again.');
  }

  // Render simple HTML page
  res.send(`
    <html>
      <head>
        <title>Enter PIN</title>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <style>
          body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; background:#f4f6f8; }
          .card { background:#fff; padding:32px; border-radius:12px; box-shadow:0 8px 24px rgba(0,0,0,0.1); max-width:400px; width:100%; text-align:center; }
          input { width:100%; padding:12px; font-size:16px; border:1px solid #d0d7de; border-radius:8px; margin:16px 0; text-align:center; letter-spacing:0.35em; }
          button { width:100%; padding:12px; font-size:16px; border:0; border-radius:8px; background:#27ae60; color:#fff; cursor:pointer; }
          button:hover { background:#1f8f50; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Enter your 4-digit PIN</h2>
          <form method="POST" action="/verify-pin/${req.params.token}">
            <input type="password" name="pin" maxlength="4" required />
            <button type="submit">Submit</button>
          </form>
        </div>
      </body>
    </html>
  `);
});

// POST route: Validate PIN and perform top-up
app.post('/verify-pin/:token', async (req, res) => {
  try {
    const tokenRef = db.collection('pinTokens').doc(req.params.token);
    const tokenSnap = await tokenRef.get();
    if (!tokenSnap.exists) return res.send('Invalid or expired link.');

    const { phone, network, topupPhone, amount, expiresAt } = tokenSnap.data();

    if (expiresAt.toMillis() < Date.now()) {
      await tokenRef.delete();
      return res.send('Link expired. Please start the top-up process again.');
    }

    // Get user from Firestore
    const userSnap = await db.collection('users').doc(phone).get();
    const user = userSnap.data();
    if (!user) return res.send('User not found.');

    // Check PIN
    const pin = (req.body.pin || '').trim();
    if (!checkPin(pin, user.pinHash)) {
      return res.send('Incorrect PIN. Please try again.');
    }

    // Call VTU API
    const topupData = {
      network: network.toString(),
      mobile_number: topupPhone,
      Ported_number: "true",
      request_id: `${Date.now()}`,
      amount: amount.toString(),
      airtime_type: "VTU"
    };

    let vtuResponse;
    try {
      vtuResponse = await axios.post(
        "https://sandbox.vtunaija.com.ng/api/topup/",
        topupData,
        {
          headers: {
            Authorization: "Token oluwatobilobad60bdcdf4165b62b81d41e6a83cb8c731e",
            "Content-Type": "application/json"
          }
        }
      );
    } catch (err) {
      console.error('VTU Error:', err.response?.data || err.message);
      return res.send('Top-up failed due to network or API error.');
    }

    if (vtuResponse.data?.status === 'success') {
      // Send WhatsApp confirmation
      await sendTextMessage(phone,
        `✅ Airtime top-up successful!\n` +
        `Network: ${networkNames[network]}\n` +
        `Phone: ${topupPhone}\n` +
        `Amount: ₦${amount}\n` +
        `Transaction ID: ${vtuResponse.data.id}`
      );

      // Clean up token
      await tokenRef.delete();

      return res.send(`
        <html>
          <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;text-align:center;padding:48px">
            <h2>✅ Top-up Successful!</h2>
            <p>Amount: ₦${amount}</p>
            <p>Network: ${networkNames[network]}</p>
            <p>Phone: ${topupPhone}</p>
            <p>Transaction ID: ${vtuResponse.data.id}</p>
            <p style="color:#6b7280;margin-top:24px">You can now return to WhatsApp.</p>
          </body>
        </html>
      `);
    } else {
      return res.send(`❌ Top-up failed: ${vtuResponse.data.api_response || 'Unknown error'}`);
    }

  } catch (err) {
    console.error('Verify PIN route error:', err);
    return res.send('An unexpected error occurred. Please try again.');
  }
});










async function handleMenuChoice(text, from, userData) {
  const input = text.trim();
  const flowRef = db.collection('flows').doc(from);
  const flowSnap = await flowRef.get();
  let flow = flowSnap.exists ? flowSnap.data() : {};

  try {
    switch(flow.step) {
      // -------- Step 0: Main Menu --------
      case undefined:
        switch(input) {
          case '1': // Buy Airtime
            await flowRef.set({ step: 'chooseNetwork' });
            await sendTextMessage(from, 'Select network:\n1️⃣ MTN\n2️⃣ Airtel\n3️⃣ Glo\n4️⃣ 9Mobile');
            break;
          case '2':
            await sendTextMessage(from, 'Buy Data is not implemented yet.');
            break;
          case '3':
            await sendTextMessage(from, `Your balance: ₦${Number(userData?.balance || 0).toLocaleString()}`);
            break;
          case '4':
            if(userData?.bank){
              await sendTextMessage(from, `🏦 Bank: ${userData.bank.name}\n💳 Account Name: ${userData.bank.accountName}\n🔢 Account Number: ${userData.bank.accountNumber}`);
            } else {
              await sendTextMessage(from, 'Bank details not available.');
            }
            break;
          default:
            await sendTextMessage(from, 'Invalid choice. Reply 1,2,3,4.');
        }
        break;

      // -------- Step 1: Choose Network --------
      case 'chooseNetwork':
        if(!['1','2','3','4'].includes(input)){
          await sendTextMessage(from, 'Invalid network. Reply 1,2,3,4.');
          return;
        }
        await flowRef.update({ step: 'enterPhone', network: parseInt(input,10) });
        await sendTextMessage(from, 'Enter the phone number to top up:');
        break;

      // -------- Step 2: Enter Phone Number --------
      case 'enterPhone':
        const phoneNumber = input.replace(/\D/g,'');
        if(phoneNumber.length < 10){
          await sendTextMessage(from, 'Please enter a valid 10-digit phone number.');
          return;
        }
        await flowRef.update({ step: 'enterAmount', phone: phoneNumber });
        await sendTextMessage(from, 'Enter the amount to top up:');
        break;

      // -------- Step 3: Enter Amount --------
      case 'enterAmount':
        const amount = parseInt(input,10);
        if(isNaN(amount) || amount <=0){
          await sendTextMessage(from,'Please enter a valid amount.');
          return;
        }

        // Retrieve flow data
        const { network, phone: topupPhone } = flow;

        // -------- Generate PIN verification link --------
        const token = crypto.randomBytes(16).toString('hex');
        const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000);

        await db.collection('pinTokens').doc(token).set({
          phone: from,
          network,
          topupPhone,
          amount,
          expiresAt
        });

        const link = `https://whatsapbot.vercel.app/verify-pin/${token}`;
        await sendTextMessage(from,
          `To complete your top-up of ₦${amount}, please verify your PIN here:\n${link}\n\nLink expires in 5 minutes.`
        );

        // Clear flow so user can start new operation later
        await flowRef.delete();
        break;

      default:
        await sendTextMessage(from, 'Something went wrong. Returning to main menu.');
        await flowRef.delete();
    }

  } catch(e){
    console.error('Menu handling error:', e);
    await sendTextMessage(from, 'Unexpected error. Please try again.');
    await flowRef.delete();
  }
}

// Paystack webhook
app.post(
  '/webhook/paystack',
  express.raw({ type: 'application/json' }), // ensures req.body is a Buffer
  async (req, res) => {
    try {
      const paystackSignature = req.headers['x-paystack-signature'];

      // req.body is a Buffer here
      const hash = crypto
        .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
        .update(req.body) // must be Buffer, not object
        .digest('hex');

      if (hash !== paystackSignature) {
        console.warn('⚠️ Invalid Paystack signature');
        return res.sendStatus(400);
      }

      // Respond early to avoid timeouts
      res.sendStatus(200);

      const event = JSON.parse(req.body.toString());

      // Only handle successful charges on dedicated accounts
      if (event.event !== 'charge.success' || event.data.channel !== 'dedicated_nuban') return;

      const data = event.data;
      const receiverAccount = data.metadata?.receiver_account_number;
      if (!receiverAccount) return console.warn('No receiver account in metadata.');

      const amount = data.amount / 100;
      const reference = data.reference;
      const senderName = data.authorization?.sender_name || 'Unknown';
      const senderBank = data.authorization?.sender_bank || 'Unknown';
      const paidAt = new Date(data.paid_at);

      console.log(`💰 Deposit received for account: ${receiverAccount}, reference: ${reference}`);

      // Firestore processing (async)
      (async () => {
        try {
          const userSnap = await admin.firestore().collection('users')
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
          const newBalance = await admin.firestore().runTransaction(async (tx) => {
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

          // Send WhatsApp receipt
          try {
            const message =
              `💰 *Payment Received!*\n\n` +
              `Amount: ₦${amount.toLocaleString()}\n` +
              `From: ${senderName} (${senderBank})\n` +
              `Reference: ${reference}\n` +
              `Paid At: ${paidAt.toLocaleString()}\n` +
              `\n🏦 New Balance: ₦${newBalance.toLocaleString()}\n` +
              `Thank you for using ZLT Topup!`;

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
    }
  }
);





app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());



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





/* ---------------- Privacy Policy Endpoint ---------------- */
app.get("/privacy-policy", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Privacy Policy - ZLt Topup</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          line-height: 1.6;
          margin: 2rem;
          background: #f9f9f9;
          color: #333;
        }
        h1 { color: #0d6efd; }
      </style>
    </head>
    <body>
      <h1>Privacy Policy</h1>
      <p>At <strong>ZLt Topup</strong>, we value your privacy. This Privacy Policy explains how we collect, use, and protect your personal information.</p>
      
      <h2>Information We Collect</h2>
      <p>We may collect your email, name, and payment details when you use our platform.</p>
      
      <h2>How We Use Information</h2>
      <p>Your information is used solely for account creation, service delivery, and transaction verification.</p>
      
      <h2>Security</h2>
      <p>We implement industry-standard security to protect your data against unauthorized access.</p>
      
      <h2>Contact Us</h2>
      <p>If you have any questions, contact us at <a href="mailto:zlttopup@gmail.com">zlttopup@gmail.com</a>.</p>
    </body>
    </html>
  `);
});

/* ---------------- Data Deletion Endpoint ---------------- */
app.get("/delete-user-data", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Data Deletion - ZLt Topup</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          line-height: 1.6;
          margin: 2rem;
          background: #f9f9f9;
          color: #333;
        }
        h1 { color: #dc3545; }
      </style>
    </head>
    <body>
      <h1>Data Deletion Instructions</h1>
      <p>At <strong>ZLt Topup</strong>, we respect your privacy and give you full control over your data.</p>
      
      <h2>How to Request Deletion</h2>
      <p>If you would like to delete your account and associated data, please send an email to 
      <a href="mailto:zlttopup@gmail.com">zlttopup@gmail.com</a> using your registered email address.</p>
      
      <p>Once we receive your request, we will verify your identity and process the deletion within <strong>7 business days</strong>.</p>
      
      <h2>Automatic Deletion</h2>
      <p>If you stop using our services for more than 12 months, we may automatically delete your data for security and compliance purposes.</p>
      
      <h2>Contact Us</h2>
      <p>For any questions about your data or this deletion process, please contact us at 
      <a href="mailto:zlttopup@gmail.com">zlttopup@gmail.com</a>.</p>
    </body>
    </html>
  `);
});

/* ---------------- Server ---------------- */
app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
