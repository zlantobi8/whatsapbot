// server.js
import express from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import path from "path";
import { fileURLToPath } from "url";
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
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
/* ---------------- Express ---------------- */
const app = express();
app.use("/static", express.static(path.join(__dirname, "static")));



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
    `4️⃣ Bank Info`
  );
}


// dataplans.js

const MTN_PLAN = {
  ALL: [
    { id: 304, dataplan_id: "304", network: 1, plan_type: "SME", plan_type1: "Datashare", plan_network: "MTN", month_validate: "30 Days", plan: "500MB", plan_amount: "450.00" },
    { id: 121, dataplan_id: "121", network: 1, plan_type: "SME", plan_type1: "Datashare", plan_network: "MTN", month_validate: "30 Days", plan: "1GB", plan_amount: "560.00" },
    { id: 122, dataplan_id: "122", network: 1, plan_type: "SME", plan_type1: "Datashare", plan_network: "MTN", month_validate: "30 Days", plan: "2GB", plan_amount: "1150.00" },
    { id: 123, dataplan_id: "123", network: 1, plan_type: "SME", plan_type1: "Datashare", plan_network: "MTN", month_validate: "30 Days", plan: "3GB", plan_amount: "1600.00" },
    { id: 124, dataplan_id: "124", network: 1, plan_type: "SME", plan_type1: "Datashare", plan_network: "MTN", month_validate: "30 Days", plan: "5GB", plan_amount: "2400.00" }
  ]
};

const GLO_PLAN = {
  ALL: [
    { id: 22, dataplan_id: "22", network: 3, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "GLO", month_validate: "30 Days", plan: "500MB", plan_amount: "225.00" },
    { id: 23, dataplan_id: "23", network: 3, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "GLO", month_validate: "30 Days", plan: "1GB", plan_amount: "450.00" },
    { id: 24, dataplan_id: "24", network: 3, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "GLO", month_validate: "30 Days", plan: "2GB", plan_amount: "900.00" },
    { id: 25, dataplan_id: "25", network: 3, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "GLO", month_validate: "30 Days", plan: "3GB", plan_amount: "1350.00" },
    { id: 26, dataplan_id: "26", network: 3, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "GLO", month_validate: "30 Days", plan: "5GB", plan_amount: "2250.00" },
    { id: 27, dataplan_id: "27", network: 3, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "GLO", month_validate: "30 Days", plan: "10GB", plan_amount: "4500.00" },
    { id: 158, dataplan_id: "158", network: 3, plan_type: "Cooperate", plan_type1: "Gifting_Plan", plan_network: "GLO", month_validate: "30 Days", plan: "7.5GB", plan_amount: "2600.00" }
  ]
};

const AIRTEL_PLAN = {
  ALL: [
    { id: 28, dataplan_id: "28", network: 2, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "AIRTEL", month_validate: "30 Days", plan: "500MB", plan_amount: "520.00" },
    { id: 29, dataplan_id: "29", network: 2, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "AIRTEL", month_validate: "30 Days", plan: "1GB", plan_amount: "822.00" },
    { id: 30, dataplan_id: "30", network: 2, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "AIRTEL", month_validate: "30 Days", plan: "2GB", plan_amount: "1557.00" },
    { id: 31, dataplan_id: "31", network: 2, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "AIRTEL", month_validate: "7 Days", plan: "100MB", plan_amount: "120.00" },
    { id: 32, dataplan_id: "32", network: 2, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "AIRTEL", month_validate: "30 Days", plan: "6GB", plan_amount: "3100.00" },
    { id: 111, dataplan_id: "111", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "2 Days", plan: "150MB", plan_amount: "80.00" },
    { id: 112, dataplan_id: "112", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "2 Days", plan: "300MB", plan_amount: "140.00" },
    { id: 113, dataplan_id: "113", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "1 Days", plan: "1GB", plan_amount: "400.00" },
    { id: 114, dataplan_id: "114", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "5 Days", plan: "2GB", plan_amount: "720.00" },
    { id: 116, dataplan_id: "116", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "7 Days", plan: "3GB", plan_amount: "1100.00" },
    { id: 117, dataplan_id: "117", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "7 Days", plan: "7GB", plan_amount: "2200.00" },
    { id: 118, dataplan_id: "118", network: 2, plan_type: "SME", plan_type1: "SME", plan_network: "AIRTEL", month_validate: "30 Days", plan: "10GB", plan_amount: "3400.00" }
  ]
};

const MOBILE9_PLAN = {
  ALL: [
    { id: 34, dataplan_id: "34", network: 4, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "9MOBILE", month_validate: "30 Days", plan: "500MB", plan_amount: "80.00" },
    { id: 35, dataplan_id: "35", network: 4, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "9MOBILE", month_validate: "30 Days", plan: "1GB", plan_amount: "149.00" },
    { id: 36, dataplan_id: "36", network: 4, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "9MOBILE", month_validate: "30 Days", plan: "2GB", plan_amount: "300.00" },
    { id: 37, dataplan_id: "37", network: 4, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "9MOBILE", month_validate: "30 Days", plan: "3GB", plan_amount: "450.00" },
    { id: 39, dataplan_id: "39", network: 4, plan_type: "Corporate", plan_type1: "Cooperate", plan_network: "9MOBILE", month_validate: "30 Days", plan: "10GB", plan_amount: "1400.00" }
  ]
};

const DATA_PLANS = {
  1: MTN_PLAN.ALL,
  2: AIRTEL_PLAN.ALL,
  3: GLO_PLAN.ALL,
  4: MOBILE9_PLAN.ALL
};













const activeFlows = new Map(); // In-memory store: userId => flow object

async function handleMenuChoice(text, from, userData) {
  const input = text.trim().toLowerCase();
  const userBalance = Number(userData?.balance || 0);

  // --- Catch greetings ---
  const greetings = ['hi', 'hello', 'hey', 'good morning', 'good afternoon', 'good evening'];
  if (greetings.includes(input)) {
    activeFlows.delete(from);
    return sendMainMenu(from, userData?.firstName || '');
  }

  // --- Get flow from memory ---
  let flow = activeFlows.get(from) || { step: undefined, attempts: 0 };

  const resetFlow = async (msg = '') => {
    activeFlows.delete(from);
    if (msg) await sendTextMessage(from, msg);
    await sendMainMenu(from, userData?.firstName || '');
  };

  try {
    // --- Validate input ---
    const expectedInput = {
      chooseNetwork: 'numeric',
      choosePlan: 'numeric',
      enterPhone: 'phone',
      enterAmount: 'numeric'
    };

    if (flow.step) {
      const type = expectedInput[flow.step];
      let valid = true;

      if (type === 'numeric') valid = /^\d+$/.test(input);
      if (type === 'phone') valid = /^\d{10,15}$/.test(input.replace(/\D/g, ''));

      if (!valid) {
        flow.attempts += 1;
        activeFlows.set(from, flow);

        if (flow.attempts >= 2) {
          return resetFlow("❌ Too many invalid attempts. Returning to main menu.");
        } else {
          return sendTextMessage(from, `❌ Invalid input. Please try again. (Attempt ${flow.attempts}/2)`);
        }
      }
    }

    flow.attempts = 0; // reset attempts on valid input

    // --- Step Handling ---
    switch (flow.step) {
      case undefined: // Main Menu
        switch (input) {
          case '1':
          case '2':
            flow = {
              step: 'chooseNetwork',
              type: input === '1' ? 'airtime' : 'data',
              attempts: 0
            };
            activeFlows.set(from, flow);
            return sendTextMessage(from, `Select network:\n1️⃣ MTN\n2️⃣ Glo\n3️⃣ Airtel\n4️⃣ 9Mobile`);

          case '3':
            return sendTextMessage(from, `Your balance: ₦${userBalance.toLocaleString()}`);

          case '4':
            if (userData?.bank) {
              return sendTextMessage(from,
                `🏦 Bank: ${userData.bank.name}\n💳 Account Name: ${userData.bank.accountName}\n🔢 Account Number: ${userData.bank.accountNumber}`
              );
            } else {
              return sendTextMessage(from, 'Bank details not available.');
            }

          default:
            return sendTextMessage(from, 'Invalid choice. Reply 1, 2, 3, or 4.');
        }

      case 'chooseNetwork':
        const network = parseInt(input, 10);
        flow.network = network;

        if (flow.type === 'airtime') {
          flow.step = 'enterPhone';
          activeFlows.set(from, flow);
          return sendTextMessage(from, 'Enter the phone number to top up:');
        } else {
          const plans = DATA_PLANS[network] || [];
          if (!plans.length) return resetFlow("No data plans found for this network.");

          let msg = 'Select a data plan:\n';
          plans.forEach((plan, idx) => {
            msg += `${idx + 1}. ${plan.plan} - ₦${plan.plan_amount} (${plan.month_validate})\n`;
          });

          flow.step = 'choosePlan';
          flow.plans = plans;
          activeFlows.set(from, flow);
          return sendTextMessage(from, msg);
        }

      case 'choosePlan':
        const planIndex = parseInt(input, 10) - 1;
        if (!flow.plans || planIndex < 0 || planIndex >= flow.plans.length) return resetFlow();
        const selectedPlan = flow.plans[planIndex];

        if (userBalance < Number(selectedPlan.plan_amount)) {
          await sendTextMessage(from,
            `❌ Insufficient balance. You need ₦${selectedPlan.plan_amount}, but your balance is ₦${userBalance}.`
          );
          return resetFlow();
        }

        flow.selectedPlan = selectedPlan;
        flow.step = 'enterPhone';
        activeFlows.set(from, flow);
        return sendTextMessage(from, `You selected ${selectedPlan.plan}. Enter the phone number to top up:`);

      case 'enterPhone':
        const phoneNumber = input.replace(/\D/g, '');
        if (flow.type === 'airtime') {
          flow.phone = phoneNumber;
          flow.step = 'enterAmount';
          activeFlows.set(from, flow);
          return sendTextMessage(from, 'Enter the amount to top up:');
        } else {
          const { selectedPlan, network } = flow;
          const token = crypto.randomBytes(16).toString('hex');
          const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000);

          await db.collection('pinTokens').doc(token).set({
            phone: from,
            network,
            topupPhone: phoneNumber,
            plan: selectedPlan,
            type: 'data',
            expiresAt
          });

          activeFlows.delete(from);

          return sendTextMessage(from,
            `To complete your data top-up of ${selectedPlan.plan} for ₦${selectedPlan.plan_amount}, verify your PIN here:\n` +
            `https://whatsapbot.vercel.app/verify-pin/${token}\n\nLink expires in 5 minutes.`
          );
        }

      case 'enterAmount':
        const amount = parseInt(input, 10);
        if (isNaN(amount) || amount <= 0 || userBalance < amount) {
          return resetFlow(`❌ Invalid amount or insufficient balance. Your balance is ₦${userBalance}.`);
        }

        const { network: airtimeNetwork, phone: topupPhone } = flow;
        const token = crypto.randomBytes(16).toString('hex');
        const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000);

        await db.collection('pinTokens').doc(token).set({
          phone: from,
          network: airtimeNetwork,
          topupPhone,
          amount,
          type: 'airtime',
          expiresAt
        });

        activeFlows.delete(from);

        return sendTextMessage(from,
          `To complete your top-up of ₦${amount}, please verify your PIN here:\n` +
          `https://whatsapbot.vercel.app/verify-pin/${token}\n\nLink expires in 5 minutes.`
        );

      default:
        return resetFlow();
    }

  } catch (e) {
    console.error('Menu handling error:', e);
    await resetFlow("⚠️ Something went wrong, returning to main menu.");
  }
}


// --- Helper to send main menu ---


// --- Main Menu Helper ---



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








const networkNames = { 1: 'MTN', 2: 'Glo', 3: '9Mobile', 4: 'Airtel' };

// Utility: Compare plain PIN with hashed PIN
function checkPin(pin, pinHash) {
  const hash = crypto.createHash('sha256').update(pin).digest('hex');
  return hash === pinHash;
}

// GET route: Show PIN entry page
app.get('/verify-pin/:token', async (req, res) => {
  try {
    const tokenRef = db.collection('pinTokens').doc(req.params.token);
    const tokenSnap = await tokenRef.get();

    if (!tokenSnap.exists) return res.send('Invalid or expired link.');

    const { expiresAt } = tokenSnap.data();
    if (expiresAt.toMillis() < Date.now()) {
      await tokenRef.delete();
      return res.send('Link expired. Please start the top-up process again.');
    }

    res.send(renderPinForm(req.params.token));
  } catch (err) {
    console.error('GET verify-pin error:', err);
    return res.send('An unexpected error occurred.');
  }
});

// POST route: Validate PIN and perform top-up
app.post('/verify-pin/:token', async (req, res) => {
  try {
    const tokenRef = db.collection('pinTokens').doc(req.params.token);
    const tokenSnap = await tokenRef.get();
    if (!tokenSnap.exists) return res.send('Invalid or expired link.');

    const tokenData = tokenSnap.data();
    const { phone, network, topupPhone, amount, plan, type, expiresAt } = tokenData;

    if (expiresAt.toMillis() < Date.now()) {
      await tokenRef.delete();
      return res.send('Link expired. Please start the top-up process again.');
    }

    const userRef = db.collection('users').doc(phone);
    const userSnap = await userRef.get();
    if (!userSnap.exists) return res.send('User not found.');

    const user = userSnap.data();
    const pin = (req.body.pin || '').trim();

    // Check PIN
    if (!checkPin(pin, user.pinHash)) {
      return res.send(renderPinForm(req.params.token, 'Incorrect PIN. Please try again.'));
    }

    // Determine API route and payload
    let apiUrl = '';
    let topupPayload = {};
    let topupAmount = 0;

    if (type === 'airtime') {
      topupAmount = Number(amount);
      apiUrl = 'https://vtunaija.com.ng/api/topup/';
      topupPayload = {
        network: network.toString(),
        mobile_number: topupPhone,
        Ported_number: "true",
        request_id: `${Date.now()}`,
        amount: amount.toString(),
        airtime_type: "VTU"
      };
    } else if (type === 'data') {
      topupAmount = Number(plan.plan_amount);
      apiUrl = 'https://vtunaija.com.ng/api/data/';
      topupPayload = {
        network: network.toString(),
        mobile_number: topupPhone,
        Ported_number: "true",
        request_id: `${Date.now()}`,
        plan: plan.dataplan_id
      };
    }

    // Check user balance before calling API
    if (user.balance < topupAmount) {
      return res.send(`❌ Insufficient balance. Your balance is ₦${user.balance}. You need ₦${topupAmount} to complete this top-up.`);
    }

    // Call VTU API
    let vtuResponse;
    try {
      vtuResponse = await axios.post(apiUrl, topupPayload, {
        headers: {
          Authorization: "Token zlantobi dd2d6983b3870e717bbbb7d006e7f996f1",
          "Content-Type": "application/json"
        }
      });
    } catch (err) {
      console.error('VTU Error:', err.response?.data || err.message);
      return res.send('Top-up failed due to network or API error.');
    }

    if (vtuResponse.data?.status === 'success') {
      // Deduct balance
      await userRef.update({ balance: admin.firestore.FieldValue.increment(-topupAmount) });
      if (type === 'airtime') {
        // Save receipt
        await userRef.collection('airtimeTransactions').add({
          type,
          network,
          networkName: networkNames[network],
          phone: topupPhone,
          amount: topupAmount,
          plan: type === 'data' ? plan.plan : null,
          transactionId: vtuResponse.data.id,
          timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

      } else if (type === 'data') {
        // Save receipt
        await userRef.collection('DataTransactions').add({
          type,
          network,
          networkName: networkNames[network],
          phone: topupPhone,
          amount: topupAmount,
          plan: type === 'data' ? plan.plan : null,
          transactionId: vtuResponse.data.id,
          timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
      }


      // Send WhatsApp confirmation
      await sendTextMessage(phone,
        `✅ ${type === 'airtime' ? 'Airtime' : 'Data'} top-up successful!\nNetwork: ${networkNames[network]}\nPhone: ${topupPhone}\nAmount: ₦${topupAmount}\nTransaction ID: ${vtuResponse.data.id}`
      );

      // Clean up token
      await tokenRef.delete();

      return res.send(renderSuccessPage(network, topupPhone, topupAmount, vtuResponse.data.id));
    } else {
      return res.send(`❌ Top-up failed: ${vtuResponse.data.api_response || 'Unknown error'}`);
    }

  } catch (err) {
    console.error('Verify PIN route error:', err);
    return res.send('An unexpected error occurred. Please try again.');
  }
});


// Helper: render PIN form with optional error message
function renderPinForm(token, errorMessage) {
  return `
    <html>
      <head>
        <title>Enter PIN - Zlt Topup</title>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <style>
          body { 
            font-family: system-ui, -apple-system, Segoe UI, sans-serif; 
            display:flex; justify-content:center; align-items:center; 
            height:100vh; margin:0; background:#f4f6f8; 
          }
          .card { 
            background:#fff; padding:32px; border-radius:16px; 
            box-shadow:0 8px 28px rgba(0,0,0,0.12); 
            max-width:400px; width:100%; text-align:center; 
          }
          .logo {
            width:120px; margin:0 auto 16px; display:block;
          }
          h2 { 
            color:#2c3e50; margin-bottom:12px;
          }
          input { 
            width:100%; padding:14px; font-size:18px; 
            border:2px solid #d0d7de; border-radius:10px; 
            margin:18px 0; text-align:center; 
            letter-spacing:0.4em; outline:none;
          }
          input:focus { border-color:#9b59b6; }
          button { 
            width:100%; padding:14px; font-size:16px; 
            border:0; border-radius:10px; 
            background:#9b59b6; color:#fff; 
            cursor:pointer; font-weight:600; 
            transition:background 0.2s ease;
          }
          button:hover { background:#884ea0; }
          .error { 
            color: #e74c3c; margin-bottom: 12px; font-weight: bold; 
          }
        </style>
      </head>
      <body>
        <div class="card">
          <img src="/static/logo.png" alt="Zlt Topup" class="logo" />
          <h2>Enter your 4-digit PIN</h2>
          ${errorMessage ? `<p class="error">${errorMessage}</p>` : ''}
          <form method="POST" action="/verify-pin/${token}">
            <input type="password" name="pin" maxlength="4" required />
            <button type="submit">Verify</button>
          </form>
        </div>
      </body>
    </html>
  `;
}

// Success Page with branding
function renderSuccessPage(network, topupPhone, amount, transactionId) {
  return `
    <html>
      <head>
        <title>Success - Zlt Topup</title>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <style>
          body { 
            font-family: system-ui, -apple-system, Segoe UI, sans-serif; 
            text-align:center; padding:48px; background:#f9fafb; 
          }
          .card {
            background:#fff; padding:32px; border-radius:16px; 
            box-shadow:0 8px 28px rgba(0,0,0,0.12);
            max-width:500px; margin:0 auto;
          }
          .logo {
            width:120px; margin:0 auto 20px; display:block;
          }
          h2 { color:#27ae60; margin-bottom:16px; }
          p { margin:8px 0; font-size:16px; }
          .note { color:#6b7280; margin-top:24px; font-size:14px; }
        </style>
      </head>
      <body>
        <div class="card">
          <img src="/static/logo.png" alt="Zlt Topup" class="logo" />
          <h2>✅ Top-up Successful!</h2>
          <p><strong>Amount:</strong> ₦${amount}</p>
          <p><strong>Network:</strong> ${networkNames[network]}</p>
          <p><strong>Phone:</strong> ${topupPhone}</p>
          <p><strong>Transaction ID:</strong> ${transactionId}</p>
          <p class="note">You can now return to WhatsApp.</p>
        </div>
      </body>
    </html>
  `;
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
        body { 
          font-family: system-ui, -apple-system, Segoe UI, sans-serif; 
          background: #f4f6f8; display:flex; align-items:center; 
          justify-content:center; height:100vh; margin:0; 
        }
        .card { 
          background:#fff; padding:32px; border-radius:16px; 
          box-shadow:0 8px 28px rgba(0,0,0,0.12); 
          width:100%; max-width:420px; text-align:center; 
        }
        .logo { 
          width:120px; margin:0 auto 20px; display:block; 
        }
        h2 { 
          color:#2c3e50; margin-bottom:16px; 
        }
        input { 
          width:100%; padding:14px; font-size:18px; 
          border:2px solid #d0d7de; border-radius:10px; 
          margin:18px 0; letter-spacing:0.4em; text-align:center; 
          outline:none;
        }
        input:focus { border-color:#9b59b6; }
        button { 
          width:100%; padding:14px; font-size:16px; 
          border:0; border-radius:10px; background:#9b59b6; 
          color:#fff; cursor:pointer; font-weight:600; 
          transition: background 0.2s ease; 
        }
        button:hover { background:#884ea0; }
        .muted { 
          color:#6b7280; font-size:14px; margin-top:12px; 
        }
      </style>
    </head>
    <body>
      <div class="card">
        <img src="/static/logo.png" alt="Zlt Topup" class="logo" />
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
    <head>
      <title>PIN Set - Zlt Topup</title>
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
        body { 
          font-family: system-ui, -apple-system, Segoe UI, sans-serif; 
          background:#f4f6f8; margin:0; padding:0; 
          display:flex; align-items:center; justify-content:center; 
          height:100vh; 
        }
        .card { 
          background:#fff; padding:32px; border-radius:16px; 
          box-shadow:0 8px 28px rgba(0,0,0,0.12); 
          width:100%; max-width:460px; text-align:center; 
        }
        .logo { 
          width:120px; margin:0 auto 20px; display:block; 
        }
        h2 { 
          color:#2c3e50; margin-bottom:16px; 
        }
        p { 
          font-size:16px; margin:8px 0; 
        }
        .muted { 
          color:#6b7280; font-size:14px; margin-top:20px; 
        }
      </style>
    </head>
    <body>
      <div class="card">
        <img src="/static/logo.png" alt="Zlt Topup" class="logo" />
        <h2>🎉 PIN Set Successfully!</h2>
        <p><strong>${firstName} ${lastName}</strong>, your account is ready.</p>
        <p>🏦 <strong>Bank:</strong> ${accountData.bank.name}</p>
        <p>💳 <strong>Account Name:</strong> ${accountData.account_name}</p>
        <p>🔢 <strong>Account Number:</strong> ${accountData.account_number}</p>
        <p class="muted">You can now return to WhatsApp and reply with 1, 2, 3 or 4 from the menu I sent.</p>
      </div>
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
      <title>Privacy Policy - Zlt Topup</title>
      <style>
        body {
          font-family: system-ui, -apple-system, Segoe UI, sans-serif;
          background: #f4f6f8;
          margin: 0; padding: 0;
          display: flex; justify-content: center; align-items: flex-start;
          min-height: 100vh;
        }
        .card {
          background: #fff;
          padding: 32px;
          margin: 40px 20px;
          border-radius: 16px;
          box-shadow: 0 8px 28px rgba(0,0,0,0.12);
          max-width: 720px;
          width: 100%;
        }
        .logo {
          width: 120px; display:block; margin:0 auto 20px;
        }
        h1, h2 {
          color: #0d6efd;
        }
        p {
          color: #333; line-height: 1.6;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <img src="/static/logo.png" alt="Zlt Topup" class="logo" />
        <h1>Privacy Policy</h1>
        <p>At <strong>Zlt Topup</strong>, we value your privacy. This Privacy Policy explains how we collect, use, and protect your personal information.</p>
        
        <h2>Information We Collect</h2>
        <p>We may collect your email, name, and payment details when you use our platform.</p>
        
        <h2>How We Use Information</h2>
        <p>Your information is used solely for account creation, service delivery, and transaction verification.</p>
        
        <h2>Security</h2>
        <p>We implement industry-standard security to protect your data against unauthorized access.</p>
        
        <h2>Contact Us</h2>
        <p>If you have any questions, contact us at 
          <a href="mailto:zlttopup@gmail.com">zlttopup@gmail.com</a>.
        </p>
      </div>
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
      <title>Data Deletion - Zlt Topup</title>
      <style>
        body {
          font-family: system-ui, -apple-system, Segoe UI, sans-serif;
          background: #f4f6f8;
          margin: 0; padding: 0;
          display: flex; justify-content: center; align-items: flex-start;
          min-height: 100vh;
        }
        .card {
          background: #fff;
          padding: 32px;
          margin: 40px 20px;
          border-radius: 16px;
          box-shadow: 0 8px 28px rgba(0,0,0,0.12);
          max-width: 720px;
          width: 100%;
        }
        .logo {
          width: 120px; display:block; margin:0 auto 20px;
        }
        h1, h2 {
          color: #6c63ff;
        }
        p {
          color: #333; line-height: 1.6;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <img src="/static/logo.png" alt="Zlt Topup" class="logo" />
        <h1>Data Deletion Instructions</h1>
        <p>At <strong>Zlt Topup</strong>, we respect your privacy and give you full control over your data.</p>
        
        <h2>How to Request Deletion</h2>
        <p>If you would like to delete your account and associated data, please send an email to 
        <a href="mailto:zlttopup@gmail.com">zlttopup@gmail.com</a> using your registered email address.</p>
        
        <p>Once we receive your request, we will verify your identity and process the deletion within <strong>7 business days</strong>.</p>
        
        <h2>Automatic Deletion</h2>
        <p>If you stop using our services for more than 12 months, we may automatically delete your data for security and compliance purposes.</p>
        
        <h2>Contact Us</h2>
        <p>For any questions about your data or this deletion process, please contact us at 
        <a href="mailto:zlttopup@gmail.com">zlttopup@gmail.com</a>.</p>
      </div>
    </body>
    </html>
  `);
});

/* ---------------- Server ---------------- */
app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
