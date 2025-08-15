import express from 'express';
import fetch from 'node-fetch';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';

// Firebase setup
admin.initializeApp({
    credential: admin.credential.cert("./serviceAccountKey.json")
});
const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const accessToken = process.env.ACCESS_TOKEN;
const phoneNumberId = process.env.phoneNumberId;
const verifyToken = process.env.verifyToken;

// 1️⃣ Send plain text
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

// 2️⃣ Send button message
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

// Webhook verification
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
    }
});

// Webhook POST
app.post('/webhook', async (req, res) => {
    const body = req.body;

    if (body.object && body.entry && body.entry[0].changes && body.entry[0].changes[0].value.messages) {
        const message = body.entry[0].changes[0].value.messages[0];
        const from = message.from;
        const text = message.text?.body?.trim() || '';

        const userRef = db.collection('users').doc(from);
        const userSnap = await userRef.get();

        if (userSnap.exists) {
            // User exists → welcome back
            const userData = userSnap.data();
            await sendTextMessage(from, `Welcome back, ${userData.firstName}! 🎉`);
        } else {
            const flowRef = db.collection('flows').doc(from);
            const flowSnap = await flowRef.get();
            const flowData = flowSnap.data();

            if (!flowSnap.exists) {
                // Step 1 → ask first name
                await sendTextMessage(from, 'Welcome to Zlt Topup! Please enter your FIRST NAME:');
                await flowRef.set({ step: 1 });
            } else if (flowData.step === 1) {
                await flowRef.update({ firstName: text, step: 2 });
                await sendTextMessage(from, 'Great! Now please enter your LAST NAME:');
            } else if (flowData.step === 2) {
                await flowRef.update({ lastName: text, step: 3 });
                await sendTextMessage(from, 'Almost done! Please enter your EMAIL:');
            } else if (flowData.step === 3) {
                const firstName = flowData.firstName;
                const lastName = flowData.lastName;
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

                const pinUrl = `https://silent-ideas-hide.loca.lt/set-pin/${pinToken}`;
                await sendTextMessage(from, `Almost done! Please set your PIN securely here: ${pinUrl} (expires in 5 minutes)`);

                await flowRef.update({ step: 4 });
            }
        }
    }

    res.sendStatus(200);
});

// PIN setup form
app.get('/set-pin/:token', async (req, res) => {
    const token = req.params.token;
    const tokenRef = db.collection('pinTokens').doc(token);
    const tokenSnap = await tokenRef.get();

    if (!tokenSnap.exists) return res.send('Invalid or expired token.');

    const tokenData = tokenSnap.data();
    const now = admin.firestore.Timestamp.now();

    if (tokenData.expiresAt.toMillis() < now.toMillis()) {
        await tokenRef.delete();
        return res.send('Token expired. Please restart the registration process.');
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

    if (!firstName || !lastName || !email) {
        return res.send('Error: Missing information. Please restart registration.');
    }

    // Save user
    await db.collection('users').doc(phone).set({
        firstName,
        lastName,
        phone,
        email,
        pin,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Cleanup
    await tokenRef.delete();
    await db.collection('flows').doc(phone).delete();

    try {
        // Create Paystack customer
        const customerResponse = await axios.post(
            "https://api.paystack.co/customer",
            { email, first_name: firstName, last_name: lastName, phone },
            {
                headers: {
                    Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                    "Content-Type": "application/json"
                }
            }
        );

        const customerCode = customerResponse.data.data.customer_code;

        // Create dedicated account
        const accountResponse = await axios.post(
            "https://api.paystack.co/dedicated_account",
            { customer: customerCode, preferred_bank: "wema-bank" },
            {
                headers: {
                    Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                    "Content-Type": "application/json"
                }
            }
        );

        const accountData = accountResponse.data.data;

        // WhatsApp message
        await sendTextMessage(phone,
            `🎉 ${firstName} ${lastName}, your account is ready!\n\n` +
            `🏦 Bank: ${accountData.bank.name}\n` +
            `💳 Account Name: ${accountData.account_name}\n` +
            `🔢 Account Number: ${accountData.account_number}\n\n` +
            `Keep your PIN safe and do not share it with anyone!`
        );

        res.json({
            status: true,
            message: "PIN set successfully! Account details sent via WhatsApp.",
            customer: customerResponse.data.data,
            dedicated_account: accountData
        });

    } catch (error) {
        if (error.response) {
            res.status(error.response.status).json(error.response.data);
        } else {
            res.status(500).json({ message: error.message });
        }
    }
});

// Start server
app.listen(3000, () => {
    console.log('🚀 Server running on port 3000');
});
