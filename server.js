const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration SaaSPay
const SAASPAY_SECRET_KEY = process.env.SAASPAY_SECRET_KEY;
const SAASPAY_WEBHOOK_SECRET = process.env.SAASPAY_WEBHOOK_SECRET;
const SAASPAY_API_BASE_URL = process.env.SAASPAY_API_BASE_URL || 'https://api.saspay.me/api/v1';
const missingSecrets = [
    ['SAASPAY_SECRET_KEY', SAASPAY_SECRET_KEY],
    ['SAASPAY_WEBHOOK_SECRET', SAASPAY_WEBHOOK_SECRET]
].filter(([, value]) => !value);

if (missingSecrets.length > 0) {
    console.error(`Configuration manquante : ${missingSecrets.map(([name]) => name).join(', ')}`);
    process.exit(1);
}

// Base de données locale sécurisée (persistée dans subscriptions.json pour standalone, ou branchable sur Firestore / Supabase)
const DB_FILE = process.env.SUBSCRIPTIONS_FILE || path.join(__dirname, 'subscriptions.json');

if (process.env.NODE_ENV === 'production' && !process.env.SUBSCRIPTIONS_FILE) {
    console.warn('SUBSCRIPTIONS_FILE n’est pas défini : les abonnements peuvent être perdus au redéploiement.');
}

function loadDatabase() {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ subscriptions: {} }, null, 2));
    }
    const data = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(data);
}

function saveDatabase(db) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    const temporaryFile = `${DB_FILE}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryFile, JSON.stringify(db, null, 2));
    fs.renameSync(temporaryFile, DB_FILE);
}

function hasValidWebhookSignature(signature, rawBody) {
    if (typeof signature !== 'string') return false;

    const suppliedDigest = signature.trim().replace(/^sha256=/i, '');
    if (!/^[a-f0-9]{64}$/i.test(suppliedDigest)) return false;

    const expectedDigest = crypto.createHmac('sha256', SAASPAY_WEBHOOK_SECRET)
        .update(rawBody)
        .digest();
    const receivedDigest = Buffer.from(suppliedDigest, 'hex');
    return crypto.timingSafeEqual(expectedDigest, receivedDigest);
}

// Middleware pour conserver le buffer brut (requis pour la vérification HMAC de la signature du webhook)
app.use((req, res, next) => {
    if (req.path === '/api/webhook/saaspay') {
        const startedAt = Date.now();
        console.info(`[HTTP] Webhook entrant ${req.method} ${req.path}`);
        res.on('finish', () => {
            console.info(`[HTTP] Webhook terminé ${req.method} ${req.path} ${res.statusCode} (${Date.now() - startedAt} ms)`);
        });
    }
    next();
});

app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));
app.use(cors());

// =========================================================================
// 1. ROUTE : CRÉATION D'UNE SESSION DE PAIEMENT SÉCURISÉE (CÔTÉ SERVEUR)
// =========================================================================
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { userId, tenantId, customerName, customerPhone, customerEmail, plan } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'userId est requis' });
        }

        const selectedPlan = plan || 'MONTHLY_5000';
        const planAmounts = { MONTHLY_5000: 5000, YEARLY_50000: 50000 };
        if (!Object.hasOwn(planAmounts, selectedPlan)) {
            return res.status(400).json({ error: 'Plan invalide' });
        }
        const amount = planAmounts[selectedPlan];
        const currency = 'XOF';
        const reference = `GESTIO_${userId}_${Date.now()}`;

        console.log(`[Checkout] Création session SaaSPay pour ${userId} - Montant: ${amount} ${currency}`);

        // Appel sécurisé à l'API SaaSPay avec la clé secrète (JAMAIS exposée au mobile)
        let checkoutUrl;
        let externalSessionId;

        try {
            const saaspayResponse = await axios.post(`${SAASPAY_API_BASE_URL.replace(/\/+$/, '')}/checkout-sessions/`, {
                amount: `${amount}.00`,
                currency: currency,
                description: `Abonnement Google AI Plus - ${selectedPlan}`,
                customer_phone: customerPhone || '',
                customer_email: customerEmail || `${userId}@gestio.app`,
                customer_name: customerName || 'Client GESTIO',
                metadata: {
                    user_id: userId,
                    tenant_id: tenantId || 'tenant_main',
                    plan: selectedPlan,
                    reference: reference
                },
                return_url: process.env.APP_SUCCESS_URL || 'https://gestio.app/success'
            }, {
                headers: {
                    'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            });

            if (saaspayResponse.data) {
                const sessionData = saaspayResponse.data.data ?? saaspayResponse.data;
                checkoutUrl = sessionData.checkout_url || sessionData.payment_url || sessionData.url;
                externalSessionId = sessionData.id;
            }
        } catch (apiError) {
            console.warn('[SaaSPay API Warning]', apiError.response ? apiError.response.data : apiError.message);
            return res.status(502).json({ error: 'La passerelle de paiement n’a pas pu créer la session.' });
        }

        let parsedCheckoutUrl;
        try {
            parsedCheckoutUrl = new URL(checkoutUrl);
        } catch (error) {
            return res.status(502).json({ error: 'La passerelle a renvoyé une URL de paiement invalide.' });
        }
        if (parsedCheckoutUrl.protocol !== 'https:' || !externalSessionId) {
            return res.status(502).json({ error: 'La passerelle a renvoyé une session de paiement incomplète.' });
        }

        // Enregistrement de l'état PENDING dans la base de données (l'utilisateur N'EST PAS activé)
        const db = loadDatabase();
        db.subscriptions[userId] = {
            userId: userId,
            tenantId: tenantId || 'tenant_main',
            status: 'PENDING_PAYMENT',
            plan: selectedPlan,
            amount: amount,
            currency: currency,
            reference: reference,
            sessionId: externalSessionId,
            createdAt: new Date().toISOString(),
            startDate: null,
            endDate: null,
            lastCheckedAt: new Date().toISOString()
        };
        saveDatabase(db);

        return res.json({
            success: true,
            checkoutUrl: checkoutUrl,
            sessionId: externalSessionId,
            reference: reference,
            amount: amount,
            currency: currency
        });

    } catch (err) {
        console.error('[Erreur Create Checkout Session]', err);
        return res.status(500).json({ error: 'Erreur serveur lors de la création de la session de paiement' });
    }
});

// =========================================================================
// 2. ROUTE : WEBHOOK SÉCURISÉ (NOTIFICATION SAASPAY -> VALIDATION BASE DE DONNÉES)
// =========================================================================
app.post('/api/webhook/saaspay', (req, res) => {
    try {
        const signature = req.headers['x-saaspay-signature'] || req.headers['x-signature'] || req.headers['stripe-signature'];

        if (!hasValidWebhookSignature(signature, req.rawBody)) {
            console.error('[Webhook] Signature HMAC SaaSPay absente ou invalide.');
            return res.status(401).json({ error: 'Signature absente ou invalide' });
        }

        const event = req.body;
        console.log(`[Webhook SaaSPay Reçu] Type: ${event.event || event.type || 'PAYMENT_EVENT'}`);

        const eventType = String(event.event || event.type || '').toLowerCase();
        const data = event.data || event;
        const metadata = data.metadata || {};
        const userId = metadata.user_id || data.user_id;

        if (!userId) {
            console.warn('[Webhook] Aucun userId identifié dans le payload SaaSPay');
            return res.status(400).json({ error: 'userId introuvable dans la notification' });
        }

        const db = loadDatabase();
        const currentSub = db.subscriptions[userId];
        if (!currentSub || currentSub.status !== 'PENDING_PAYMENT') {
            if (currentSub && currentSub.status === 'ACTIVE') {
                return res.json({ received: true, duplicate: true });
            }
            return res.status(409).json({ error: 'Aucune session de paiement en attente pour cet utilisateur' });
        }

        if (data.reference && data.reference !== currentSub.reference) {
            return res.status(409).json({ error: 'Référence de paiement inattendue' });
        }
        if (data.amount !== undefined && Number(data.amount) !== currentSub.amount) {
            return res.status(409).json({ error: 'Montant de paiement inattendu' });
        }
        if (data.currency && data.currency.toUpperCase() !== currentSub.currency) {
            return res.status(409).json({ error: 'Devise de paiement inattendue' });
        }

        // Traitement strict du statut de paiement
        const paymentStatus = String(data.status || '').toLowerCase();
        const isSuccess = ['payment.success', 'payment.paid', 'payment.completed', 'charge.completed', 'transaction.paid'].includes(eventType) ||
                  ['success', 'paid', 'completed', 'succeeded'].includes(paymentStatus);

        if (isSuccess) {
            const startDate = new Date();
            const durationDays = (currentSub.plan === 'YEARLY_50000') ? 365 : 30;
            const endDate = new Date(startDate.getTime() + durationDays * 24 * 60 * 60 * 1000);

            // MISE À JOUR OFFICIELLE DANS LA BASE DE DONNÉES
            db.subscriptions[userId] = {
                ...currentSub,
                status: 'ACTIVE',
                startDate: startDate.toISOString(),
                endDate: endDate.toISOString(),
                transactionId: data.id || data.transaction_id || data.reference,
                lastPaymentAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            saveDatabase(db);
            console.log(`[Webhook] ✓ Utilisateur ${userId} activé avec succès jusqu'au ${endDate.toISOString()}`);
        } else if (['payment.failed', 'charge.failed', 'transaction.failed'].includes(eventType) || paymentStatus === 'failed') {
            db.subscriptions[userId] = {
                ...currentSub,
                status: 'PAYMENT_FAILED',
                updatedAt: new Date().toISOString()
            };
            saveDatabase(db);
            console.log(`[Webhook] ✗ Échec de paiement pour ${userId}`);
        } else if (['payment.canceled', 'payment.cancelled', 'subscription.canceled', 'subscription.cancelled'].includes(eventType) ||
               ['canceled', 'cancelled'].includes(paymentStatus)) {
            db.subscriptions[userId] = {
                ...currentSub,
                status: 'CANCELED',
                updatedAt: new Date().toISOString()
            };
            saveDatabase(db);
            console.log(`[Webhook] ! Abonnement annulé pour ${userId}`);
        }

        return res.json({ received: true });
    } catch (err) {
        console.error('[Erreur Webhook SaaSPay]', err);
        return res.status(500).json({ error: 'Erreur interne traitement webhook' });
    }
});

// =========================================================================
// 3. ROUTE : LECTURE DU STATUT DEPUIS LA BASE DE DONNÉES (LECTURE SEULE POUR LE CLIENT)
// =========================================================================
app.get('/api/subscription-status/:userId', (req, res) => {
    try {
        const { userId } = req.params;
        const db = loadDatabase();
        const sub = db.subscriptions[userId];

        if (!sub) {
            return res.json({
                status: 'INACTIVE',
                isSubscribed: false,
                plan: null,
                endDate: null,
                message: 'Aucun abonnement trouvé pour cet utilisateur'
            });
        }

        // Vérification de l'expiration temporelle
        let isExpired = false;
        if (sub.endDate) {
            const end = new Date(sub.endDate);
            if (new Date() > end) {
                isExpired = true;
            }
        }

        const isActive = (sub.status === 'ACTIVE' && !isExpired);

        return res.json({
            userId: sub.userId,
            status: isExpired ? 'EXPIRED' : sub.status,
            isSubscribed: isActive,
            plan: sub.plan,
            startDate: sub.startDate,
            endDate: sub.endDate,
            transactionId: sub.transactionId || null,
            message: isActive ? 'Abonnement actif et confirmé' : (isExpired ? 'Abonnement expiré' : 'Paiement non confirmé')
        });

    } catch (err) {
        console.error('[Erreur Get Subscription Status]', err);
        return res.status(500).json({ error: 'Erreur lecture statut' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'gestio-saaspay-backend', time: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`[GESTIO Backend] Serveur SaaSPay & Webhook opérationnel sur le port ${PORT}`);
    console.log(`[Webhook URL] POST http://localhost:${PORT}/api/webhook/saaspay`);
});
