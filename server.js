const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration SasPay & Firebase
const SAASPAY_SECRET_KEY = process.env.SAASPAY_SECRET_KEY;
const SAASPAY_WEBHOOK_SECRET = process.env.SAASPAY_WEBHOOK_SECRET;
const SAASPAY_API_BASE_URL = (process.env.SAASPAY_API_BASE_URL || 'https://api.saspay.me/api/v1').replace(/\/+$/, '');
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'gen-lang-client-0469449992';

if (SAASPAY_API_BASE_URL !== 'https://api.saspay.me/api/v1') {
    console.warn(`[Config Warning] SAASPAY_API_BASE_URL vaut "${SAASPAY_API_BASE_URL}" au lieu de "https://api.saspay.me/api/v1".`);
}

const missingSecrets = [
    ['SAASPAY_SECRET_KEY', SAASPAY_SECRET_KEY],
    ['SAASPAY_WEBHOOK_SECRET', SAASPAY_WEBHOOK_SECRET]
].filter(([, value]) => !value);

if (missingSecrets.length > 0) {
    console.error(`Configuration manquante : ${missingSecrets.map(([name]) => name).join(', ')}`);
    process.exit(1);
}

if (SAASPAY_SECRET_KEY.startsWith('sk_test_')) {
    console.info('[SasPay] Mode TEST détecté (clé sk_test_).');
}

const SUBSCRIPTION_AMOUNT_NUM = 5000;
const SUBSCRIPTION_AMOUNT_STR = '5000.00';
const SUBSCRIPTION_CURRENCY = 'XOF';
const PAYMENT_OPTIONS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const WEBHOOK_MAX_AGE_SECONDS = 300; // 5 minutes

// Base de données JSON persistante (abonnements + paiements suivis par paymentId)
const DB_FILE = process.env.SUBSCRIPTIONS_FILE || path.join(__dirname, 'subscriptions.json');

if (process.env.NODE_ENV === 'production' && !process.env.SUBSCRIPTIONS_FILE) {
    console.warn('SUBSCRIPTIONS_FILE n’est pas défini : les abonnements peuvent être perdus au redéploiement.');
}

function loadDatabase() {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ subscriptions: {}, payments: {} }, null, 2));
    }
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    if (!parsed.subscriptions) parsed.subscriptions = {};
    if (!parsed.payments) parsed.payments = {};
    return parsed;
}

function saveDatabase(db) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    const temporaryFile = `${DB_FILE}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryFile, JSON.stringify(db, null, 2));
    fs.renameSync(temporaryFile, DB_FILE);
}

// =========================================================================
// VÉRIFICATION CRYPTOGRAPHIQUE DES JETONS FIREBASE AUTH (RS256)
// =========================================================================
let cachedGoogleCerts = { certs: null, expiresAt: 0 };

async function getGooglePublicCerts() {
    const now = Date.now();
    if (cachedGoogleCerts.certs && now < cachedGoogleCerts.expiresAt) {
        return cachedGoogleCerts.certs;
    }
    const resp = await axios.get(
        'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
        { timeout: 8000 }
    );
    const cacheControl = String(resp.headers['cache-control'] || '');
    const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
    const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : 3600;
    cachedGoogleCerts = {
        certs: resp.data,
        expiresAt: now + maxAgeSec * 1000,
    };
    return cachedGoogleCerts.certs;
}

function base64UrlDecode(str) {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
    return Buffer.from(padded, 'base64');
}

async function verifyFirebaseIdToken(idToken) {
    if (!idToken || typeof idToken !== 'string') {
        throw new Error('Jeton Firebase manquant');
    }
    const parts = idToken.split('.');
    if (parts.length !== 3) {
        throw new Error('Format de jeton Firebase invalide');
    }
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));

    if (header.alg !== 'RS256' || !header.kid) {
        throw new Error('Algorithme ou identifiant de clé invalide');
    }

    const certs = await getGooglePublicCerts();
    const cert = certs[header.kid];
    if (!cert) {
        throw new Error('Clé de signature Firebase introuvable');
    }

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();

    const signatureBuf = base64UrlDecode(signatureB64);
    if (!verifier.verify(cert, signatureBuf)) {
        throw new Error('Signature du jeton Firebase invalide');
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp <= nowSec) {
        throw new Error('Jeton Firebase expiré');
    }
    if (!payload.iat || payload.iat > nowSec + 300) {
        throw new Error('Horodatage du jeton invalide');
    }
    if (payload.aud !== FIREBASE_PROJECT_ID) {
        throw new Error('Projet Firebase non autorisé');
    }
    if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) {
        throw new Error('Émetteur du jeton invalide');
    }
    const uid = payload.sub || payload.user_id;
    if (!uid || typeof uid !== 'string') {
        throw new Error('Identifiant utilisateur introuvable dans le jeton');
    }

    return {
        uid,
        email: payload.email || '',
        name: payload.name || '',
    };
}

async function requireFirebaseAuth(req, res, next) {
    try {
        const authHeader = req.get('authorization') || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) {
            return res.status(401).json({ error: 'Authentification requise' });
        }
        req.firebaseUser = await verifyFirebaseIdToken(token);
        next();
    } catch (err) {
        console.warn('[Auth Firebase]', err.message);
        return res.status(401).json({ error: 'Session expirée ou invalide. Veuillez vous reconnecter.' });
    }
}

// =========================================================================
// MÉTADONNÉES PAYS & CACHE DES OPTIONS DE PAIEMENT SASPAY
// =========================================================================
const COUNTRY_META = {
    CI: { name: "Côte d'Ivoire", dialCode: '+225', minLen: 10, maxLen: 10, placeholder: '0701020304' },
    SN: { name: 'Sénégal', dialCode: '+221', minLen: 9, maxLen: 9, placeholder: '771234567' },
    BJ: { name: 'Bénin', dialCode: '+229', minLen: 8, maxLen: 10, placeholder: '97000000' },
    TG: { name: 'Togo', dialCode: '+228', minLen: 8, maxLen: 8, placeholder: '90000000' },
    BF: { name: 'Burkina Faso', dialCode: '+226', minLen: 8, maxLen: 8, placeholder: '70000000' },
    ML: { name: 'Mali', dialCode: '+223', minLen: 8, maxLen: 8, placeholder: '70000000' },
    NE: { name: 'Niger', dialCode: '+227', minLen: 8, maxLen: 8, placeholder: '90000000' },
    GW: { name: 'Guinée-Bissau', dialCode: '+245', minLen: 7, maxLen: 9, placeholder: '955000000' },
    GN: { name: 'Guinée', dialCode: '+224', minLen: 9, maxLen: 9, placeholder: '620000000' },
    CM: { name: 'Cameroun', dialCode: '+237', minLen: 9, maxLen: 9, placeholder: '670000000' },
    GA: { name: 'Gabon', dialCode: '+241', minLen: 7, maxLen: 9, placeholder: '06000000' },
    CG: { name: 'Congo-Brazzaville', dialCode: '+242', minLen: 9, maxLen: 9, placeholder: '060000000' },
    CD: { name: 'RD Congo', dialCode: '+243', minLen: 9, maxLen: 10, placeholder: '810000000' },
    TD: { name: 'Tchad', dialCode: '+235', minLen: 8, maxLen: 8, placeholder: '66000000' },
    CF: { name: 'Centrafrique', dialCode: '+236', minLen: 8, maxLen: 8, placeholder: '75000000' },
    GQ: { name: 'Guinée équatoriale', dialCode: '+240', minLen: 9, maxLen: 9, placeholder: '222000000' },
    GH: { name: 'Ghana', dialCode: '+233', minLen: 9, maxLen: 10, placeholder: '240000000' },
    NG: { name: 'Nigéria', dialCode: '+234', minLen: 10, maxLen: 11, placeholder: '8000000000' },
    KE: { name: 'Kenya', dialCode: '+254', minLen: 9, maxLen: 10, placeholder: '712345678' },
    UG: { name: 'Ouganda', dialCode: '+256', minLen: 9, maxLen: 9, placeholder: '770000000' },
    RW: { name: 'Rwanda', dialCode: '+250', minLen: 9, maxLen: 9, placeholder: '780000000' },
    TZ: { name: 'Tanzanie', dialCode: '+255', minLen: 9, maxLen: 9, placeholder: '710000000' },
    MW: { name: 'Malawi', dialCode: '+265', minLen: 9, maxLen: 9, placeholder: '991234567' },
    MZ: { name: 'Mozambique', dialCode: '+258', minLen: 9, maxLen: 9, placeholder: '821234567' },
    ZM: { name: 'Zambie', dialCode: '+260', minLen: 9, maxLen: 9, placeholder: '971234567' },
    SL: { name: 'Sierra Leone', dialCode: '+232', minLen: 8, maxLen: 8, placeholder: '76123456' },
    ZA: { name: 'Afrique du Sud', dialCode: '+27', minLen: 9, maxLen: 10, placeholder: '820000000' },
    MA: { name: 'Maroc', dialCode: '+212', minLen: 9, maxLen: 9, placeholder: '600000000' },
    TN: { name: 'Tunisie', dialCode: '+216', minLen: 8, maxLen: 8, placeholder: '20000000' },
    DZ: { name: 'Algérie', dialCode: '+213', minLen: 9, maxLen: 9, placeholder: '550000000' },
    EG: { name: 'Égypte', dialCode: '+20', minLen: 10, maxLen: 10, placeholder: '1000000000' },
    MG: { name: 'Madagascar', dialCode: '+261', minLen: 9, maxLen: 10, placeholder: '320000000' },
    MU: { name: 'Maurice', dialCode: '+230', minLen: 8, maxLen: 8, placeholder: '52500000' },
    FR: { name: 'France', dialCode: '+33', minLen: 9, maxLen: 10, placeholder: '612345678' },
    BE: { name: 'Belgique', dialCode: '+32', minLen: 8, maxLen: 10, placeholder: '470000000' },
    CH: { name: 'Suisse', dialCode: '+41', minLen: 9, maxLen: 9, placeholder: '790000000' },
    GB: { name: 'Royaume-Uni', dialCode: '+44', minLen: 10, maxLen: 10, placeholder: '7123456789' },
    DE: { name: 'Allemagne', dialCode: '+49', minLen: 10, maxLen: 11, placeholder: '15123456789' },
    ES: { name: 'Espagne', dialCode: '+34', minLen: 9, maxLen: 9, placeholder: '612345678' },
    IT: { name: 'Italie', dialCode: '+39', minLen: 9, maxLen: 10, placeholder: '3123456789' },
    CA: { name: 'Canada', dialCode: '+1', minLen: 10, maxLen: 10, placeholder: '5140000000' },
    US: { name: 'États-Unis', dialCode: '+1', minLen: 10, maxLen: 10, placeholder: '4150000000' },
    AE: { name: 'Émirats Arabes Unis', dialCode: '+971', minLen: 9, maxLen: 9, placeholder: '501234567' },
};

const SKIPPED_PSEUDO_COUNTRIES = new Set(['XX', 'XY', 'XC']);
const UNCOVERED_CARD_COUNTRIES = ['MA', 'TN', 'DZ', 'FR', 'BE', 'CH', 'CA', 'US', 'GB'];

function countryCodeToFlag(code) {
    const clean = String(code || '').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(clean)) return '🌍';
    return String.fromCodePoint(...[...clean].map((c) => 127397 + c.charCodeAt(0)));
}

function isEntryActive(item) {
    if (!item || typeof item !== 'object') return false;
    if (item.is_active === false || item.active === false || item.enabled === false) return false;
    if (typeof item.status === 'string' && ['inactive', 'disabled', 'suspended'].includes(item.status.toLowerCase())) {
        return false;
    }
    return true;
}

function detectPreOtpRequired(item, countryCode, netCode) {
    if (item.payin?.otp_required === true || item.otp_required === true || item.requires_pre_otp === true || item.prepayment_otp === true) {
        return true;
    }
    const n = String(netCode || '').toLowerCase();
    const c = String(countryCode || '').toUpperCase();
    return (c === 'CI' || c === 'BF') && (n.includes('orange') || n.startsWith('om_'));
}

function detectPostOtpRequired(item, countryCode, netCode) {
    if (item.payin?.confirm_otp_required === true || item.confirm_otp_required === true || item.post_otp_required === true) {
        return true;
    }
    const n = String(netCode || '').toLowerCase();
    const c = String(countryCode || '').toUpperCase();
    return (c === 'SN' && n.includes('wizall')) || (c === 'BJ' && n.includes('coris'));
}

function formatOtpInstructions(rawInstr) {
    if (!rawInstr || typeof rawInstr !== 'string') return null;
    const cleaned = rawInstr.replace(/\{amount\}/gi, String(SUBSCRIPTION_AMOUNT_NUM)).trim();
    return cleaned || null;
}

let paymentOptionsCache = { data: null, rates: [], expiresAt: 0 };
const exchangeRateCache = new Map();
const EXCHANGE_RATE_CACHE_TTL_MS = 15 * 60 * 1000;

function extractSasPayErrorMessage(errBody, fallback = 'Impossible de lancer le paiement pour le moment.') {
    if (!errBody) return fallback;
    if (typeof errBody === 'string') return errBody;
    if (typeof errBody.message === 'string' && errBody.message.trim()) return errBody.message.trim();
    if (typeof errBody.detail === 'string' && errBody.detail.trim()) return errBody.detail.trim();
    if (typeof errBody.error === 'string' && errBody.error.trim()) return errBody.error.trim();
    const source = errBody.error && typeof errBody.error === 'object' ? errBody.error : errBody;
    const messages = [];
    const walk = (val) => {
        if (typeof val === 'string' && val.trim()) {
            messages.push(val.trim());
        } else if (Array.isArray(val)) {
            val.forEach(walk);
        } else if (val && typeof val === 'object') {
            Object.values(val).forEach(walk);
        }
    };
    walk(source);
    return messages.length > 0 ? messages.join(' ') : fallback;
}

function resolveAbsoluteReturnUrl(req) {
    const candidates = [
        req.body?.returnUrl,
        req.body?.return_url,
        process.env.APP_SUCCESS_URL,
        req.get('origin') ? `${req.get('origin').replace(/\/+$/, '')}/?payment=return` : '',
        process.env.APP_URL ? `${process.env.APP_URL.replace(/\/+$/, '')}/?payment=return` : '',
        'https://gestio.app/?payment=return',
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && /^https?:\/\/.+/i.test(candidate.trim())) {
            return candidate.trim();
        }
    }
    return 'https://gestio.app/?payment=return';
}

async function getExchangeRateToXof(fromCurrency) {
    const upper = String(fromCurrency || 'XOF').trim().toUpperCase();
    if (!upper || upper === 'XOF') return 1;

    const now = Date.now();
    const cached = exchangeRateCache.get(upper);
    if (cached && now < cached.expiresAt) {
        return cached.rate;
    }

    try {
        const resp = await axios.get(`${SAASPAY_API_BASE_URL}/exchange-rates/`, {
            params: { from_currency: upper, to_currency: 'XOF' },
            headers: {
                'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
                'Accept': 'application/json',
            },
            timeout: 8000,
        });
        const results = resp.data?.data?.results || resp.data?.results || resp.data?.data || [];
        const match = Array.isArray(results)
            ? results.find((r) => String(r.from_currency || '').toUpperCase() === upper && String(r.to_currency || '').toUpperCase() === 'XOF') || results[0]
            : null;
        const rate = Number(match?.rate);
        if (Number.isFinite(rate) && rate > 0) {
            exchangeRateCache.set(upper, { rate, expiresAt: now + EXCHANGE_RATE_CACHE_TTL_MS });
            return rate;
        }
    } catch (err) {
        console.warn(`[SasPay FX] Conversion ${upper}->XOF indisponible:`, err.message);
    }
    return cached?.rate || 1;
}

async function calculateDynamicFeeFor5000(rateItems, countryCode, networkCode) {
    const netLower = String(networkCode || '').trim().toLowerCase();
    const cUpper = String(countryCode || '').trim().toUpperCase();
    const items = Array.isArray(rateItems) ? rateItems : [];

    let rateEntry = null;
    if (netLower === 'card') {
        rateEntry = items.find((item) => String(item?.network_code || item?.network || '').trim().toLowerCase() === 'card') || null;
    } else {
        rateEntry =
            items.find(
                (item) =>
                    String(item?.country_code || item?.country || '').trim().toUpperCase() === cUpper &&
                    String(item?.network_code || item?.network || '').trim().toLowerCase() === netLower
            ) ||
            items.find((item) => String(item?.network_code || item?.network || '').trim().toLowerCase() === netLower) ||
            null;
    }

    const tiers = Array.isArray(rateEntry?.payin?.tiers) ? rateEntry.payin.tiers : [];
    if (tiers.length === 0) {
        return {
            feeAmount: 0,
            subscriptionAmount: SUBSCRIPTION_AMOUNT_NUM,
            percent: 0,
            fixed: 0,
            tierCurrency: SUBSCRIPTION_CURRENCY,
        };
    }

    // Choisir le palier correspondant au montant client (5 000 FCFA convertis dans la devise du palier si besoin)
    let chosenTier = tiers[0];
    for (const tier of tiers) {
        const tierCur = String(tier?.currency || rateEntry?.currency || 'XOF').trim().toUpperCase();
        const fx = tierCur !== 'XOF' ? await getExchangeRateToXof(tierCur) : 1;
        const amountInTierCur = fx > 0 ? SUBSCRIPTION_AMOUNT_NUM / fx : SUBSCRIPTION_AMOUNT_NUM;
        const minA = tier?.min_amount !== null && tier?.min_amount !== undefined ? Number(tier.min_amount) : 0;
        const maxA = tier?.max_amount !== null && tier?.max_amount !== undefined ? Number(tier.max_amount) : Infinity;
        if (amountInTierCur >= minA && amountInTierCur <= maxA) {
            chosenTier = tier;
            break;
        }
    }

    const tierCurrency = String(chosenTier?.currency || rateEntry?.currency || 'XOF').trim().toUpperCase();
    const tierFeeMode = String(chosenTier?.fee_charge_mode || 'ADD_ON').trim().toUpperCase() === 'DEDUCTED' ? 'DEDUCTED' : 'ADD_ON';
    const fxToXof = tierCurrency !== 'XOF' ? await getExchangeRateToXof(tierCurrency) : 1;

    const percent = Number(chosenTier?.percent || 0);
    const fixedRaw = Number(chosenTier?.fixed || 0);
    const fixedXof = fixedRaw * fxToXof;
    const minFeeXof = Number(chosenTier?.min_fee || 0) * fxToXof;
    const floorXof = chosenTier?.floor_amount != null ? Number(chosenTier.floor_amount) * fxToXof : 0;
    const capXof = chosenTier?.cap_amount != null ? Number(chosenTier.cap_amount) * fxToXof : 0;

    // SasPay arrondit les frais XOF au franc supérieur (Math.ceil)
    const computeCeilFeeXof = (baseAmt) => {
        let f = (baseAmt * percent) / 100 + fixedXof;
        if (minFeeXof > 0 && f < minFeeXof) f = minFeeXof;
        if (floorXof > 0 && f < floorXof) f = floorXof;
        if (capXof > 0 && f > capXof) f = capXof;
        return Math.max(0, Math.ceil(f));
    };

    if (tierFeeMode === 'DEDUCTED') {
        const feeAmount = computeCeilFeeXof(SUBSCRIPTION_AMOUNT_NUM);
        const subscriptionAmount = Math.max(0, SUBSCRIPTION_AMOUNT_NUM - feeAmount);
        return {
            amountToSend: SUBSCRIPTION_AMOUNT_NUM,
            feeChargeMode: 'DEDUCTED',
            feeAmount,
            subscriptionAmount,
            percent,
            fixed: fixedRaw,
            tierCurrency,
        };
    }

    // Mode ADD_ON : SasPay ajoute les frais au montant envoyé (total client = amountToSend + fee(amountToSend))
    // On résout dynamiquement amountToSend pour que le client confirme exactement 5 000 FCFA
    const approxGuess = Math.round((SUBSCRIPTION_AMOUNT_NUM - fixedXof) / (1 + percent / 100));
    let bestAmount = Math.max(1, Math.min(SUBSCRIPTION_AMOUNT_NUM, approxGuess));
    let bestDiff = Infinity;
    for (let candidate = Math.max(1, approxGuess - 10); candidate <= Math.min(SUBSCRIPTION_AMOUNT_NUM, approxGuess + 10); candidate++) {
        const total = candidate + computeCeilFeeXof(candidate);
        const diff = Math.abs(SUBSCRIPTION_AMOUNT_NUM - total);
        if (diff < bestDiff || (diff === bestDiff && total === SUBSCRIPTION_AMOUNT_NUM)) {
            bestDiff = diff;
            bestAmount = candidate;
        }
    }

    const feeAmount = computeCeilFeeXof(bestAmount);
    return {
        amountToSend: bestAmount,
        feeChargeMode: 'ADD_ON',
        feeAmount,
        subscriptionAmount: bestAmount,
        percent,
        fixed: fixedRaw,
        tierCurrency,
    };
}

function buildPaymentOptionsFromSasPay(ratesPayload, countriesPayload) {
    const rateItems = Array.isArray(ratesPayload)
        ? ratesPayload
        : Array.isArray(ratesPayload?.data)
        ? ratesPayload.data
        : Array.isArray(ratesPayload?.rates)
        ? ratesPayload.rates
        : [];

    const countryItems = Array.isArray(countriesPayload)
        ? countriesPayload
        : Array.isArray(countriesPayload?.data)
        ? countriesPayload.data
        : Array.isArray(countriesPayload?.countries)
        ? countriesPayload.countries
        : [];

    const cardRateEntry = rateItems.find(
        (item) => String(item?.network_code || item?.network || '').trim().toLowerCase() === 'card'
    );
    const isCardAvailable = !cardRateEntry || (isEntryActive(cardRateEntry) && cardRateEntry.payin?.available !== false);

    const byCountry = new Map();

    const ensureCountry = (code, rawCountryObj = {}) => {
        const upper = String(code || '').trim().toUpperCase();
        if (!/^[A-Z]{2}$/.test(upper) || SKIPPED_PSEUDO_COUNTRIES.has(upper)) return null;
        if (!byCountry.has(upper)) {
            const meta = COUNTRY_META[upper] || {};
            byCountry.set(upper, {
                code: upper,
                name: meta.name || rawCountryObj.country_name || rawCountryObj.name || upper,
                dialCode: rawCountryObj.dial_code || rawCountryObj.calling_code || meta.dialCode || '+',
                flag: countryCodeToFlag(upper),
                minPhoneLength: meta.minLen || 7,
                maxPhoneLength: meta.maxLen || 12,
                phonePlaceholder: meta.placeholder || '00000000',
                networks: [],
            });
        }
        return byCountry.get(upper);
    };

    // 1. Parse active payin mobile money networks from /pricing/my-rates/
    for (const item of rateItems) {
        if (!isEntryActive(item)) continue;
        if (item.payin && item.payin.available === false) continue;

        const cCode = item.country_code || item.country;
        const netCode = item.network_code || item.network || item.channel;
        if (!cCode || !netCode) continue;

        const countryEntry = ensureCountry(cCode, item);
        if (!countryEntry) continue;

        const netName = item.network_name || item.provider_name || item.name || String(netCode);
        const isCard = String(netCode).toLowerCase() === 'card';
        const rawInstr = item.payin?.otp_instructions || item.otp_instructions || '';

        if (!countryEntry.networks.some((n) => n.code === String(netCode))) {
            countryEntry.networks.push({
                code: String(netCode),
                name: isCard ? 'Carte bancaire' : String(netName),
                type: isCard ? 'card' : 'mobile_money',
                otpRequired: detectPreOtpRequired(item, countryEntry.code, netCode),
                postOtpRequired: detectPostOtpRequired(item, countryEntry.code, netCode),
                otpInstructions: formatOtpInstructions(rawInstr),
            });
        }
    }

    // 2. Add active countries from /countries/ that have dial codes or are uncovered
    for (const cItem of countryItems) {
        if (!isEntryActive(cItem)) continue;
        const cCode = String(cItem.iso_code || cItem.code || '').trim().toUpperCase();
        if (!cCode || SKIPPED_PSEUDO_COUNTRIES.has(cCode)) continue;
        if (!byCountry.has(cCode) && COUNTRY_META[cCode]) {
            ensureCountry(cCode, cItem);
        }
    }

    for (const code of UNCOVERED_CARD_COUNTRIES) {
        if (!byCountry.has(code) && COUNTRY_META[code]) {
            ensureCountry(code, COUNTRY_META[code]);
        }
    }

    // 3. Ajouter également "Carte bancaire" (réseau card) à chaque pays si actif dans SasPay
    if (isCardAvailable) {
        for (const country of byCountry.values()) {
            if (!country.networks.some((n) => n.code === 'card')) {
                country.networks.push({
                    code: 'card',
                    name: 'Carte bancaire',
                    type: 'card',
                    otpRequired: false,
                    postOtpRequired: false,
                    otpInstructions: null,
                });
            }
        }
    }

    const countries = Array.from(byCountry.values()).sort((a, b) => a.name.localeCompare(b.name, 'fr'));
    countries.push({
        code: 'OTHER',
        name: 'Autre pays',
        dialCode: '+',
        flag: '🌍',
        minPhoneLength: 6,
        maxPhoneLength: 15,
        phonePlaceholder: 'Numéro international',
        networks: [
            {
                code: 'card',
                name: 'Carte bancaire',
                type: 'card',
                otpRequired: false,
                postOtpRequired: false,
                otpInstructions: null,
            },
        ],
    });

    return { countries, rateItems };
}

async function fetchPaymentOptionsWithRates(forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh && paymentOptionsCache.data && now < paymentOptionsCache.expiresAt) {
        return { countries: paymentOptionsCache.data, rateItems: paymentOptionsCache.rates };
    }

    const headers = {
        'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
        'Accept': 'application/json',
    };

    try {
        const [ratesRes, countriesRes] = await Promise.allSettled([
            axios.get(`${SAASPAY_API_BASE_URL}/pricing/my-rates/`, { headers, timeout: 10000 }),
            axios.get(`${SAASPAY_API_BASE_URL}/countries/`, { headers, timeout: 10000 }),
        ]);

        const ratesData = ratesRes.status === 'fulfilled' ? ratesRes.value.data : null;
        const countriesData = countriesRes.status === 'fulfilled' ? countriesRes.value.data : null;

        if (!ratesData && !countriesData) {
            throw new Error('Réponse SasPay indisponible');
        }

        const built = buildPaymentOptionsFromSasPay(ratesData, countriesData);
        paymentOptionsCache = {
            data: built.countries,
            rates: built.rateItems,
            expiresAt: now + PAYMENT_OPTIONS_CACHE_TTL_MS,
        };
        return built;
    } catch (err) {
        if (paymentOptionsCache.data) {
            return { countries: paymentOptionsCache.data, rateItems: paymentOptionsCache.rates };
        }
        throw new Error(`Impossible de récupérer les options SasPay : ${err.message}`);
    }
}

async function fetchPaymentOptionsCached(forceRefresh = false) {
    const { countries } = await fetchPaymentOptionsWithRates(forceRefresh);
    return countries;
}

// =========================================================================
// VÉRIFICATION WEBHOOK : HORODATAGE (<= 5 MIN) + HMAC-SHA256({timestamp}.{rawBody})
// =========================================================================
function verifySasPayWebhook(req) {
    const signature = req.get('x-webhook-signature');
    const timestampHeader = req.get('x-webhook-timestamp');

    if (!signature || !timestampHeader || !req.rawBody) {
        return { ok: false, reason: 'En-têtes de signature ou horodatage manquants' };
    }

    const parsedTs = Number(String(timestampHeader).trim());
    if (!Number.isFinite(parsedTs) || parsedTs <= 0) {
        return { ok: false, reason: 'Horodatage invalide' };
    }

    // Support secondes ou millisecondes
    const tsSeconds = parsedTs > 1e12 ? Math.floor(parsedTs / 1000) : Math.floor(parsedTs);
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSeconds - tsSeconds) > WEBHOOK_MAX_AGE_SECONDS) {
        return { ok: false, reason: 'Horodatage expiré (> 5 minutes)' };
    }

    const suppliedDigest = String(signature).trim().replace(/^sha256=/i, '');
    if (!/^[a-f0-9]{64}$/i.test(suppliedDigest)) {
        return { ok: false, reason: 'Format de signature invalide' };
    }

    const rawString = Buffer.isBuffer(req.rawBody) ? req.rawBody.toString('utf8') : String(req.rawBody);
    const signedPayload = `${String(timestampHeader).trim()}.${rawString}`;

    const expectedDigest = crypto
        .createHmac('sha256', SAASPAY_WEBHOOK_SECRET)
        .update(signedPayload)
        .digest();
    const receivedDigest = Buffer.from(suppliedDigest, 'hex');

    if (expectedDigest.length !== receivedDigest.length || !crypto.timingSafeEqual(expectedDigest, receivedDigest)) {
        return { ok: false, reason: 'Signature HMAC invalide' };
    }

    return { ok: true };
}

// Normalisation d'état SasPay vers PENDING | SUCCESS | FAILED
function normalizeSasPayStatus(rawStatus) {
    const s = String(rawStatus || '').toLowerCase().trim();
    if (['success', 'succeeded', 'paid', 'completed', 'transaction.success'].includes(s)) {
        return 'SUCCESS';
    }
    if (['failed', 'error', 'declined', 'rejected', 'canceled', 'cancelled', 'expired', 'transaction.failed'].includes(s)) {
        return 'FAILED';
    }
    return 'PENDING';
}

function activateUserSubscription(db, payment, verifiedData = {}) {
    const userId = payment.userId;
    const existingSub = db.subscriptions[userId];
    const now = new Date();
    const currentEnd = existingSub?.status === 'ACTIVE' && existingSub?.endDate
        ? new Date(existingSub.endDate)
        : null;
    const baseStart = currentEnd && currentEnd > now ? currentEnd : now;
    const endDate = new Date(baseStart.getTime() + 30 * 24 * 60 * 60 * 1000);

    db.subscriptions[userId] = {
        userId,
        tenantId: payment.tenantId || existingSub?.tenantId || 'tenant_main',
        status: 'ACTIVE',
        plan: payment.plan || 'MONTHLY_5000',
        amount: SUBSCRIPTION_AMOUNT_NUM,
        feeAmount: payment.feeAmount ?? 0,
        subscriptionAmount: payment.subscriptionAmount ?? SUBSCRIPTION_AMOUNT_NUM,
        currency: SUBSCRIPTION_CURRENCY,
        startDate: existingSub?.status === 'ACTIVE' && existingSub?.startDate ? existingSub.startDate : now.toISOString(),
        endDate: endDate.toISOString(),
        transactionId: payment.paymentId,
        reference: payment.reference,
        lastPaymentAt: now.toISOString(),
        updatedAt: now.toISOString(),
        verifiedCharged: verifiedData.charged ?? SUBSCRIPTION_AMOUNT_NUM,
    };

    db.payments[payment.paymentId] = {
        ...payment,
        status: 'SUCCESS',
        updatedAt: now.toISOString(),
    };
}

async function verifyPaymentWithSasPay(paymentId) {
    const resp = await axios.get(`${SAASPAY_API_BASE_URL}/payments/${encodeURIComponent(paymentId)}/verify/`, {
        headers: {
            'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
            'Accept': 'application/json',
        },
        timeout: 10000,
    });
    return resp.data?.data ?? resp.data;
}

// Middleware pour conserver le buffer brut (requis pour HMAC webhook)
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
// 1. GET /api/payment-options : PAYS & RÉSEAUX ACTIFS + CARTE BANCAIRE
// =========================================================================
app.get('/api/payment-options', async (req, res) => {
    try {
        const countries = await fetchPaymentOptionsCached(req.query.refresh === '1');
        return res.json({
            countries,
            cachedUntil: new Date(paymentOptionsCache.expiresAt).toISOString(),
        });
    } catch (err) {
        console.error('[Payment Options Error]', err.message);
        return res.status(502).json({ error: 'Impossible de charger les moyens de paiement actuellement.' });
    }
});

// =========================================================================
// 2. POST /api/pay-softpay : PAIEMENT DIRECT MULTI-PAYS
// =========================================================================
app.post('/api/pay-softpay', requireFirebaseAuth, async (req, res) => {
    try {
        const userId = req.firebaseUser.uid;
        const { country, network, phone, customerName, customerEmail, otp, tenantId } = req.body || {};

        if (!country || !network) {
            return res.status(400).json({ error: 'Le pays et le moyen de paiement sont requis.' });
        }

        const { countries, rateItems } = await fetchPaymentOptionsWithRates();
        const selectedCountry = countries.find((c) => c.code === String(country).toUpperCase());
        if (!selectedCountry) {
            return res.status(400).json({ error: 'Ce pays n’est pas disponible actuellement.' });
        }

        const selectedNetwork = selectedCountry.networks.find((n) => n.code === String(network));
        if (!selectedNetwork) {
            return res.status(400).json({ error: 'Ce réseau n’est pas actif dans ce pays.' });
        }

        const cleanPhone = String(phone || '').replace(/[^\d+]/g, '');
        const digitsOnly = cleanPhone.replace(/\D/g, '');
        if (digitsOnly.length < 7 || digitsOnly.length > 15) {
            return res.status(400).json({ error: 'Numéro de téléphone invalide.' });
        }

        if (selectedNetwork.otpRequired && !String(otp || '').trim()) {
            return res.status(422).json({
                error: 'Un code temporaire généré depuis votre téléphone est requis avant la validation.',
                code: 'PREPAYMENT_OTP_REQUIRED',
            });
        }

        // Calcul dynamique des frais depuis GET /pricing/my-rates/ (carte ou mobile money) et montant net = 5000 - frais
        const feeCalc = await calculateDynamicFeeFor5000(rateItems, selectedCountry.code, selectedNetwork.code);

        const resolvedName = String(customerName || req.firebaseUser.name || 'Client GESTIO').trim();
        const nameParts = resolvedName.split(/\s+/);
        const firstName = nameParts[0] || 'Client';
        const lastName = nameParts.slice(1).join(' ') || 'GESTIO';
        const resolvedEmail = String(customerEmail || req.firebaseUser.email || `${userId}@gestio.app`).trim();
        const returnUrl = resolveAbsoluteReturnUrl(req);

        const reference = `GESTIO_${userId}_${Date.now()}`;
        const idempotencyKey = crypto.randomUUID();

        const payload = {
            country: selectedCountry.code === 'OTHER' ? 'CI' : selectedCountry.code,
            network: selectedNetwork.code,
            amount: feeCalc.amountToSend.toFixed(2),
            currency: SUBSCRIPTION_CURRENCY,
            fee_charge_mode: feeCalc.feeChargeMode,
            phone: cleanPhone,
            customer: {
                email: resolvedEmail,
                first_name: firstName,
                last_name: lastName,
                phone: cleanPhone,
            },
            description: 'Abonnement Premium GESTIO (1 mois)',
            metadata: {
                user_id: userId,
                tenant_id: tenantId || 'tenant_main',
                plan: 'MONTHLY_5000',
                reference,
                customer_amount: SUBSCRIPTION_AMOUNT_NUM,
                fee_amount: feeCalc.feeAmount,
                subscription_amount: feeCalc.subscriptionAmount,
            },
            return_url: returnUrl,
            ...(otp ? { otp: String(otp).trim() } : {}),
        };

        const headers = {
            'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': idempotencyKey,
        };

        let saspayResp;
        try {
            try {
                saspayResp = await axios.post(`${SAASPAY_API_BASE_URL}/payments/softpay/`, payload, {
                    headers,
                    timeout: 15000,
                });
            } catch (softpayErr) {
                if (softpayErr?.response?.status === 404) {
                    saspayResp = await axios.post(`${SAASPAY_API_BASE_URL}/payments/`, payload, {
                        headers,
                        timeout: 15000,
                    });
                } else {
                    throw softpayErr;
                }
            }
        } catch (apiError) {
            const errBody = apiError?.response?.data;
            const status = apiError?.response?.status || 502;
            console.warn('[SasPay SoftPay Error]', status, errBody || apiError.message);
            const userMsg = extractSasPayErrorMessage(errBody, 'Impossible de lancer le paiement pour le moment.');
            return res.status(status >= 400 && status < 500 ? status : 502).json({ error: userMsg });
        }

        const respData = saspayResp.data?.data ?? saspayResp.data ?? {};
        const paymentId = respData.id || respData.payment_id || respData.transaction_id;
        const checkoutUrl = respData.checkout_url || respData.payment_url || respData.url || null;

        if (!paymentId) {
            return res.status(502).json({ error: 'Réponse de paiement incomplète.' });
        }

        const requiresOtpConfirm = Boolean(
            respData.requires_otp ||
            respData.otp_required ||
            respData.next_action === 'confirm_otp' ||
            selectedNetwork.postOtpRequired
        );

        // Enregistrement du paiement en attente SANS écraser un abonnement déjà actif
        const db = loadDatabase();
        db.payments[paymentId] = {
            paymentId,
            userId,
            tenantId: tenantId || 'tenant_main',
            plan: 'MONTHLY_5000',
            status: 'PENDING',
            amount: SUBSCRIPTION_AMOUNT_NUM,
            feeAmount: feeCalc.feeAmount,
            subscriptionAmount: feeCalc.subscriptionAmount,
            feePercent: feeCalc.percent,
            feeFixed: feeCalc.fixed,
            feeCurrency: feeCalc.tierCurrency,
            currency: SUBSCRIPTION_CURRENCY,
            country: selectedCountry.code,
            network: selectedNetwork.code,
            phone: cleanPhone,
            reference,
            idempotencyKey,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };

        // Si l'utilisateur n'a pas encore d'abonnement actif, marquer PENDING_PAYMENT sans écraser un actif
        const existingSub = db.subscriptions[userId];
        const hasActiveSub = existingSub && existingSub.status === 'ACTIVE' && (!existingSub.endDate || new Date(existingSub.endDate) > new Date());
        if (!hasActiveSub) {
            db.subscriptions[userId] = {
                userId,
                tenantId: tenantId || 'tenant_main',
                status: 'PENDING_PAYMENT',
                plan: 'MONTHLY_5000',
                amount: SUBSCRIPTION_AMOUNT_NUM,
                feeAmount: feeCalc.feeAmount,
                subscriptionAmount: feeCalc.subscriptionAmount,
                currency: SUBSCRIPTION_CURRENCY,
                reference,
                paymentId,
                createdAt: new Date().toISOString(),
                startDate: null,
                endDate: null,
                lastCheckedAt: new Date().toISOString(),
            };
        }

        saveDatabase(db);

        if (checkoutUrl) {
            return res.json({
                success: true,
                paymentId,
                status: 'PENDING',
                checkoutUrl,
            });
        }

        return res.json({
            success: true,
            paymentId,
            status: 'PENDING',
            requiresOtpConfirm,
            message: respData.message || 'Validez le paiement sur votre téléphone',
        });
    } catch (err) {
        console.error('[Erreur SoftPay]', err);
        return res.status(500).json({ error: 'Erreur lors de l’initialisation du paiement.' });
    }
});

// =========================================================================
// 3. POST /api/confirm-otp : CONFIRMATION CODE SMS APRÈS PAIEMENT
// =========================================================================
app.post('/api/confirm-otp', requireFirebaseAuth, async (req, res) => {
    try {
        const userId = req.firebaseUser.uid;
        const { paymentId, otp } = req.body || {};

        if (!paymentId || !otp) {
            return res.status(400).json({ error: 'Identifiant de paiement et code de confirmation requis.' });
        }

        const db = loadDatabase();
        const payment = db.payments[paymentId];
        if (payment && payment.userId !== userId) {
            return res.status(403).json({ error: 'Accès refusé pour ce paiement.' });
        }

        const resp = await axios.post(
            `${SAASPAY_API_BASE_URL}/payments/${encodeURIComponent(paymentId)}/confirm-otp/`,
            { otp: String(otp).trim() },
            {
                headers: {
                    'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
                    'Content-Type': 'application/json',
                },
                timeout: 15000,
            }
        );

        const data = resp.data?.data ?? resp.data ?? {};
        const normalized = normalizeSasPayStatus(data.status);

        return res.json({
            success: true,
            paymentId,
            status: normalized,
            message: data.message || 'Code transmis.',
        });
    } catch (err) {
        const status = err?.response?.status || 502;
        const body = err?.response?.data;
        console.warn('[Confirm OTP Error]', status, body || err.message);
        return res.status(status >= 400 && status < 500 ? status : 502).json({
            error: body?.message || body?.error || 'Code incorrect ou expiré.',
        });
    }
});

// =========================================================================
// 4. GET /api/payment-status/:paymentId : VÉRIFICATION TEMPS RÉEL VIA /verify/
// =========================================================================
app.get('/api/payment-status/:paymentId', requireFirebaseAuth, async (req, res) => {
    try {
        const { paymentId } = req.params;
        const userId = req.firebaseUser.uid;

        const db = loadDatabase();
        const payment = db.payments[paymentId];
        if (payment && payment.userId !== userId) {
            return res.status(403).json({ error: 'Accès refusé pour ce paiement.' });
        }

        const verified = await verifyPaymentWithSasPay(paymentId);
        const normalizedStatus = normalizeSasPayStatus(verified.status);

        if (normalizedStatus === 'SUCCESS' && payment) {
            const verifiedCurrency = String(verified.currency || payment.currency || '').toUpperCase();
            if (verifiedCurrency === 'XOF') {
                const rawCharged = verified.charged ?? verified.debited_amount ?? verified.amounts?.charged;
                const chargedVal = rawCharged !== undefined ? Number(rawCharged) : NaN;
                if (!Number.isFinite(chargedVal) || chargedVal < SUBSCRIPTION_AMOUNT_NUM - 10 || chargedVal > SUBSCRIPTION_AMOUNT_NUM + 10) {
                    return res.status(409).json({
                        paymentId,
                        status: 'FAILED',
                        isSubscribed: false,
                        error: 'Montant débité non conforme.',
                    });
                }
            }

            if (payment.status !== 'SUCCESS') {
                activateUserSubscription(db, payment, verified);
                saveDatabase(db);
            }
        } else if (normalizedStatus === 'FAILED' && payment && payment.status !== 'SUCCESS') {
            db.payments[paymentId] = {
                ...payment,
                status: 'FAILED',
                updatedAt: new Date().toISOString(),
            };
            saveDatabase(db);
        }

        const sub = db.subscriptions[userId];
        const isActive = Boolean(
            sub && sub.status === 'ACTIVE' && (!sub.endDate || new Date(sub.endDate) > new Date())
        );

        return res.json({
            paymentId,
            status: normalizedStatus,
            isSubscribed: isActive,
            requiresOtpConfirm: Boolean(verified.requires_otp || verified.next_action === 'confirm_otp'),
            endDate: sub?.endDate || null,
        });
    } catch (err) {
        console.warn('[Payment Status Error]', err?.response?.data || err.message);
        return res.status(502).json({ error: 'Vérification temporairement impossible.' });
    }
});

// =========================================================================
// 5. ROUTE : WEBHOOK SÉCURISÉ (TIMESTAMP + HMAC + RE-VÉRIFICATION /verify/)
// =========================================================================
app.post('/api/webhook/saaspay', async (req, res) => {
    try {
        const sigCheck = verifySasPayWebhook(req);
        if (!sigCheck.ok) {
            console.error(`[Webhook] Rejeté : ${sigCheck.reason}`);
            return res.status(401).json({ error: sigCheck.reason });
        }

        const event = req.body || {};
        const eventType = String(event.event || event.type || '').toLowerCase();
        const data = event.data || {};
        const paymentId = data.id;

        if (!paymentId) {
            return res.status(400).json({ error: 'Identifiant de paiement (data.id) manquant' });
        }

        const db = loadDatabase();
        const payment = db.payments[paymentId];
        if (!payment) {
            console.warn(`[Webhook] Paiement introuvable pour data.id=${paymentId}`);
            return res.status(404).json({ error: 'Paiement introuvable' });
        }

        if (eventType === 'transaction.failed') {
            if (payment.status !== 'SUCCESS') {
                db.payments[paymentId] = {
                    ...payment,
                    status: 'FAILED',
                    updatedAt: new Date().toISOString(),
                };
                saveDatabase(db);
            }
            console.log(`[Webhook] ✗ Échec enregistré pour paymentId=${paymentId}`);
            return res.json({ received: true, status: 'FAILED' });
        }

        if (eventType !== 'transaction.success') {
            return res.json({ received: true, ignored: true });
        }

        // Revérification obligatoire auprès de /payments/{id}/verify/ avant toute activation
        let verified;
        try {
            verified = await verifyPaymentWithSasPay(paymentId);
        } catch (verifyErr) {
            console.error(`[Webhook] Échec re-vérification /verify/ pour ${paymentId}:`, verifyErr.message);
            return res.status(502).json({ error: 'Impossible de revérifier la transaction' });
        }

        if (normalizeSasPayStatus(verified.status) !== 'SUCCESS') {
            return res.status(409).json({ error: 'La transaction n’est pas confirmée comme réussie' });
        }

        const verifiedCurrency = String(verified.currency || data.currency || '').toUpperCase();
        if (verifiedCurrency === 'XOF') {
            // Vérifier impérativement le montant réellement débité (charged) ≈ 5 000 FCFA (jamais amount seul)
            const rawCharged = verified.charged ?? verified.debited_amount ?? verified.amounts?.charged;
            const chargedVal = rawCharged !== undefined ? Number(rawCharged) : NaN;
            if (!Number.isFinite(chargedVal) || chargedVal < SUBSCRIPTION_AMOUNT_NUM - 10 || chargedVal > SUBSCRIPTION_AMOUNT_NUM + 10) {
                console.error(`[Webhook] Montant XOF non conforme: charged=${rawCharged}`);
                return res.status(409).json({ error: 'Montant débité (charged) non conforme pour XOF' });
            }
        }
        // Pour les autres devises, ne pas comparer le montant

        if (payment.status !== 'SUCCESS') {
            activateUserSubscription(db, payment, verified);
            saveDatabase(db);
            console.log(`[Webhook] ✓ Abonnement activé pour userId=${payment.userId} (paymentId=${paymentId})`);
        }

        return res.json({ received: true, status: 'SUCCESS' });
    } catch (err) {
        console.error('[Erreur Webhook SasPay]', err);
        return res.status(500).json({ error: 'Erreur interne traitement webhook' });
    }
});

// =========================================================================
// 6. ROUTE COMPATIBILITÉ : CRÉATION CHECKOUT SESSION (EXIGÉE PAR ANCIENNE VERSION)
// =========================================================================
app.post('/api/create-checkout-session', requireFirebaseAuth, async (req, res) => {
    try {
        const userId = req.firebaseUser.uid;
        const { tenantId, customerName, customerPhone, customerEmail } = req.body || {};
        const reference = `GESTIO_${userId}_${Date.now()}`;
        const idempotencyKey = crypto.randomUUID();

        const saaspayResponse = await axios.post(`${SAASPAY_API_BASE_URL}/checkout-sessions/`, {
            amount: SUBSCRIPTION_AMOUNT_STR,
            currency: SUBSCRIPTION_CURRENCY,
            fee_charge_mode: 'DEDUCTED',
            description: 'Abonnement Premium GESTIO (1 mois)',
            customer_phone: customerPhone || '',
            customer_email: customerEmail || req.firebaseUser.email || `${userId}@gestio.app`,
            customer_name: customerName || req.firebaseUser.name || 'Client GESTIO',
            metadata: {
                user_id: userId,
                tenant_id: tenantId || 'tenant_main',
                plan: 'MONTHLY_5000',
                reference,
            },
            return_url: process.env.APP_SUCCESS_URL || 'https://gestio.app/?payment=return',
        }, {
            headers: {
                'Authorization': `Bearer ${SAASPAY_SECRET_KEY}`,
                'Content-Type': 'application/json',
                'Idempotency-Key': idempotencyKey,
            },
            timeout: 10000,
        });

        const sessionData = saaspayResponse.data?.data ?? saaspayResponse.data ?? {};
        const checkoutUrl = sessionData.checkout_url || sessionData.payment_url || sessionData.url;
        const externalSessionId = sessionData.id;

        if (!checkoutUrl || !externalSessionId) {
            return res.status(502).json({ error: 'Session de paiement incomplète.' });
        }

        const db = loadDatabase();
        db.payments[externalSessionId] = {
            paymentId: externalSessionId,
            userId,
            tenantId: tenantId || 'tenant_main',
            plan: 'MONTHLY_5000',
            status: 'PENDING',
            amount: SUBSCRIPTION_AMOUNT_NUM,
            currency: SUBSCRIPTION_CURRENCY,
            reference,
            idempotencyKey,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };
        saveDatabase(db);

        return res.json({
            success: true,
            checkoutUrl,
            paymentId: externalSessionId,
            sessionId: externalSessionId,
            reference,
            amount: SUBSCRIPTION_AMOUNT_NUM,
            currency: SUBSCRIPTION_CURRENCY,
        });
    } catch (err) {
        console.error('[Erreur Create Checkout Session]', err?.response?.data || err.message);
        return res.status(502).json({ error: 'Erreur lors de la création du paiement' });
    }
});

// =========================================================================
// 7. ROUTE : LECTURE DU STATUT D'ABONNEMENT
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
                amount: SUBSCRIPTION_AMOUNT_NUM,
                currency: SUBSCRIPTION_CURRENCY,
                endDate: null,
                message: 'Aucun abonnement actif',
            });
        }

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
            amount: sub.amount || SUBSCRIPTION_AMOUNT_NUM,
            currency: sub.currency || SUBSCRIPTION_CURRENCY,
            startDate: sub.startDate,
            endDate: sub.endDate,
            transactionId: sub.transactionId || null,
            message: isActive ? 'Abonnement actif' : (isExpired ? 'Abonnement expiré' : 'Paiement non confirmé'),
        });
    } catch (err) {
        console.error('[Erreur Get Subscription Status]', err);
        return res.status(500).json({ error: 'Erreur lecture statut' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'gestio-saspay-backend', time: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`[GESTIO Backend] Serveur SasPay & Webhook opérationnel sur le port ${PORT}`);
    console.log(`[Webhook URL] POST http://localhost:${PORT}/api/webhook/saaspay`);
});
