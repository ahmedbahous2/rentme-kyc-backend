'use strict';

/**
 * RentMe KYC Backend (Production-hardened)
 *
 * What this server does:
 * - Creates Stripe Identity verification sessions for authenticated users.
 * - Receives Stripe webhooks and persists KYC state to Firestore (idempotent).
 * - Exposes a status endpoint for the app to show "verified / pending / failed".
 *
 * IMPORTANT:
 * - For production, the app should call these endpoints with Firebase ID tokens:
 *   Authorization: Bearer <FIREBASE_ID_TOKEN>
 *
 * - For fast local testing ONLY, you can enable insecure auth by setting:
 *   ALLOW_INSECURE_DEV_AUTH=true
 *   and then sending:
 *   X-User-Id: <uid>
 */

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');

// We keep body-parser ONLY to guarantee a raw body for Stripe webhook verification.
const bodyParser = require('body-parser');

let admin = null;
let db = null;

// -----------------------
// Config
// -----------------------
const PORT = process.env.PORT || 3000;

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Stripe Identity needs an HTTPS return_url.
// Use an HTTPS endpoint you own, then redirect to the app deep-link.
// Example: https://api.yourdomain.com/kyc/return?session={VERIFICATION_SESSION_ID}
const KYC_RETURN_URL = process.env.KYC_RETURN_URL;

// Deep-link for redirect from /kyc/return
// Example: rentme://kyc?session=...
const APP_DEEP_LINK_SCHEME = process.env.APP_DEEP_LINK_SCHEME || 'rentme';
const APP_DEEP_LINK_HOST = process.env.APP_DEEP_LINK_HOST || 'kyc';

// Firestore user document path
const USERS_COLLECTION = process.env.USERS_COLLECTION || 'users';

// A dedicated collection for webhook idempotency (event.id)
const STRIPE_EVENTS_COLLECTION = process.env.STRIPE_EVENTS_COLLECTION || '_stripeWebhookEvents';

// Security / environment flags
const ALLOW_INSECURE_DEV_AUTH = String(process.env.ALLOW_INSECURE_DEV_AUTH || '').toLowerCase() === 'true';

// Optional (but recommended in production behind proxies/load balancers)
const TRUST_PROXY = String(process.env.TRUST_PROXY || '1');

// -----------------------
// Guardrails
// -----------------------
function requireEnv(name, value) {
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
}

requireEnv('STRIPE_SECRET_KEY', STRIPE_SECRET_KEY);
requireEnv('STRIPE_WEBHOOK_SECRET', STRIPE_WEBHOOK_SECRET);
requireEnv('KYC_RETURN_URL', KYC_RETURN_URL);

// -----------------------
// Stripe
// -----------------------
const stripe = new Stripe(STRIPE_SECRET_KEY);

// -----------------------
// Firebase Admin / Firestore
// -----------------------
function initFirebase() {
  // If you do NOT want Firestore persistence (not recommended), you can set:
  // DISABLE_FIRESTORE=true
  const disableFirestore = String(process.env.DISABLE_FIRESTORE || '').toLowerCase() === 'true';
  if (disableFirestore) {
    console.warn('⚠️  DISABLE_FIRESTORE=true — KYC state will NOT be persisted. Not for production.');
    return;
  }

  try {
    admin = require('firebase-admin');
  } catch (e) {
    console.error('❌ firebase-admin is not installed. Run: npm install');
    throw e;
  }

  if (admin.apps && admin.apps.length > 0) {
    db = admin.firestore();
    return;
  }

  // Option A: Provide the whole service account JSON as an env var
  // FIREBASE_SERVICE_ACCOUNT_JSON='{"type":"service_account", ... }'
  const saJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  // Option B: Provide a file path and set GOOGLE_APPLICATION_CREDENTIALS, or rely on ADC in Cloud Run
  // GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceAccount.json

  if (saJson) {
    const parsed = JSON.parse(saJson);
    admin.initializeApp({
      credential: admin.credential.cert(parsed),
    });
  } else {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
    });
  }

  db = admin.firestore();
}

initFirebase();

// -----------------------
// Express app
// -----------------------
const app = express();
app.set('trust proxy', Number(TRUST_PROXY) || 1);

// Security headers
app.use(
  helmet({
    // We return a tiny HTML on /kyc/return sometimes; keep CSP relaxed.
    contentSecurityPolicy: false,
  })
);

app.use(cors({ origin: true }));

// Global limiter (tune to your traffic)
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 180, // 180 req/min per IP
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// -----------------------
// Stripe webhook route MUST be declared BEFORE any JSON body parsing
// -----------------------
app.post('/v1/stripe/webhook-platform', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Stripe webhook signature verification failed:', err?.message || err);
    return res.status(400).send('Invalid signature');
  }

  try {
    await handleStripeEvent(event);
    return res.json({ received: true });
  } catch (err) {
    console.error('❌ Error handling Stripe webhook:', err?.message || err);
    // 200 prevents Stripe from retrying forever for non-recoverable bugs.
    // If you want retries, return 500 but be sure your handler is robust/idempotent.
    return res.status(200).json({ received: true });
  }
});

// After webhook route, we can parse JSON normally.
app.use(express.json({ limit: '1mb' }));

// -----------------------
// Health
// -----------------------
app.get('/health', (_req, res) => res.json({ ok: true }));

// -----------------------
// KYC return redirect (HTTPS endpoint for Stripe return_url)
// -----------------------
app.get('/kyc/return', async (req, res) => {
  const sessionId = String(req.query.session || req.query.verification_session_id || '').trim();

  // Deep-link back to the app.
  const deepLink = `${APP_DEEP_LINK_SCHEME}://${APP_DEEP_LINK_HOST}?session=${encodeURIComponent(sessionId || '')}`;

  // Prefer 302 redirect.
  res.status(302).setHeader('Location', deepLink);

  // Some browsers show a blank page after redirect; provide a minimal fallback.
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(
    `<!doctype html>
<html>
  <head><meta name="viewport" content="width=device-width, initial-scale=1"/></head>
  <body style="font-family: -apple-system, system-ui; padding: 24px;">
    <h2>Returning to RentMe…</h2>
    <p>If the app did not open automatically, tap:</p>
    <p><a href="${deepLink}">Open RentMe</a></p>
  </body>
</html>`
  );
});

// -----------------------
// Auth middleware
// -----------------------
async function auth(req, res, next) {
  // Insecure dev auth (ONLY if explicitly enabled)
  if (ALLOW_INSECURE_DEV_AUTH) {
    const devUid = req.header('X-User-Id');
    if (devUid) {
      req.userId = devUid;
      return next();
    }
  }

  if (!admin || !db) {
    return res.status(500).json({
      error: 'Server not configured for production auth/storage (Firestore disabled or firebase-admin missing).',
    });
  }

  const authz = req.header('Authorization') || '';
  const match = authz.match(/^Bearer (.+)$/);

  if (!match) {
    return res.status(401).json({
      error: 'Missing Authorization header. Expected: Authorization: Bearer <FirebaseIDToken>',
    });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(match[1]);
    req.userId = decoded.uid;
    return next();
  } catch (err) {
    console.error('Auth verifyIdToken failed:', err?.message || err);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// -----------------------
// API: Create a Stripe Identity session
// -----------------------
app.post('/v1/kyc/session', auth, async (req, res) => {
  const userId = req.userId;

  try {
    // If already verified, avoid starting new sessions.
    const current = await getUserKycState(userId);
    if (current.status === 'verified') {
      return res.json({
        status: 'verified',
        url: null,
        message: 'User already verified',
      });
    }

    const session = await stripe.identity.verificationSessions.create({
      type: 'document',
      metadata: {
        userId,
        app: 'rentme',
      },
      return_url: KYC_RETURN_URL,
      options: {
        document: {
          require_live_capture: true,
          require_matching_selfie: true,
        },
      },
    });

    // Persist minimal state
    await upsertUserKycState(userId, {
      status: 'pending',
      stripeSessionId: session.id,
      stripeSessionStatus: session.status || null,
      updatedBy: 'api',
    });

    return res.json({ status: 'pending', url: session.url, session_id: session.id });
  } catch (err) {
    console.error('Error creating verification session:', err?.message || err);
    return res.status(500).json({
      error: 'Failed to create verification session',
      details: err?.message || String(err),
    });
  }
});

// -----------------------
// API: Get current KYC status
// -----------------------
app.get('/v1/kyc/status', auth, async (req, res) => {
  const userId = req.userId;
  try {
    const state = await getUserKycState(userId);
    return res.json(state);
  } catch (err) {
    console.error('Error reading KYC state:', err?.message || err);
    return res.status(500).json({ error: 'Failed to read status' });
  }
});

// -----------------------
// Firestore helpers
// -----------------------
async function getUserKycState(userId) {
  if (!db) {
    // Firestore disabled: return a safe default
    return { status: 'not_started', session_id: null, updatedAt: null };
  }

  const userRef = db.collection(USERS_COLLECTION).doc(userId);
  const snap = await userRef.get();

  if (!snap.exists) {
    return { status: 'not_started', session_id: null, updatedAt: null };
  }

  const data = snap.data() || {};

  // Normalize
  const status = data.kycStatus || 'not_started';
  const sessionId = data.kycSessionId || null;

  // Firestore Timestamp -> ISO string
  const updatedAt =
    data.kycUpdatedAt && typeof data.kycUpdatedAt.toDate === 'function'
      ? data.kycUpdatedAt.toDate().toISOString()
      : null;

  return { status, session_id: sessionId, updatedAt };
}

async function upsertUserKycState(userId, payload) {
  if (!db || !admin) return;

  const now = admin.firestore.FieldValue.serverTimestamp();
  const userRef = db.collection(USERS_COLLECTION).doc(userId);

  const update = {
    kycStatus: payload.status,
    kycSessionId: payload.stripeSessionId || null,
    kycStripeStatus: payload.stripeSessionStatus || null,
    kycUpdatedAt: now,
    kycUpdatedBy: payload.updatedBy || 'system',
  };

  if (payload.status === 'verified') {
    update.isVerified = true;
    update.kycVerifiedAt = now;
  }

  await userRef.set(update, { merge: true });
}

function mapStripeVerificationToKyc(vs, eventType) {
  // Stripe verification session has a "status" field:
  // requires_input | processing | verified | canceled
  const s = String(vs?.status || '').toLowerCase();

  if (s === 'verified' || eventType === 'identity.verification_session.verified') return 'verified';
  if (s === 'canceled' || eventType === 'identity.verification_session.canceled') return 'failed';
  if (s === 'requires_input' || eventType === 'identity.verification_session.requires_input') return 'pending';
  if (s === 'processing' || eventType === 'identity.verification_session.processing') return 'pending';

  // Redacted is treated as failed
  if (eventType === 'identity.verification_session.redacted') return 'failed';

  return 'pending';
}

// -----------------------
// Stripe webhook handler (idempotent)
// -----------------------
async function handleStripeEvent(event) {
  // Ignore if Firestore is disabled (not for production)
  if (!db || !admin) return;

  const type = event.type;

  if (!type.startsWith('identity.verification_session.')) {
    return;
  }

  const vs = event.data.object;
  const userId = vs?.metadata?.userId;

  if (!userId) {
    console.warn('Stripe event missing metadata.userId. Event:', event.id, type);
    return;
  }

  const userRef = db.collection(USERS_COLLECTION).doc(userId);
  const eventRef = db.collection(STRIPE_EVENTS_COLLECTION).doc(event.id);

  await db.runTransaction(async (txn) => {
    const already = await txn.get(eventRef);
    if (already.exists) {
      // Idempotent replay
      return;
    }

    const now = admin.firestore.FieldValue.serverTimestamp();
    const kycStatus = mapStripeVerificationToKyc(vs, type);

    txn.set(eventRef, { createdAt: now, type, userId, stripeSessionId: vs.id });

    const update = {
      kycStatus,
      kycSessionId: vs.id,
      kycStripeStatus: vs.status || null,
      kycUpdatedAt: now,
      kycLastStripeEventId: event.id,
      kycLastStripeEventType: type,
      kycUpdatedBy: 'stripe_webhook',
    };

    if (kycStatus === 'verified') {
      update.isVerified = true;
      update.kycVerifiedAt = now;
    }

    txn.set(userRef, update, { merge: true });
  });
}

// -----------------------
// Start
// -----------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`RentMe KYC server listening on :${PORT}`);
  if (ALLOW_INSECURE_DEV_AUTH) {
    console.warn('⚠️  ALLOW_INSECURE_DEV_AUTH=true — X-User-Id auth is enabled. DO NOT use in production.');
  }
});
