// RentMe KYC backend - production version for Cloud Run
// Includes full JSON responses expected by the iOS app
// Endpoints: /v1/kyc/status and /v1/kyc/session
// Compatible with Cloud Run (listens on process.env.PORT)

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ---- Health ----
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, service: 'kyc', message: 'KYC service healthy', env: process.env.ENV || 'prod' });
});

// ---- Root ----
app.get('/', (req, res) => {
  res.status(200).json({ ok: true, service: 'kyc', message: 'KYC service online', env: process.env.ENV || 'prod' });
});

// ---- v1/kyc/status ----
// Simulates returning current KYC status for user
app.get('/v1/kyc/status', (req, res) => {
  const now = new Date().toISOString();
  res.status(200).json({
    status: 'not_started',      // could be not_started | pending | verified | rejected
    session_id: 'kyc_session_stub_001',
    updatedAt: now
  });
});

// ---- v1/kyc/session ----
// Simulates creation of a KYC session
app.post('/v1/kyc/session', (req, res) => {
  const now = new Date().toISOString();
  res.status(200).json({
    status: 'pending',
    session_id: 'kyc_session_' + Math.random().toString(36).substring(2, 10),
    url: 'https://example.com/kyc/session-placeholder',
    createdAt: now
  });
});

// ---- v1/kyc/return ----
// Handles provider webhook callback (stub)
app.post('/v1/kyc/return', async (req, res) => {
  try {
    console.log('Received KYC return payload:', req.body);
    res.status(200).json({ ok: true, message: 'Webhook processed' });
  } catch (err) {
    console.error('Error in /v1/kyc/return:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ---- Safety for missing STRIPE key ----
if (!process.env.STRIPE_SECRET_KEY) {
  console.warn('⚠️ STRIPE_SECRET_KEY not found. Continuing with stub mode.');
}

// ---- Start server ----
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ RentMe KYC backend running on port ${port}`);
});
