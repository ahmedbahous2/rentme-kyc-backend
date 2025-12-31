// Corrected rentme_kyc_server.js for Cloud Run deployment
// This version ensures the server listens on the correct port (process.env.PORT)
// and includes a health check endpoint for Cloud Run.
// It also prevents crashes if environment variables like STRIPE_SECRET_KEY are missing.

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Health check endpoint for Cloud Run
app.get('/health', (req, res) => {
  res.status(200).send('ok');
});

// Example root endpoint
app.get('/', (req, res) => {
  res.status(200).send('RentMe KYC backend is running');
});

// Example route: KYC return handler
app.post('/kyc/return', async (req, res) => {
  try {
    const eventData = req.body || {};
    console.log('Received KYC return payload:', eventData);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Error handling /kyc/return:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Prevent app from crashing if STRIPE_SECRET_KEY or others are missing
if (!process.env.STRIPE_SECRET_KEY) {
  console.warn('⚠️  STRIPE_SECRET_KEY is not defined in environment variables.');
}

// Start server on the port Cloud Run provides
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ RentMe KYC backend listening on port ${port}`);
});
