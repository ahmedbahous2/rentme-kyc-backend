// rentme_kyc_server.js — Production Cloud Run version
// Compatible Node 18+, Express 5.x
// Includes all required endpoints for the RentMe iOS KYC flow.

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ------------------------------------------------------------
// Health & root endpoints
// ------------------------------------------------------------

// Cloud Run health check
app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

// Default root route
app.get("/", (req, res) => {
  res.status(200).send("RentMe KYC backend is running");
});

// ------------------------------------------------------------
// KYC return handler (already used for hosted flow return URL)
// ------------------------------------------------------------
app.post("/kyc/return", async (req, res) => {
  try {
    const eventData = req.body || {};
    console.log("Received KYC return payload:", eventData);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error("Error handling /kyc/return:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ------------------------------------------------------------
// v1 KYC API endpoints expected by the iOS app
// ------------------------------------------------------------

// Simple health / status endpoint for KYC module
app.get("/v1/kyc/status", async (req, res) => {
  try {
    res.status(200).json({
      ok: true,
      service: "kyc",
      message: "KYC service online",
      env: process.env.ENV || "unknown",
    });
  } catch (err) {
    console.error("Status error:", err);
    res.status(500).json({ ok: false, error: "Internal server error" });
  }
});

// Stub endpoint for session creation (to be wired to Stripe Identity)
app.post("/v1/kyc/session", async (req, res) => {
  try {
    const payload = req.body || {};
    console.log("Received KYC session request:", payload);

    // TODO: integrate with Stripe Identity (createVerificationSession)
    // Example placeholder response
    res.status(200).json({
      ok: true,
      message: "Stub session created successfully",
      sessionUrl: "https://example.com/kyc/session-placeholder",
    });
  } catch (err) {
    console.error("Session error:", err);
    res.status(500).json({ ok: false, error: "Internal server error" });
  }
});

// ------------------------------------------------------------
// Environment validation & startup
// ------------------------------------------------------------

// Warn if Stripe key is missing (but don't crash)
if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("⚠️  STRIPE_SECRET_KEY is not defined in environment variables.");
}

const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => {
  console.log(`✅ RentMe KYC backend listening on port ${port}`);
});
