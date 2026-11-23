import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const port = process.env.PORT || 5000;


if (!process.env.MONGODB_URI) {
  throw new Error("MONGODB_URI must be configured");
}
if (!process.env.BETTER_AUTH_URL) {
  throw new Error(
    "BETTER_AUTH_URL must be configured (the origin that serves BetterAuth)"
  );
}

const betterAuthUrl = process.env.BETTER_AUTH_URL.replace(/\/$/, "");
const JWKS = createRemoteJWKSet(new URL(`${betterAuthUrl}/api/auth/jwks`));

const CATEGORIES = [
  "Smartphone",
  "Laptop & PC",
  "AC",
  "Refrigerator",
  "TV",
  "Washing Machine",
  "Electrical",
];
const SERVICE_MODES = ["Home Visit", "Shop Drop-off"];
const ROLES = ["customer", "technician", "admin"];
const ACTIVE_STATUSES = ["requested", "accepted", "in-progress"];



/* ---------- Fallbacks ---------- */
app.use((req, res) => {
  res.status(404).json({ message: "Route not found." });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.message === "Origin is not allowed by CORS" ? 403 : 500;
  if (status === 500) console.error("Unhandled error:", err);
  res.status(status).json({ message: status === 403 ? err.message : "Server error." });
});

app.listen(port, () => {
  console.log(`fixmate is running on port ${port}`);
});