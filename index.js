import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const port = process.env.PORT || 5000;

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

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

// Stripe webhook
app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(503).json({ message: "Webhook is not configured." });
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err.message);
      return res.status(400).json({ message: "Invalid webhook signature." });
    }

    try {
      if (
        event.type === "checkout.session.completed" ||
        event.type === "checkout.session.async_payment_succeeded"
      ) {
        // Safe to call repeatedly: fulfillment is idempotent.
        await fulfillCheckoutSession(event.data.object);
      }
      return res.json({ received: true });
    } catch (err) {
      console.error("Webhook fulfillment failed:", err);
      // 500 makes Stripe retry later; retries never create duplicate payments.
      return res.status(500).json({ message: "Webhook handling failed." });
    }
  }
);

app.use(express.json());
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Origin is not allowed by CORS"));
    },
    credentials: true,
  })
);

// Database - mogodb
const client = new MongoClient(process.env.MONGODB_URI);
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err);
    throw err;
  }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db(process.env.MONGODB_DB_NAME || "fixmate");
// BetterAuth's MongoDB adapter 


// Auth middlewares

async function verifyToken(req, res, next) {
  const header = req.headers.authorization ?? "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: sign in to continue." });
  }

  try {
    const { payload } = await jwtVerify(header.slice(7), JWKS, {
      issuer: [process.env.BETTER_AUTH_URL, betterAuthUrl, new URL(betterAuthUrl).origin],
    });
    const userId = toObjectId(String(payload.id ?? payload.sub ?? ""));
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized: invalid token." });
    }

    const account = await users.findOne({ _id: userId });
    if (!account) {
      return res.status(401).json({ message: "Unauthorized: account not found." });
    }

    req.user = {
      id: account._id.toString(),
      name: account.name ?? "",
      email: account.email,
      image: account.image ?? null,
      role: ROLES.includes(account.role) ? account.role : "customer",
    };
    return next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized: invalid or expired token." });
  }
}

const requireRole = (role, label) => (req, res, next) => {
  if (req.user?.role !== role) {
    return res.status(403).json({ message: `Forbidden: ${label} access only.` });
  }
  return next();
};
const verifyCustomer = requireRole("customer", "customer");
const verifyTechnician = requireRole("technician", "technician");
const verifyAdmin = requireRole("admin", "admin");

//Fallbacks 
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