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


// Wraps async routes

const route = (handler) => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch((err) => {
    console.error(`${req.method} ${req.originalUrl} failed:`, err);
    if (!res.headersSent) {
      res.status(500).json({ message: "Something went wrong. Please try again." });
    }
  });

function toObjectId(value) {
  return typeof value === "string" && ObjectId.isValid(value)
    ? new ObjectId(value)
    : null;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const isNonEmptyString = (v, min = 1) =>
  typeof v === "string" && v.trim().length >= min;

function serializeUser(user) {
  return {
    _id: user._id.toString(),
    name: user.name ?? "",
    email: user.email ?? "",
    image: user.image ?? null,
    role: ROLES.includes(user.role) ? user.role : "customer",
    phone: user.phone ?? "",
    area: user.area ?? "",
    bio: user.bio ?? "",
    createdAt: user.createdAt ?? null,
  };
}

function serializeBooking(booking) {
  const { _id, activeKey, ...fields } = booking;
  return { ...fields, _id: _id.toString() };
}

function serializeDoc(doc) {
  return { ...doc, _id: doc._id.toString() };
}

async function getRatingMap(serviceIds) {
  if (!serviceIds.length) return new Map();
  const rows = await bookings
    .aggregate([
      { $match: { serviceId: { $in: serviceIds }, rating: { $gte: 1 } } },
      {
        $group: {
          _id: "$serviceId",
          avg: { $avg: "$rating" },
          count: { $sum: 1 },
        },
      },
    ])
    .toArray();
  return new Map(rows.map((r) => [r._id, r]));
}

function withRating(service, ratingMap) {
  const id = service._id.toString();
  const rating = ratingMap.get(id);
  return {
    ...service,
    _id: id,
    avgRating: rating ? Math.round(rating.avg * 10) / 10 : 0,
    reviewCount: rating?.count ?? 0,
  };
}

function validateServiceBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: "Service details are required." };
  }
  const basePrice = Number(body.basePrice);
  if (!isNonEmptyString(body.title, 3)) return { error: "Title is required." };
  if (!CATEGORIES.includes(body.category)) return { error: "Choose a valid category." };
  if (!isNonEmptyString(body.description, 20)) {
    return { error: "Description must be at least 20 characters." };
  }
  if (!isNonEmptyString(body.image) || !/^https?:\/\//i.test(body.image)) {
    return { error: "A service image is required." };
  }
  if (!Number.isFinite(basePrice) || basePrice <= 0 || basePrice > 100000) {
    return { error: "Base price must be a positive number." };
  }
  if (!isNonEmptyString(body.estimatedDuration, 2)) {
    return { error: "Estimated duration is required." };
  }
  if (!SERVICE_MODES.includes(body.serviceMode)) {
    return { error: "Choose a valid service mode." };
  }
  if (!isNonEmptyString(body.serviceArea, 2)) return { error: "Service area is required." };

  return {
    value: {
      title: body.title.trim(),
      category: body.category,
      description: body.description.trim(),
      image: body.image.trim(),
      basePrice: Math.round(basePrice * 100) / 100,
      estimatedDuration: body.estimatedDuration.trim(),
      serviceMode: body.serviceMode,
      serviceArea: body.serviceArea.trim(),
    },
  };
}


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


async function fulfillCheckoutSession(session) {
  if (session.payment_status !== "paid") {
    const error = new Error("Stripe has not confirmed this payment yet.");
    error.status = 409;
    throw error;
  }

  const bookingId = toObjectId(session.metadata?.bookingId);
  if (!bookingId) {
    const error = new Error("This checkout session is not a FixMate booking.");
    error.status = 400;
    throw error;
  }

  const booking = await bookings.findOne({ _id: bookingId });
  if (!booking) {
    const error = new Error("The booking for this payment was not found.");
    error.status = 404;
    throw error;
  }

  // Never trust the session blindly: it must match what the database says this job costs.
  if (
    session.metadata?.customerEmail !== booking.customerEmail ||
    booking.status !== "completed" ||
    session.currency !== "usd" ||
    session.amount_total !== Math.round(booking.finalAmount * 100)
  ) {
    const error = new Error("This payment does not match the booking.");
    error.status = 400;
    throw error;
  }

  const paymentIntentId =
    typeof session.payment_intent === "string"
      ? session.payment_intent
      : session.payment_intent?.id;

  const paymentDoc = {
    bookingId: booking._id.toString(),
    serviceTitle: booking.serviceTitle,
    customerName: booking.customerName,
    customerEmail: booking.customerEmail,
    technicianName: booking.technicianName,
    technicianEmail: booking.technicianEmail,
    amount: booking.finalAmount,
    currency: "usd",
    transactionId: paymentIntentId ?? session.id,
    stripeSessionId: session.id,
    paymentStatus: "paid",
    paidAt: new Date(),
  };

  // $setOnInsert + unique indexes = the same payment is never saved twice,
  // even if the success page and the webhook (or Stripe's retries) run at the same time.
  try {
    await payments.updateOne(
      { stripeSessionId: session.id },
      { $setOnInsert: paymentDoc },
      { upsert: true }
    );
  } catch (err) {
    if (err?.code !== 11000) throw err;
  }

  const now = new Date();
  await bookings.updateOne(
    { _id: booking._id, paymentStatus: "unpaid" },
    {
      $set: { paymentStatus: "paid", paidAt: now, updatedAt: now },
      $push: { statusHistory: { status: "paid", changedAt: now } },
    }
  );

  return (
    (await payments.findOne({ stripeSessionId: session.id })) ??
    (await payments.findOne({ bookingId: booking._id.toString() }))
  );
}


// Route

app.get("/", (req, res) => {
  res.send("The FixMate backend is up and running!");
});

/* ---------- Services: public ---------- */
// Search, filter, sort and pagination all happen in MongoDB (Challenge 1).
app.get(
  "/api/services",
  route(async (req, res) => {
    const { search, category, mode, sort } = req.query;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 12));

    const filter = { approvalStatus: "approved", isAvailable: true };
    if (typeof search === "string" && search.trim()) {
      const regex = new RegExp(escapeRegex(search.trim()), "i");
      filter.$or = [{ title: regex }, { category: regex }];
    }
    if (typeof category === "string" && category && category !== "All") {
      filter.category = category;
    }
    if (typeof mode === "string" && mode && mode !== "All") {
      filter.serviceMode = mode;
    }

    const sortMap = {
      "price-asc": { basePrice: 1, _id: 1 },
      "price-desc": { basePrice: -1, _id: 1 },
      newest: { createdAt: -1, _id: -1 },
    };

    const [records, total] = await Promise.all([
      services
        .find(filter)
        .sort(sortMap[sort] ?? sortMap.newest)
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray(),
      services.countDocuments(filter),
    ]);

    const ratingMap = await getRatingMap(records.map((s) => s._id.toString()));
    return res.json({
      services: records.map((s) => withRating(s, ratingMap)),
      total,
      page,
      totalPages: Math.max(1, Math.ceil(total / limit)),
    });
  })
);

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