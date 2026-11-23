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


  const allowedOrigins = new Set(
    (process.env.CLIENT_ORIGINS || "")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean)
  );
const clientUrl = (
  process.env.CLIENT_URL || allowedOrigins.values().next().value
).replace(/\/$/, "");

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
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
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

const users = database.collection("user");
const services = database.collection("services");
const bookings = database.collection("bookings");
const payments = database.collection("payments");

await services.createIndex({ approvalStatus: 1, isAvailable: 1, createdAt: -1 });
await services.createIndex({ technicianEmail: 1, createdAt: -1 });
await bookings.createIndex({ customerEmail: 1, createdAt: -1 });
await bookings.createIndex({ technicianEmail: 1, createdAt: -1 });
await bookings.createIndex({ serviceId: 1 });
// One active request per customer + service, enforced by the database itself (race-safe).
await bookings.createIndex(
  { activeKey: 1 },
  { unique: true, partialFilterExpression: { activeKey: { $type: "string" } } }
);
await payments.createIndex({ customerEmail: 1, paidAt: -1 });
// The same payment can never be saved twice, and a booking is paid at most once.
await payments.createIndex({ stripeSessionId: 1 }, { unique: true });
await payments.createIndex({ bookingId: 1 }, { unique: true });

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

//Services: public 

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


// Techncian Services
app.get(
  "/api/services/mine",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const records = await services
      .find({ technicianEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();
    return res.json(records.map(serializeDoc));
  })
);

app.get(
  "/api/services/:id",
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(404).json({ message: "Service not found." });

    const service = await services.findOne({ _id: id });
    if (!service || service.approvalStatus !== "approved" || !service.isAvailable) {
      return res.status(404).json({ message: "Service not found." });
    }

    const technician = await users.findOne(
      { email: service.technicianEmail },
      { projection: { name: 1, image: 1, area: 1, bio: 1 } }
    );
    const ratingMap = await getRatingMap([service._id.toString()]);

    return res.json({
      ...withRating(service, ratingMap),
      technician: {
        name: technician?.name ?? service.technicianName,
        image: technician?.image ?? null,
        area: technician?.area ?? "",
        bio: technician?.bio ?? "",
      },
    });
  })
);

app.post(
  "/api/services",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const { error, value } = validateServiceBody(req.body);
    if (error) return res.status(400).json({ message: error });

    const service = {
      ...value,
      technicianName: req.user.name,
      technicianEmail: req.user.email,
      approvalStatus: "pending",
      isAvailable: true,
      createdAt: new Date(),
    };
    const result = await services.insertOne(service);
    return res.status(201).json({ ...service, _id: result.insertedId.toString() });
  })
);

app.patch(
  "/api/services/:id",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid service ID is required." });

    const { error, value } = validateServiceBody(req.body);
    if (error) return res.status(400).json({ message: error });

    const existing = await services.findOne({ _id: id });
    if (!existing) return res.status(404).json({ message: "Service not found." });
    if (existing.technicianEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: this is not your service." });
    }

    // Any edit sends the listing back to the admin.
    await services.updateOne(
      { _id: id, technicianEmail: req.user.email },
      { $set: { ...value, approvalStatus: "pending", updatedAt: new Date() } }
    );
    return res.json(serializeDoc(await services.findOne({ _id: id })));
  })
);

app.patch(
  "/api/services/:id/availability",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid service ID is required." });
    if (typeof req.body?.isAvailable !== "boolean") {
      return res.status(400).json({ message: "isAvailable must be true or false." });
    }

    const result = await services.updateOne(
      { _id: id, technicianEmail: req.user.email },
      { $set: { isAvailable: req.body.isAvailable, updatedAt: new Date() } }
    );
    if (!result.matchedCount) {
      return res.status(404).json({ message: "Service not found." });
    }
    return res.json({ updated: true, isAvailable: req.body.isAvailable });
  })
);

app.delete(
  "/api/services/:id",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid service ID is required." });

    const result = await services.deleteOne({
      _id: id,
      technicianEmail: req.user.email,
    });
    if (!result.deletedCount) {
      return res.status(404).json({ message: "Service not found." });
    }
    return res.json({ deleted: true });
  })
);

// Customer booking related API

app.post(
  "/api/bookings",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    const body = req.body ?? {};
    const serviceId = toObjectId(body.serviceId);
    if (!serviceId) return res.status(400).json({ message: "A valid service is required." });

    const phone = String(body.customerPhone ?? "").trim();
    const address = String(body.address ?? "").trim();
    const problem = String(body.problemDescription ?? "").trim();
    const dateText = String(body.preferredDate ?? "");

    if (!/^[+\d][\d\s-]{5,}$/.test(phone)) {
      return res.status(400).json({ message: "Enter a valid phone number." });
    }
    if (address.length < 8) {
      return res.status(400).json({ message: "Enter the full service address." });
    }
    if (problem.length < 20) {
      return res
        .status(400)
        .json({ message: "Describe the problem in at least 20 characters." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateText)) {
      return res.status(400).json({ message: "Pick a valid preferred date." });
    }
    const preferredDate = new Date(`${dateText}T00:00:00.000Z`);
    // One day of tolerance so customers west of UTC can still pick "today".
    const earliest = Date.now() - 36 * 60 * 60 * 1000;
    if (Number.isNaN(preferredDate.getTime()) || preferredDate.getTime() < earliest) {
      return res.status(400).json({ message: "Preferred date must be today or later." });
    }

    const service = await services.findOne({ _id: serviceId });
    if (!service || service.approvalStatus !== "approved" || !service.isAvailable) {
      return res.status(404).json({ message: "This service is no longer available." });
    }
    if (service.technicianEmail === req.user.email) {
      return res
        .status(403)
        .json({ message: "You cannot request your own service." });
    }

    const now = new Date();
    const serviceKey = serviceId.toString();
    const booking = {
      serviceId: serviceKey,
      serviceTitle: service.title,
      serviceImage: service.image,
      category: service.category,
      basePrice: service.basePrice,
      technicianName: service.technicianName,
      technicianEmail: service.technicianEmail,
      customerName: req.user.name,
      customerEmail: req.user.email,
      customerPhone: phone,
      address,
      preferredDate,
      problemDescription: problem,
      status: "requested",
      finalAmount: service.basePrice,
      paymentStatus: "unpaid",
      statusHistory: [{ status: "requested", changedAt: now }],
      createdAt: now,
      // Unique while the job is active; removed when it ends. Blocks duplicates even under a race.
      activeKey: `${req.user.email}|${serviceKey}`,
    };

    try {
      const result = await bookings.insertOne(booking);
      return res
        .status(201)
        .json(serializeBooking({ ...booking, _id: result.insertedId }));
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({
          message: "You already have an active request for this service",
        });
      }
      throw err;
    }
  })
);

app.get(
  "/api/bookings/my",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    const records = await bookings
      .find({ customerEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();
    return res.json(records.map(serializeBooking));
  })
);

app.patch(
  "/api/bookings/:id/cancel",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid booking ID is required." });

    const now = new Date();
    const result = await bookings.updateOne(
      { _id: id, customerEmail: req.user.email, status: "requested" },
      {
        $set: { status: "cancelled", updatedAt: now },
        $push: { statusHistory: { status: "cancelled", changedAt: now } },
        $unset: { activeKey: "" },
      }
    );
    if (result.matchedCount) return res.json({ updated: true, status: "cancelled" });

    const booking = await bookings.findOne({ _id: id });
    if (!booking) return res.status(404).json({ message: "Booking not found." });
    if (booking.customerEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: this is not your booking." });
    }
    return res.status(409).json({
      message: "Only a request that is still waiting for the technician can be cancelled.",
    });
  })
);

app.post(
  "/api/bookings/:id/review",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid booking ID is required." });

    const rating = Number(req.body?.rating);
    const review = typeof req.body?.review === "string" ? req.body.review.trim() : "";
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ message: "Rating must be a whole number from 1 to 5." });
    }
    if (review.length > 300) {
      return res.status(400).json({ message: "Keep your review under 300 characters." });
    }

    const result = await bookings.updateOne(
      {
        _id: id,
        customerEmail: req.user.email,
        paymentStatus: "paid",
        rating: { $exists: false },
      },
      { $set: { rating, review, reviewedAt: new Date() } }
    );
    if (result.matchedCount) return res.json({ updated: true, rating, review });

    const booking = await bookings.findOne({ _id: id });
    if (!booking) return res.status(404).json({ message: "Booking not found." });
    if (booking.customerEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: this is not your booking." });
    }
    return res.status(409).json({
      message:
        booking.rating !== undefined
          ? "You have already reviewed this job."
          : "You can review a job after it has been paid.",
    });
  })
);


//Technician booking related API
app.get(
  "/api/bookings/technician",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const records = await bookings
      .find({ technicianEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();
    return res.json(records.map(serializeBooking));
  })
);

// The job pipeline. Anything not listed here is rejected.
const STATUS_TRANSITIONS = {
  requested: ["accepted", "rejected"],
  accepted: ["in-progress"],
  "in-progress": ["completed"],
};

app.patch(
  "/api/bookings/:id/status",
  verifyToken,
  verifyTechnician,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid booking ID is required." });

    const nextStatus = req.body?.status;
    if (typeof nextStatus !== "string") {
      return res.status(400).json({ message: "A new status is required." });
    }

    const booking = await bookings.findOne({ _id: id });
    if (!booking) return res.status(404).json({ message: "Booking not found." });
    if (booking.technicianEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: this is not your job." });
    }

    const allowed = STATUS_TRANSITIONS[booking.status] ?? [];
    if (!allowed.includes(nextStatus)) {
      return res.status(409).json({
        message: `A ${booking.status} job cannot be changed to ${nextStatus}.`,
      });
    }

    const now = new Date();
    const updates = { status: nextStatus, updatedAt: now };
    if (nextStatus === "completed") {
      const finalAmount = Number(req.body?.finalAmount);
      if (!Number.isFinite(finalAmount) || finalAmount <= 0 || finalAmount > 1000000) {
        return res
          .status(400)
          .json({ message: "Send a final amount greater than 0 to complete the job." });
      }
      updates.finalAmount = Math.round(finalAmount * 100) / 100;
    }

    const update = {
      $set: updates,
      $push: { statusHistory: { status: nextStatus, changedAt: now } },
    };
    // Only requested / accepted / in-progress count as "active" for duplicate checks.
    if (nextStatus === "rejected" || nextStatus === "completed") {
      update.$unset = { activeKey: "" };
    }

    // The status in the filter makes this safe if two requests arrive at once.
    const result = await bookings.updateOne(
      { _id: id, technicianEmail: req.user.email, status: booking.status },
      update
    );
    if (!result.matchedCount) {
      return res
        .status(409)
        .json({ message: "This job was just updated. Refresh and try again." });
    }

    return res.json(serializeBooking(await bookings.findOne({ _id: id })));
  })
);

// Payments
app.post(
  "/api/payments/create-checkout-session",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    if (!stripe) return res.status(503).json({ message: "Payments are not configured." });

    const bookingId = toObjectId(req.body?.bookingId);
    if (!bookingId) return res.status(400).json({ message: "A valid booking is required." });

    const booking = await bookings.findOne({ _id: bookingId });
    if (!booking) return res.status(404).json({ message: "Booking not found." });
    if (booking.customerEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: this is not your booking." });
    }
    if (booking.status !== "completed" || booking.paymentStatus !== "unpaid") {
      return res
        .status(409)
        .json({ message: "Only a completed, unpaid job can be paid." });
    }

    // The price comes from the database. The client never sends an amount.
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: req.user.email,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "usd",
            unit_amount: Math.round(booking.finalAmount * 100),
            product_data: {
              name: booking.serviceTitle,
              description: `Repair by ${booking.technicianName}`,
            },
          },
        },
      ],
      metadata: {
        bookingId: booking._id.toString(),
        customerEmail: req.user.email,
      },
      success_url: `${clientUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${clientUrl}/payment/cancel`,
    });

    return res.json({ url: session.url });
  })
);

app.get(
  "/api/payments/verify",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    if (!stripe) return res.status(503).json({ message: "Payments are not configured." });

    const sessionId = req.query.session_id;
    if (typeof sessionId !== "string" || !/^cs_(test|live)_[A-Za-z0-9]+$/.test(sessionId)) {
      return res.status(400).json({ message: "A valid Stripe session is required." });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ["payment_intent"],
    });
    if (session.metadata?.customerEmail !== req.user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: this payment belongs to another account." });
    }

    try {
      const payment = await fulfillCheckoutSession(session);
      return res.json({ payment: serializeDoc(payment) });
    } catch (err) {
      if (err.status) return res.status(err.status).json({ message: err.message });
      throw err;
    }
  })
);

app.get(
  "/api/payments/my",
  verifyToken,
  verifyCustomer,
  route(async (req, res) => {
    const records = await payments
      .find({ customerEmail: req.user.email })
      .sort({ paidAt: -1 })
      .toArray();
    return res.json(records.map(serializeDoc));
  })
);

/* ----Profile --- */
app.patch(
  "/api/users/profile",
  verifyToken,
  route(async (req, res) => {
    const body = req.body ?? {};
    const updates = {};

    if (body.name !== undefined) {
      if (!isNonEmptyString(body.name, 2)) {
        return res.status(400).json({ message: "Name is required." });
      }
      updates.name = body.name.trim();
    }
    for (const field of ["phone", "area"]) {
      if (body[field] !== undefined) {
        if (typeof body[field] !== "string" || body[field].length > 120) {
          return res.status(400).json({ message: `Invalid ${field}.` });
        }
        updates[field] = body[field].trim();
      }
    }
    if (body.bio !== undefined) {
      if (typeof body.bio !== "string" || body.bio.length > 400) {
        return res.status(400).json({ message: "Keep your bio under 400 characters." });
      }
      updates.bio = body.bio.trim();
    }
    if (body.image !== undefined) {
      if (typeof body.image !== "string" || !/^https?:\/\//i.test(body.image)) {
        return res.status(400).json({ message: "Invalid image URL." });
      }
      updates.image = body.image.trim();
    }
    if (!Object.keys(updates).length) {
      return res.status(400).json({ message: "Nothing to update." });
    }

    // role and email are never writable here.
    updates.updatedAt = new Date();
    await users.updateOne({ _id: new ObjectId(req.user.id) }, { $set: updates });
    const account = await users.findOne({ _id: new ObjectId(req.user.id) });
    return res.json(serializeUser(account));
  })
);


// Admin related API
app.get(
  "/api/admin/users",
  verifyToken,
  verifyAdmin,
  route(async (req, res) => {
    const records = await users.find({}).sort({ createdAt: -1 }).toArray();
    return res.json(records.map(serializeUser));
  })
);

app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  verifyAdmin,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid user ID is required." });
    if (!ROLES.includes(req.body?.role)) {
      return res.status(400).json({ message: "Role must be customer, technician or admin." });
    }
    if (id.toString() === req.user.id) {
      return res.status(403).json({ message: "You cannot change your own role." });
    }

    const result = await users.updateOne(
      { _id: id },
      { $set: { role: req.body.role, updatedAt: new Date() } }
    );
    if (!result.matchedCount) return res.status(404).json({ message: "User not found." });
    return res.json(serializeUser(await users.findOne({ _id: id })));
  })
);

app.get(
  "/api/admin/services",
  verifyToken,
  verifyAdmin,
  route(async (req, res) => {
    const filter = {};
    if (["pending", "approved", "rejected"].includes(req.query.approvalStatus)) {
      filter.approvalStatus = req.query.approvalStatus;
    }
    const records = await services.find(filter).sort({ createdAt: -1 }).toArray();
    return res.json(records.map(serializeDoc));
  })
);

app.patch(
  "/api/admin/services/:id/approval",
  verifyToken,
  verifyAdmin,
  route(async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "A valid service ID is required." });
    const { approvalStatus } = req.body ?? {};
    if (approvalStatus !== "approved" && approvalStatus !== "rejected") {
      return res.status(400).json({ message: "Status must be approved or rejected." });
    }

    const result = await services.updateOne(
      { _id: id },
      { $set: { approvalStatus, reviewedAt: new Date() } }
    );
    if (!result.matchedCount) return res.status(404).json({ message: "Service not found." });
    return res.json({ updated: true, approvalStatus });
  })
);

app.get(
  "/api/admin/bookings",
  verifyToken,
  verifyAdmin,
  route(async (req, res) => {
    const filter = {};
    if (
      ["requested", "accepted", "rejected", "in-progress", "completed", "cancelled"].includes(
        req.query.status
      )
    ) {
      filter.status = req.query.status;
    }
    const records = await bookings.find(filter).sort({ createdAt: -1 }).toArray();
    return res.json(records.map(serializeBooking));
  })
);

app.get(
  "/api/admin/payments",
  verifyToken,
  verifyAdmin,
  route(async (req, res) => {
    const records = await payments.find({}).sort({ paidAt: -1 }).toArray();
    return res.json(records.map(serializeDoc));
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