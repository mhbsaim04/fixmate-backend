import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";

const app = express();
const port = process.env.PORT || 5000;

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