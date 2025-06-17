const express = require("express");
const body = require("body-parser");
const { MongoClient } = require("mongodb");
const mongoSanitize = require("express-mongo-sanitize");

const app = express();
app.use(body.json());          // <-- keep it first
// app.use(mongoSanitize());   // uncomment later to patch the bug 👈

const uri = "mongodb://localhost:27017";
const client = new MongoClient(uri, { useUnifiedTopology: true });

let users;                     // collection handle

(async () => {
  await client.connect();
  const db = client.db("demo");
  users = db.collection("users");

  // reset DB every boot for a clean demo
  await users.deleteMany({});
  await users.insertOne({
    email: "victim@example.com",
    password: "Secret123",
    role: "admin",
    resetPassToken: "abc123"
  });

  app.listen(3000, () => console.log("⚡ Demo API on :3000"));
})();

// Vulnerable login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await users.findOne({ email, password });
  return user ? res.json({ ok: true, user }) :
                res.status(401).json({ ok: false });
});

// Vulnerable reset-password
app.post("/reset", async (req, res) => {
  const { token, password } = req.body;
  const user = await users.findOne({ resetPassToken: token });

  if (!password)               // just token validation phase
    return res.json({ valid: !!user });

  if (!user) return res.status(404).json({ msg: "token bad" });

  await users.updateOne(
    { _id: user._id },
    { $set: { password }, $unset: { resetPassToken: "" } }
  );
  res.json({ msg: "password changed" });
});
