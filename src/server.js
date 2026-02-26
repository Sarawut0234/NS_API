require("dotenv").config();
const express = require("express");
const pool = require("./db");

const app = express();
const port = Number(process.env.PORT) || 3000;

app.set("trust proxy", true);

function normalizeIp(ip) {
  if (!ip) return "";
  return String(ip).trim().replace(/^::ffff:/, "");
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    const [firstIp] = forwarded.split(",");
    return normalizeIp(firstIp);
  }

  return normalizeIp(req.ip || req.socket?.remoteAddress || "");
}

app.get("/verify", async (req, res) => {
  const licenseKey = req.query.key;
  const scriptName = req.query.script;

  if (!licenseKey || !scriptName) {
    return res.status(400).json({ status: "failed" });
  }

  const clientIp = getClientIp(req);

  try {
    const [rows] = await pool.execute(
      "SELECT allowed_ip FROM licenses WHERE license_key = ? AND script_name = ?",
      [licenseKey, scriptName]
    );

    const matched = rows.some((row) => normalizeIp(row.allowed_ip) === clientIp);

    return res.json({ status: matched ? "success" : "failed" });
  } catch (error) {
    console.error("Database error:", error.message);
    return res.status(500).json({ status: "failed" });
  }
});

app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});