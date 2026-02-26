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
  const licenseKey = String(req.query.key || "").trim();
  const scriptName = String(req.query.script || "").trim();

  if (!licenseKey) {
    return res.status(400).json({ status: "failed" });
  }

  const clientIp = getClientIp(req);

  try {
    let query = "SELECT allowed_ip FROM licenses WHERE license_key = ?";
    const params = [licenseKey];

    // Backward-compatible: if script is provided, filter by script_name too.
    if (scriptName) {
      query += " AND script_name = ?";
      params.push(scriptName);
    }

    const [rows] = await pool.execute(query, params);
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