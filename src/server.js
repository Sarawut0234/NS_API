require("dotenv").config();
const express = require("express");
const pool = require("./db");

const app = express();
const port = Number(process.env.PORT) || 3000;

app.set("trust proxy", true);

function normalizeIp(ip) {
  if (!ip) return "";

  let value = String(ip).trim();
  value = value.replace(/^::ffff:/i, "");

  // Strip :port from IPv4 if present (e.g. 1.2.3.4:12345)
  const hostWithPort = value.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d+)$/);
  if (hostWithPort) {
    value = hostWithPort[1];
  }

  return value;
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
    return res.status(400).json({ status: "failed", reason: "missing_key" });
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

    if (!rows.length) {
      return res.json({ status: "failed", reason: "license_not_found" });
    }

    const matched = rows.some((row) => {
      const allowed = normalizeIp(row.allowed_ip);
      return allowed === "*" || allowed === clientIp;
    });

    if (!matched) {
      return res.json({
        status: "failed",
        reason: "ip_mismatch",
        client_ip: clientIp
      });
    }

    return res.json({ status: "success" });
  } catch (error) {
    console.error("Database error:", error.message);
    return res.status(500).json({ status: "failed", reason: "server_error" });
  }
});

app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});