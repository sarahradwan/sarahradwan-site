const { createHmac, randomBytes, timingSafeEqual } = require("crypto");

const COOKIE = "sara_admin";
const MAX_AGE = 7 * 24 * 60 * 60; // 7 days in seconds

function makeToken(email, secret) {
  const expires = Date.now() + MAX_AGE * 1000;
  const nonce = randomBytes(12).toString("hex");
  const payload = `${email}|${expires}|${nonce}`;
  const sig = createHmac("sha256", secret).update(payload).digest("hex");
  return Buffer.from(`${payload}|${sig}`).toString("base64url");
}

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: JSON.stringify({ message: "Method not allowed" }) };
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return { statusCode: 400, body: JSON.stringify({ message: "Bad request" }) }; }

  const { email, password } = body;
  const { ADMIN_EMAIL, ADMIN_PASSWORD, SESSION_SECRET } = process.env;

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !SESSION_SECRET) {
    return { statusCode: 500, body: JSON.stringify({ message: "Server not configured — please set ADMIN_EMAIL, ADMIN_PASSWORD and SESSION_SECRET in Netlify environment variables" }) };
  }

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return { statusCode: 401, body: JSON.stringify({ message: "Invalid email or password" }) };
  }

  const token = makeToken(email, SESSION_SECRET);

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${MAX_AGE}; Path=/`,
    },
    body: JSON.stringify({ success: true, email }),
  };
};
