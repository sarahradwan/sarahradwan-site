const { createHmac, timingSafeEqual } = require("crypto");

const COOKIE = "sara_admin";

function getCookie(header, name) {
  if (!header) return null;
  const m = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}

function verifyToken(token, secret) {
  try {
    const raw = Buffer.from(token, "base64url").toString("utf8");
    const parts = raw.split("|");
    if (parts.length !== 4) return null;
    const [email, expiresStr, nonce, sig] = parts;
    if (Date.now() > parseInt(expiresStr, 10)) return null;
    const payload = `${email}|${expiresStr}|${nonce}`;
    const expected = createHmac("sha256", secret).update(payload).digest("hex");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return null;
    if (!timingSafeEqual(a, b)) return null;
    return email;
  } catch {
    return null;
  }
}

exports.handler = async function (event) {
  const { SESSION_SECRET } = process.env;
  if (!SESSION_SECRET) return { statusCode: 200, body: JSON.stringify({ authenticated: false }) };

  const token = getCookie(event.headers.cookie, COOKIE);
  if (!token) return { statusCode: 200, body: JSON.stringify({ authenticated: false }) };

  const email = verifyToken(token, SESSION_SECRET);
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ authenticated: Boolean(email), email: email || "" }),
  };
};
