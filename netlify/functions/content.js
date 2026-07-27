const { createHmac, timingSafeEqual } = require("crypto");
const { getStore } = require("@netlify/blobs");

const COOKIE = "sara_admin";
const STORE_NAME = "sara-content";
const CONTENT_KEY = "content";

function getCookie(header, name) {
  if (!header) return null;
  const m = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}

function isAuthenticated(event) {
  const { SESSION_SECRET } = process.env;
  if (!SESSION_SECRET) return false;
  const token = getCookie(event.headers.cookie, COOKIE);
  if (!token) return false;
  try {
    const raw = Buffer.from(token, "base64url").toString("utf8");
    const parts = raw.split("|");
    if (parts.length !== 4) return false;
    const [email, expiresStr, nonce, sig] = parts;
    if (Date.now() > parseInt(expiresStr, 10)) return false;
    const payload = `${email}|${expiresStr}|${nonce}`;
    const expected = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch { return false; }
}

exports.handler = async function (event) {
  const store = getStore({ name: STORE_NAME, consistency: "strong" });

  // GET — load content (public, no auth needed)
  if (event.httpMethod === "GET") {
    try {
      const data = await store.get(CONTENT_KEY, { type: "json" });
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data || null),
      };
    } catch {
      return { statusCode: 200, headers: { "Content-Type": "application/json" }, body: "null" };
    }
  }

  // PUT — save content (admin only)
  if (event.httpMethod === "PUT") {
    if (!isAuthenticated(event)) {
      return { statusCode: 401, body: JSON.stringify({ message: "Unauthorized" }) };
    }
    try {
      const data = JSON.parse(event.body);
      await store.setJSON(CONTENT_KEY, data);
      return { statusCode: 200, body: JSON.stringify({ success: true }) };
    } catch (err) {
      return { statusCode: 500, body: JSON.stringify({ message: err.message }) };
    }
  }

  return { statusCode: 405, body: JSON.stringify({ message: "Method not allowed" }) };
};
