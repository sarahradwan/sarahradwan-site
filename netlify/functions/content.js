const { createHmac, createHash, timingSafeEqual } = require("crypto");

const COOKIE = "sara_admin";
const CONTENT_PUBLIC_ID = "sara-radwan/cms-content";

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

async function readContent() {
  const { CLOUDINARY_CLOUD_NAME } = process.env;
  if (!CLOUDINARY_CLOUD_NAME) return null;
  try {
    const url = `https://res.cloudinary.com/${CLOUDINARY_CLOUD_NAME}/raw/upload/${CONTENT_PUBLIC_ID}?t=${Date.now()}`;
    const res = await fetch(url);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function writeContent(data) {
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET } = process.env;
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    throw new Error("Cloudinary credentials not configured in Netlify environment variables.");
  }

  const jsonString = JSON.stringify(data);
  const timestamp = Math.round(Date.now() / 1000);
  const publicId = CONTENT_PUBLIC_ID;

  const paramsToSign = `overwrite=true&public_id=${publicId}&timestamp=${timestamp}`;
  const signature = createHash("sha1")
    .update(paramsToSign + CLOUDINARY_API_SECRET)
    .digest("hex");

  const boundary = `----FormBoundary${timestamp}`;
  const field = (name, value) =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;

  const parts = [
    Buffer.from(field("api_key", CLOUDINARY_API_KEY)),
    Buffer.from(field("timestamp", String(timestamp))),
    Buffer.from(field("public_id", publicId)),
    Buffer.from(field("overwrite", "true")),
    Buffer.from(field("signature", signature)),
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="content.json"\r\nContent-Type: application/json\r\n\r\n`
    ),
    Buffer.from(jsonString),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ];

  const body = Buffer.concat(parts);

  const res = await fetch(
    `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/raw/upload`,
    {
      method: "POST",
      headers: {
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
        "Content-Length": String(body.byteLength),
      },
      body,
    }
  );

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Cloudinary save failed (${res.status})`);
  }
}

exports.handler = async function (event) {
  // GET — load content (public)
  if (event.httpMethod === "GET") {
    try {
      const data = await readContent();
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
      await writeContent(data);
      return { statusCode: 200, body: JSON.stringify({ success: true }) };
    } catch (err) {
      return { statusCode: 500, body: JSON.stringify({ message: err.message }) };
    }
  }

  return { statusCode: 405, body: JSON.stringify({ message: "Method not allowed" }) };
};
