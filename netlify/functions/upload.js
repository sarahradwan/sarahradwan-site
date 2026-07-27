const { createHmac, createHash, timingSafeEqual } = require("crypto");

const COOKIE = "sara_admin";
const MAX_BYTES = 4 * 1024 * 1024; // 4 MB

// ── Session verification ──────────────────────────────────────────────────────

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

// ── Cloudinary upload ─────────────────────────────────────────────────────────

async function uploadToCloudinary(buffer, contentType, fileName) {
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET } = process.env;

  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    throw new Error(
      "Images cannot be saved yet. Please add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET to your Netlify environment variables."
    );
  }

  const timestamp = Math.round(Date.now() / 1000);
  const folder = "sara-radwan";
  const baseName = fileName.replace(/\.[^.]+$/, "").replace(/[^a-z0-9_-]/gi, "_");
  const publicId = `${folder}/${baseName}_${timestamp}`;

  // Signed upload — no preset needed
  const paramsToSign = `folder=${folder}&public_id=${publicId}&timestamp=${timestamp}`;
  const signature = createHash("sha1")
    .update(paramsToSign + CLOUDINARY_API_SECRET)
    .digest("hex");

  // Build multipart form
  const boundary = `----FormBoundary${Date.now().toString(16)}`;
  const parts = [];

  const field = (name, value) =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;

  parts.push(Buffer.from(field("api_key", CLOUDINARY_API_KEY)));
  parts.push(Buffer.from(field("timestamp", String(timestamp))));
  parts.push(Buffer.from(field("public_id", publicId)));
  parts.push(Buffer.from(field("folder", folder)));
  parts.push(Buffer.from(field("signature", signature)));
  parts.push(
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: ${contentType}\r\n\r\n`
    )
  );
  parts.push(buffer);
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));

  const body = Buffer.concat(parts);

  const res = await fetch(
    `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`,
    {
      method: "POST",
      headers: {
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
        "Content-Length": String(body.byteLength),
      },
      body,
    }
  );

  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || "Cloudinary upload failed");
  return data.secure_url; // permanent HTTPS URL, never expires
}

// ── Handler ───────────────────────────────────────────────────────────────────

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: JSON.stringify({ message: "Method not allowed" }) };
  }

  if (!isAuthenticated(event)) {
    return { statusCode: 401, body: JSON.stringify({ message: "Unauthorized" }) };
  }

  const contentType = event.headers["content-type"] || "image/jpeg";
  const rawName = event.headers["x-file-name"];
  const fileName = rawName ? decodeURIComponent(rawName) : "photo.jpg";

  const buffer = Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8");

  if (buffer.byteLength > MAX_BYTES) {
    return {
      statusCode: 400,
      body: JSON.stringify({ message: `${fileName} is larger than 4 MB` }),
    };
  }

  try {
    const url = await uploadToCloudinary(buffer, contentType, fileName);
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ message: err.message }) };
  }
};
