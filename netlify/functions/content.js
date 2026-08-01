const { createHmac, createHash, timingSafeEqual } = require("crypto");

const COOKIE = "sara_admin";
// For raw files Cloudinary treats the extension as part of the public_id —
// it appended ".json" on upload, so the read must look for the same name.
const CONTENT_PUBLIC_ID = "sara-radwan/cms-content.json";

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

// Returns { data, trace }. The trace records every step; it is kept for
// server-side diagnosis but is never sent to the browser, so a failure here
// simply yields null and the site falls back to its built-in defaults.
async function readContent() {
  const trace = [];
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET } = process.env;

  trace.push({
    step: "env",
    cloudName: CLOUDINARY_CLOUD_NAME || "MISSING",
    apiKeySet: Boolean(CLOUDINARY_API_KEY),
    apiSecretSet: Boolean(CLOUDINARY_API_SECRET),
  });

  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    trace.push({ step: "abort", reason: "Cloudinary env vars missing in Netlify" });
    return { data: null, trace };
  }

  const creds = Buffer.from(`${CLOUDINARY_API_KEY}:${CLOUDINARY_API_SECRET}`).toString("base64");

  // Step 1 — Admin API lookup for the resource's versioned URL.
  let secureUrl;
  try {
    const metaUrl = `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/resources/raw/upload?public_ids[]=${encodeURIComponent(CONTENT_PUBLIC_ID)}`;
    const metaRes = await fetch(metaUrl, { headers: { Authorization: `Basic ${creds}` } });
    const metaBody = await metaRes.text();

    trace.push({
      step: "adminApi",
      status: metaRes.status,
      body: metaBody.slice(0, 400),
    });

    if (!metaRes.ok) return { data: null, trace };

    const parsed = JSON.parse(metaBody);
    if (!parsed.resources || parsed.resources.length === 0) {
      trace.push({ step: "abort", reason: `No resource found with public_id "${CONTENT_PUBLIC_ID}" — nothing has been published yet, or it was saved under a different name.` });
      // List what raw files DO exist, so a name mismatch is visible.
      try {
        const listRes = await fetch(
          `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/resources/raw?max_results=50`,
          { headers: { Authorization: `Basic ${creds}` } }
        );
        const listBody = await listRes.json();
        trace.push({
          step: "listAllRawFiles",
          status: listRes.status,
          found: (listBody.resources || []).map(r => r.public_id),
        });
      } catch (err) {
        trace.push({ step: "listAllRawFiles", error: err.message });
      }
      return { data: null, trace };
    }
    secureUrl = parsed.resources[0].secure_url;
    trace.push({ step: "resolvedUrl", secureUrl });
  } catch (err) {
    trace.push({ step: "adminApi", error: err.message });
    return { data: null, trace };
  }

  // Step 2 — fetch the JSON from the versioned URL (never CDN-stale).
  try {
    const fileRes = await fetch(secureUrl);
    const fileBody = await fileRes.text();
    trace.push({ step: "fetchFile", status: fileRes.status, bytes: fileBody.length });

    if (!fileRes.ok) return { data: null, trace };

    const data = JSON.parse(fileBody);
    trace.push({ step: "parsed", projectCount: data?.projects?.length ?? "n/a" });
    return { data, trace };
  } catch (err) {
    trace.push({ step: "fetchFile", error: err.message });
    return { data: null, trace };
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

  const resBody = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(resBody.error?.message || `Cloudinary save failed (${res.status})`);
  }
  // Return what Cloudinary actually stored, so callers can verify the public_id.
  return { storedPublicId: resBody.public_id, url: resBody.secure_url, bytes: resBody.bytes };
}

// ── Asset URL normalisation, applied as content is served ────────────────────
//
// Both fixes below are done here rather than in the stored content so they
// apply to everything already saved AND to anything uploaded from now on,
// without anyone having to remember.

// A bare filename as saved by the editor, e.g. "education-spread.jpg".
const BARE_FILENAME = /^[A-Za-z0-9._-]+\.(jpe?g|png|svg|webp|gif)$/i;

// A Cloudinary delivery URL: prefix + everything after /upload/.
const CLOUDINARY_UPLOAD = /^(https:\/\/res\.cloudinary\.com\/[^/]+\/image\/upload\/)(.+)$/;

// f_auto picks WebP/AVIF per browser, q_auto compresses, w_1600 caps the width
// at roughly twice the largest slot the design ever renders.
const DELIVERY = "f_auto,q_auto,w_1600";

function normaliseAsset(value) {
  if (typeof value !== "string" || !value) return value;

  // A bare filename resolves against the current route (/project/<id>/<file>)
  // and 404s. Everything shipped with the site lives under /media/.
  if (BARE_FILENAME.test(value)) return "/media/" + value;

  const m = value.match(CLOUDINARY_UPLOAD);
  if (!m) return value;
  const rest = m[2];

  // Never transform a PDF. Cloudinary responds to a delivery transform on a
  // .pdf by flattening it to a single image, which breaks the page-by-page
  // document viewer that reads these URLs.
  if (/\.pdf(\?|$)/i.test(rest)) return value;

  // Anything not starting with a version segment already carries a
  // transformation, so leave it exactly as it is.
  if (!/^v\d+\//.test(rest)) return value;

  return m[1] + DELIVERY + "/" + rest;
}

function normaliseAssets(node) {
  if (typeof node === "string") return normaliseAsset(node);
  if (Array.isArray(node)) return node.map(normaliseAssets);
  if (node && typeof node === "object") {
    const out = {};
    for (const key of Object.keys(node)) out[key] = normaliseAssets(node[key]);
    return out;
  }
  return node;
}

exports.handler = async function (event) {
  // GET — load content (public).
  if (event.httpMethod === "GET") {
    // The editor must never be served a cached copy: publishing and then
    // reloading /admin within the cache window would load stale content and
    // silently revert the edit on the next save.
    const isEditor = isAuthenticated(event);
    try {
      const { data } = await readContent();

      return {
        statusCode: 200,
        headers: {
          "Content-Type": "application/json",
          // Visitors are served from the CDN for a minute, which keeps the
          // Cloudinary Admin API off the hot path under traffic. Published
          // changes go live within 60 seconds.
          "Cache-Control": isEditor
            ? "no-store"
            : "public, max-age=0, s-maxage=60",
          Vary: "Cookie",
        },
        body: JSON.stringify(data ? normaliseAssets(data) : null),
      };
    } catch {
      // The site renders its built-in defaults when content is null, so a
      // failure here degrades rather than breaking the page.
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
        body: "null",
      };
    }
  }

  // PUT — save content (admin only)
  if (event.httpMethod === "PUT") {
    if (!isAuthenticated(event)) {
      return { statusCode: 401, body: JSON.stringify({ message: "Unauthorized" }) };
    }
    try {
      const data = JSON.parse(event.body);
      const stored = await writeContent(data);
      return { statusCode: 200, body: JSON.stringify({ success: true, ...stored }) };
    } catch (err) {
      return { statusCode: 500, body: JSON.stringify({ message: err.message }) };
    }
  }

  return { statusCode: 405, body: JSON.stringify({ message: "Method not allowed" }) };
};
