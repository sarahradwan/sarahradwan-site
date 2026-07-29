const { createHash } = require("crypto");

const VERSION = "pdf-v1";
const MAX_INLINE_BYTES = 4 * 1024 * 1024; // Netlify caps function responses at 6 MB; base64 adds ~33%

/* Cloudinary blocks PDF delivery on most accounts, returning 401 for the plain
   delivery URL. Signed delivery URLs are exempt, so this function signs the URL
   server-side, fetches the file, and returns the bytes from this domain.

   Serving from this domain also sidesteps the site's Content-Security-Policy:
   framing res.cloudinary.com directly is cross-origin and blocked unless
   frame-src lists it, whereas a function response is same-origin. */

function signedUrl(cloudName, apiSecret, resourceType, deliveryType, version, publicIdWithExt) {
  // Cloudinary signs "<transformation>/<public_id>.<ext>" — no transformation
  // here, and the version is not part of the signed string.
  const toSign = publicIdWithExt;
  const digest = createHash("sha1").update(toSign + apiSecret).digest("base64");
  const sig = digest.replace(/\+/g, "-").replace(/\//g, "_").substring(0, 8);
  const versionSegment = version ? `${version}/` : "";
  return `https://res.cloudinary.com/${cloudName}/${resourceType}/${deliveryType}/s--${sig}--/${versionSegment}${publicIdWithExt}`;
}

/* Parses a Cloudinary delivery URL into the parts needed to re-sign it.
   Only URLs belonging to the configured cloud are accepted, so this cannot be
   used as an open proxy for arbitrary hosts. */
function parseCloudinaryUrl(raw, cloudName) {
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.hostname !== "res.cloudinary.com") return null;

  const parts = u.pathname.replace(/^\//, "").split("/");
  if (parts.shift() !== cloudName) return null;

  const resourceType = parts.shift();   // image | raw
  const deliveryType = parts.shift();   // upload
  if (!resourceType || !deliveryType) return null;
  if (!["image", "raw"].includes(resourceType)) return null;
  if (deliveryType !== "upload") return null;

  // Drop any existing signature, then lift the version out.
  if (parts[0] && /^s--[^-]+--$/.test(parts[0])) parts.shift();
  let version = null;
  if (parts[0] && /^v\d+$/.test(parts[0])) version = parts.shift();

  const publicIdWithExt = parts.join("/");
  if (!publicIdWithExt.toLowerCase().endsWith(".pdf")) return null;

  return { resourceType, deliveryType, version, publicIdWithExt };
}

exports.handler = async function (event) {
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_SECRET } = process.env;
  const params = event.queryStringParameters || {};
  const debug = params.debug === "1";

  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_SECRET) {
    return json(500, { version: VERSION, error: "Cloudinary environment variables are not set" });
  }

  const raw = params.u ? decodeURIComponent(params.u) : "";
  if (!raw) return json(400, { version: VERSION, error: "Missing ?u= parameter" });

  const parsed = parseCloudinaryUrl(raw, CLOUDINARY_CLOUD_NAME);
  if (!parsed) {
    return json(400, {
      version: VERSION,
      error: "Not a PDF delivery URL for this Cloudinary account",
      received: raw,
    });
  }

  const signed = signedUrl(
    CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_SECRET,
    parsed.resourceType, parsed.deliveryType, parsed.version, parsed.publicIdWithExt
  );

  // Try the signed URL first, then the plain one — whichever the account allows.
  const attempts = [{ label: "signed", url: signed }, { label: "plain", url: raw }];
  const tried = [];

  for (const attempt of attempts) {
    let res;
    try {
      res = await fetch(attempt.url);
    } catch (err) {
      tried.push({ ...attempt, error: err.message });
      continue;
    }

    const length = Number(res.headers.get("content-length") || 0);
    tried.push({
      label: attempt.label,
      status: res.status,
      contentType: res.headers.get("content-type"),
      bytes: length || null,
    });

    if (!res.ok) continue;

    if (debug) continue; // in debug mode report every attempt, stream nothing

    if (length && length > MAX_INLINE_BYTES) {
      return {
        statusCode: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
        body: tooLargePage(attempt.url, length),
      };
    }

    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > MAX_INLINE_BYTES) {
      return {
        statusCode: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
        body: tooLargePage(attempt.url, buf.byteLength),
      };
    }

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": "inline",
        "Cache-Control": "public, max-age=3600",
      },
      body: buf.toString("base64"),
      isBase64Encoded: true,
    };
  }

  return json(debug ? 200 : 502, {
    version: VERSION,
    signedUrl: debug ? signed : undefined,
    publicId: debug ? parsed.publicIdWithExt : undefined,
    attempts: tried,
    hint: debug
      ? undefined
      : "Cloudinary refused both the signed and the plain URL for this PDF.",
  });
};

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(obj, null, 2),
  };
}

function tooLargePage(url, bytes) {
  const mb = (bytes / (1024 * 1024)).toFixed(1);
  return `<!doctype html><meta charset="utf-8">
<style>body{font-family:'DM Sans',Helvetica,Arial,sans-serif;background:#F7F4EF;color:#111;
display:grid;place-items:center;height:100vh;margin:0;text-align:center;padding:24px}
a{display:inline-block;margin-top:18px;padding:14px 22px;background:#111;color:#fff;
text-decoration:none;font-size:12px;letter-spacing:.16em;text-transform:uppercase}</style>
<div><p>This document is ${mb} MB — too large to display inline.</p>
<a href="${url}" target="_blank" rel="noreferrer">Open the PDF &#8599;</a></div>`;
}
