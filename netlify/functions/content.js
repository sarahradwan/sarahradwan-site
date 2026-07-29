const { createHmac, createHash, timingSafeEqual } = require("crypto");

const VERSION = "v11"; // bump on every change — shown in ?debug=1 so we know what's live
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

// Returns { data, trace } — trace records every step so failures are visible
// via /.netlify/functions/content?debug=1 instead of silently becoming null.
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

/* Reports, for every project PDF, the stored URL, what Cloudinary returns for
   it directly, and what this site returns for the /cdn-pdf/ proxy path the
   inline viewer actually loads. Distinguishes a missing/blocked asset from a
   broken proxy rule without guessing. */
async function inspectPdfs(data, event) {
  const host = event.headers["x-forwarded-host"] || event.headers.host;
  const proto = (event.headers["x-forwarded-proto"] || "https").split(",")[0];
  const projects = (data && data.projects) || [];

  const withPdf = projects.filter((p) => p.pdf);
  const report = {
    version: VERSION,
    siteHost: host,
    projectCount: projects.length,
    projectsWithPdf: withPdf.length,
    cdnPdfRuleDeployed: null,
    pdfs: [],
  };

  // Does the /cdn-pdf/* rewrite exist at all? If netlify.toml was not
  // deployed, the SPA catch-all answers with the site's HTML instead.
  try {
    const probe = await fetch(`${proto}://${host}/cdn-pdf/__probe__.pdf`);
    const ctype = probe.headers.get("content-type") || "";
    report.cdnPdfRuleDeployed = {
      status: probe.status,
      contentType: ctype,
      verdict: ctype.includes("text/html")
        ? "NOT DEPLOYED — the SPA fallback answered, so netlify.toml is missing the /cdn-pdf/* rule"
        : "rule appears to be in place (upstream answered, not the SPA fallback)",
    };
  } catch (err) {
    report.cdnPdfRuleDeployed = { error: err.message };
  }

  for (const p of withPdf) {
    const entry = { id: p.id, storedUrl: p.pdf };

    try {
      const direct = await fetch(p.pdf);
      entry.direct = {
        status: direct.status,
        contentType: direct.headers.get("content-type"),
        bytes: direct.headers.get("content-length"),
      };
    } catch (err) {
      entry.direct = { error: err.message };
    }

    const proxyPath = p.pdf.replace(/^https?:\/\/res\.cloudinary\.com\/[^/]+\//, "/cdn-pdf/");
    entry.proxyPath = proxyPath;
    entry.rewriteApplied = proxyPath !== p.pdf;

    if (entry.rewriteApplied) {
      try {
        const viaProxy = await fetch(`${proto}://${host}${proxyPath}`);
        const ctype = viaProxy.headers.get("content-type") || "";
        entry.viaProxy = {
          status: viaProxy.status,
          contentType: ctype,
          servedSpaFallback: ctype.includes("text/html"),
        };
      } catch (err) {
        entry.viaProxy = { error: err.message };
      }
    } else {
      entry.viaProxy = { skipped: "stored URL is not a res.cloudinary.com URL" };
    }

    report.pdfs.push(entry);
  }

  if (!withPdf.length) {
    report.note = "No project has a pdf value saved. Upload a PDF in the editor and press Publish first.";
  }
  return report;
}

exports.handler = async function (event) {
  // GET — load content (public).
  //   ?debug=1   → returns the read diagnostic trace
  //   ?debug=2   → additionally runs a write self-test (only if no content exists yet)
  //   ?debug=pdf → reports stored PDF URLs and how they resolve
  if (event.httpMethod === "GET") {
    const debug = event.queryStringParameters?.debug;
    try {
      const { data, trace } = await readContent();

      if (debug === "pdf") {
        return {
          statusCode: 200,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(await inspectPdfs(data, event), null, 2),
        };
      }

      if (debug === "2") {
        const selftest = {};
        if (data !== null) {
          selftest.skipped = "Content already exists — write test skipped so it isn't overwritten.";
        } else {
          try {
            selftest.write = await writeContent({ __selftest: true, savedAt: new Date().toISOString() });
            const recheck = await readContent();
            selftest.readBack = { hasData: recheck.data !== null, trace: recheck.trace };
          } catch (err) {
            selftest.writeError = err.message;
          }
        }
        return {
          statusCode: 200,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ version: VERSION, trace, hasData: data !== null, selftest }),
        };
      }

      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(debug === "1" ? { version: VERSION, trace, hasData: data !== null } : (data || null)),
      };
    } catch (err) {
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: debug ? JSON.stringify({ version: VERSION, fatal: err.message }) : "null",
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
