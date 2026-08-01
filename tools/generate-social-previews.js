#!/usr/bin/env node
/*
 * Generates one static HTML file per route so that link previews are correct.
 *
 * Why this exists
 * ---------------
 * The site is a client-rendered single page app. It updates the tab title and
 * canonical link after React boots, but LinkedIn, WhatsApp, Slack, iMessage and
 * Twitter never run JavaScript: they read the HTML exactly as the server sends
 * it. That HTML is the same index.html for every URL, so every project link
 * previewed as the generic homepage.
 *
 * How it works
 * ------------
 * Each generated file is a byte-for-byte copy of dist/index.html with only the
 * <title>, description, canonical and og:/twitter: tags swapped. Netlify serves
 * a matching static file in preference to the SPA catch-all, so /project/act-air
 * is answered by dist/project/act-air.html. React then boots from the same
 * bundle and takes over as usual, so nothing about the live site changes for a
 * human visitor.
 *
 * This is deliberately build-time rather than an edge function: it adds no
 * runtime code in front of every request, so it cannot take the site down.
 *
 * Run it after adding or renaming a project:
 *     node tools/generate-social-previews.js
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const TEMPLATE = path.join(DIST, "index.html");
const ORIGIN = "https://sarahradwan.me";
const CONTENT_URL = `${ORIGIN}/.netlify/functions/content`;
const DEFAULT_IMAGE = `${ORIGIN}/media/og-image.jpg`;

// Static routes. Titles mirror the labels used in the site's own navigation.
const PAGES = [
  { route: "/about",        title: "About",              description: "Twenty-two years, four languages, one discipline. Creative leadership across brand systems, institutional communications and publishing." },
  { route: "/case-studies", title: "Case Studies",       description: "Selected work for government, institutional, commercial and cultural clients across the UAE, GCC and Europe." },
  { route: "/portfolio",    title: "Areas of Leadership", description: "Government, institutional, commercial and cultural work, presented as evidence of judgement, scale and craft." },
  { route: "/ai",           title: "AI & Innovation",    description: "AI-integrated creative production: where machine capability meets art direction, and what that changes about the work." },
  { route: "/contact",      title: "Contact",            description: "Enquiries about creative direction, brand systems, institutional communications and publishing." },
];

// ── helpers ──────────────────────────────────────────────────────────────────

/** Escapes a value for safe use inside a double-quoted HTML attribute. */
function attr(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Trims to a whole word near the limit, as previews truncate mid-word badly. */
function summarise(text, limit = 200) {
  const clean = String(text || "").replace(/\s+/g, " ").trim();
  if (clean.length <= limit) return clean;
  const cut = clean.slice(0, limit);
  return cut.slice(0, cut.lastIndexOf(" ")).replace(/[,;:.]$/, "") + "…";
}

/**
 * Social cards want a predictable landscape image. Cloudinary can produce one
 * on the fly; anything already local is made absolute and used as-is.
 */
function socialImage(src) {
  if (!src) return DEFAULT_IMAGE;
  if (src.startsWith("/")) return ORIGIN + src;

  const m = src.match(/^(https:\/\/res\.cloudinary\.com\/[^/]+\/image\/upload\/)(.+?)(\.[a-z0-9]+)?$/i);
  if (!m) return src;
  // Never point a preview at a PDF, and strip any existing transformation.
  if (/\.pdf$/i.test(src)) return DEFAULT_IMAGE;
  const rest = m[2].replace(/^[^/]*,[^/]*\//, "");
  return `${m[1]}f_jpg,q_auto,w_1200,h_630,c_fill,g_auto/${rest}.jpg`;
}

/** Swaps the head tags. Everything outside these tags is left untouched. */
function render(template, { title, description, url, image, imageAlt }) {
  const subs = [
    [/<title>[\s\S]*?<\/title>/, `<title>${attr(title)}</title>`],
    [/<meta name="description" content="[^"]*">/, `<meta name="description" content="${attr(description)}">`],
    [/<link rel="canonical" href="[^"]*">/, `<link rel="canonical" href="${attr(url)}">`],
    [/<meta property="og:title" content="[^"]*">/, `<meta property="og:title" content="${attr(title)}">`],
    [/<meta property="og:description" content="[^"]*">/, `<meta property="og:description" content="${attr(description)}">`],
    [/<meta property="og:url" content="[^"]*">/, `<meta property="og:url" content="${attr(url)}">`],
    [/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="${attr(image)}">`],
    [/<meta property="og:image:alt" content="[^"]*">/, `<meta property="og:image:alt" content="${attr(imageAlt)}">`],
  ];

  let out = template;
  for (const [pattern, replacement] of subs) {
    if (!pattern.test(out)) throw new Error(`index.html no longer contains ${pattern}`);
    out = out.replace(pattern, replacement);
  }
  return out;
}

function write(route, html) {
  const file = path.join(DIST, route.replace(/^\//, "") + ".html");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, html);
  return path.relative(ROOT, file);
}

// ── main ─────────────────────────────────────────────────────────────────────

(async () => {
  const template = fs.readFileSync(TEMPLATE, "utf8");

  const res = await fetch(CONTENT_URL);
  if (!res.ok) throw new Error(`Could not load site content (${res.status})`);
  const content = await res.json();
  const projects = (content && content.projects) || [];
  if (!projects.length) throw new Error("Site content contained no projects; refusing to generate.");

  const written = [];

  for (const p of projects) {
    // The client name is only worth adding when it earns its place: it must
    // differ from the project title and be short enough to survive the ~60
    // characters a preview card shows. Several projects name the client as the
    // title ("Act Air UAE"), and others list every sector in that field.
    // Matching is loose on purpose: "Statistics Centre Abu Dhabi" and
    // "Statistics Centre Abu Dhabi (SCAD)" are the same name, so an exact
    // comparison would let that pair through.
    const client = String(p.client || "").trim();
    const norm = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
    const c = norm(client);
    const t = norm(p.title);
    const useClient =
      client &&
      client.length <= 34 &&
      !client.includes(",") &&
      c && t && !c.includes(t) && !t.includes(c);

    const title = `${p.title}${useClient ? " · " + client : ""} · Sara Radwan`;
    const description = summarise(p.summary || p.subtitle || (Array.isArray(p.body) ? p.body[0] : p.body));
    written.push(
      write(`/project/${p.id}`, render(template, {
        title,
        description,
        url: `${ORIGIN}/project/${p.id}`,
        image: socialImage(p.image || (p.gallery && p.gallery[0]) || (p.extraImages && p.extraImages[0])),
        imageAlt: `${p.title}, work by Sara Radwan`,
      }))
    );
  }

  for (const page of PAGES) {
    written.push(
      write(page.route, render(template, {
        title: `${page.title} · Sara Radwan`,
        description: page.description,
        url: ORIGIN + page.route,
        image: DEFAULT_IMAGE,
        imageAlt: "Sara Radwan, Creative Director and Brand Strategist",
      }))
    );
  }

  console.log(`Generated ${written.length} preview pages:`);
  console.log(`  ${projects.length} projects`);
  console.log(`  ${PAGES.length} standard pages`);
  console.log(`\nThe homepage keeps its own tags in dist/index.html.`);
})().catch((err) => {
  console.error("Failed:", err.message);
  process.exit(1);
});
