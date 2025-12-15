require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieSession = require("cookie-session");
const csrf = require("csurf");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "https://YOURSITE.com";
const MASTER_TOKEN = process.env.MASTER_TOKEN || "";
const COOKIE_SECRET = process.env.COOKIE_SECRET || "dev-only-change-me";

if (!MASTER_TOKEN) {
  console.error("ERROR: MASTER_TOKEN is not set.");
  process.exit(1);
}

app.set("trust proxy", 1); // IMPORTANT when behind Cloudflare/NGINX/etc.

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"] // prevents clickjacking/iframes
      }
    },
    referrerPolicy: { policy: "no-referrer" }
  })
);

// Rate limit token minting
const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30, // 30/min per IP (tune)
  standardHeaders: true,
  legacyHeaders: false
});

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session cookie (SameSite=Strict prevents cross-site usage)
app.use(
  cookieSession({
    name: "sess",
    keys: [COOKIE_SECRET],
    httpOnly: true,
    secure: true,       // must be HTTPS in production
    sameSite: "strict", // critical: blocks cross-site
    maxAge: 30 * 60 * 1000 // 30 minutes
  })
);

// Issue a session on first visit (simple, anonymous session)
app.use((req, _res, next) => {
  if (!req.session) req.session = {};
  if (!req.session.sid) {
    req.session.sid = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
  next();
});

// CSRF protection (uses session)
const csrfProtection = csrf();
app.use(csrfProtection);

// Serve static page
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Serve the page at /
app.get("/", (req, res) => {
  // deliver the CSRF token to the client via a header-friendly endpoint below
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Give the client a CSRF token (same-origin only)
app.get("/api/csrf", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

/**
 * Strict origin check:
 * - blocks cross-origin browser calls
 * - does NOT stop server-to-server callers, but combined with SameSite session + CSRF
 *   it prevents “mirrored site” JS from minting tokens.
 */
function requireAllowedOrigin(req, res, next) {
  const origin = req.get("origin") || "";
  if (origin !== ALLOW_ORIGIN) {
    return res.status(403).json({ error: "Forbidden origin" });
  }
  next();
}

// Optional: block specific IPs (IPv4/IPv6 strings)
const blockedIpsForCreation = new Set([
  // "2603:8001:7d3f:1697:1863:89ee:7f61:ed1d",
]);

function rejectBlockedIp(req, res, next) {
  const ip = req.ip; // express uses x-forwarded-for if trust proxy is set
  if (blockedIpsForCreation.has(ip)) {
    return res.status(403).json({ error: "IP blocked" });
  }
  next();
}

// Token mint endpoint
app.post(
  "/api/token",
  tokenLimiter,
  requireAllowedOrigin,
  rejectBlockedIp,
  (req, res) => {
    const { accountId, streamName, tokenId, trackingId } = req.body || {};

    if (!accountId || !streamName) {
      return res.status(400).json({ error: "Missing accountId or streamName" });
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = now + 120; // 2 minutes (tune)

    const tid = Number.isFinite(Number(tokenId)) ? Number(tokenId) : Math.floor(Math.random() * 1e9);

    const payload = {
      streaming: {
        tokenId: tid,
        tokenType: "Subscribe",
        accountId,
        streamName,
        allowedOrigins: []
      },
      iat: now,
      exp,
      meta: {
        // bind-ish info for auditing/debugging; do NOT rely on this as “perfect security”
        sid: req.session.sid,
        clientIp: req.ip,
        trackingId: trackingId || null
      }
    };

    const token = jwt.sign(payload, MASTER_TOKEN, { algorithm: "HS256" });

    res.json({
      streamId: `${accountId}/${streamName}`,
      token,
      exp
    });
  }
);

// CSRF error handler
app.use((err, _req, res, _next) => {
  if (err && err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ error: "Bad CSRF token" });
  }
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on :${port}`));


