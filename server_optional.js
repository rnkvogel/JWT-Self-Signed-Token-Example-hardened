/**
 * Optional server-side server.js for Phishing attempts.
 */
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieSession = require("cookie-session");
const csrf = require("csurf");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

const app = express();

/**
 * ENV CONFIG
 */
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "https://YOURSITE.com";
const MASTER_TOKEN = process.env.MASTER_TOKEN || "";
const COOKIE_SECRET = process.env.COOKIE_SECRET || "dev-only-change-me";
const PORT = process.env.PORT || 3000;

/**
 * Optional server-side stream locking.
 *
 * If these are set, the browser cannot request arbitrary accountId/streamName.
 * This is safer against phishing/ghost token attempts.
 */
const LOCKED_ACCOUNT_ID = process.env.ACCOUNT_ID || "";
const LOCKED_STREAM_NAME = process.env.STREAM_NAME || "";

/**
 * Abuse / auto-block config.
 */
const ABUSE_LIMIT = Number(process.env.ABUSE_LIMIT || 10);
const ABUSE_WINDOW_MS = Number(process.env.ABUSE_WINDOW_MS || 10 * 60 * 1000);
const AUTO_BLOCK_MS = Number(process.env.AUTO_BLOCK_MS || 60 * 60 * 1000);
const SECURITY_LOG_FILE = process.env.SECURITY_LOG_FILE || path.join(__dirname, "security-deny.log");

if (!MASTER_TOKEN) {
  console.error("ERROR: MASTER_TOKEN is not set.");
  process.exit(1);
}

/**
 * IMPORTANT when behind Cloudflare, NGINX, load balancers, etc.
 * This allows req.ip to use X-Forwarded-For correctly.
 */
app.set("trust proxy", 1);

/**
 * In-memory abuse tracking.
 *
 * For multi-server production, move this to Redis, Cloudflare WAF, NGINX,
 * or another shared edge/rate-limit layer.
 */
const abuseCounts = new Map();
const autoBlockedIps = new Map();

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

/**
 * Security event logging.
 *
 * Logs blocked phishing/ghost attempts with useful headers:
 * - Origin
 * - Referer
 * - User-Agent
 * - Sec-Fetch-* browser metadata
 */
function logSecurityEvent(req, reason, extra = {}) {
  const row = {
    time: new Date().toISOString(),
    reason,
    ip: getClientIp(req),
    method: req.method,
    path: req.originalUrl,
    origin: req.get("origin") || null,
    referer: req.get("referer") || null,
    userAgent: req.get("user-agent") || null,
    secFetchSite: req.get("sec-fetch-site") || null,
    secFetchMode: req.get("sec-fetch-mode") || null,
    secFetchDest: req.get("sec-fetch-dest") || null,
    ...extra
  };

  console.warn("[SECURITY]", JSON.stringify(row));

  fs.appendFile(SECURITY_LOG_FILE, JSON.stringify(row) + "\n", () => {});
}

/**
 * Records abuse and temporarily blocks repeat offenders.
 */
function recordAbuse(req, reason) {
  const ip = getClientIp(req);
  const now = Date.now();

  let current = abuseCounts.get(ip);

  if (!current || now - current.firstSeen > ABUSE_WINDOW_MS) {
    current = {
      count: 0,
      firstSeen: now,
      lastSeen: now,
      reasons: {}
    };
  }

  current.count += 1;
  current.lastSeen = now;
  current.reasons[reason] = (current.reasons[reason] || 0) + 1;

  abuseCounts.set(ip, current);

  if (current.count >= ABUSE_LIMIT) {
    autoBlockedIps.set(ip, now + AUTO_BLOCK_MS);

    logSecurityEvent(req, "AUTO_BLOCKED_IP", {
      abuseCount: current.count,
      reasons: current.reasons,
      blockedUntil: new Date(now + AUTO_BLOCK_MS).toISOString()
    });
  }
}

/**
 * Rejects IPs temporarily auto-blocked by repeated bad requests.
 */
function rejectAutoBlockedIp(req, res, next) {
  const ip = getClientIp(req);
  const until = autoBlockedIps.get(ip);

  if (until && Date.now() < until) {
    logSecurityEvent(req, "AUTO_BLOCK_ACTIVE", {
      blockedUntil: new Date(until).toISOString()
    });

    return res.status(403).json({
      error: "IP temporarily blocked"
    });
  }

  if (until && Date.now() >= until) {
    autoBlockedIps.delete(ip);
  }

  next();
}

/**
 * Static/manual IP block list.
 */
const blockedIpsForCreation = new Set([
  // "2603:8001:7d3f:1697:1863:89ee:7f61:ed1d",
]);

function rejectManuallyBlockedIp(req, res, next) {
  const ip = getClientIp(req);

  if (blockedIpsForCreation.has(ip)) {
    logSecurityEvent(req, "MANUAL_IP_BLOCK");
    return res.status(403).json({
      error: "IP blocked"
    });
  }

  next();
}

/**
 * Early phishing/ghost request gate.
 *
 * This runs BEFORE:
 * - body parsing
 * - session creation
 * - CSRF
 * - JWT signing
 *
 * Goal:
 * Reject obvious phishing, mirrored-site, cross-site, bad-method,
 * and non-JSON attempts as cheaply as possible.
 */
function earlyPhishingGate(req, res, next) {
  if (!req.path.startsWith("/api/")) {
    return next();
  }

  const origin = req.get("origin") || "";
  const secFetchSite = req.get("sec-fetch-site") || "";
  const secFetchMode = req.get("sec-fetch-mode") || "";

  /**
   * Only allow POST for token minting.
   */
  if (req.path === "/api/token" && req.method !== "POST") {
    logSecurityEvent(req, "TOKEN_BAD_METHOD");
    recordAbuse(req, "TOKEN_BAD_METHOD");

    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  /**
   * Require JSON for token minting.
   * This blocks many simple phishing form/beacon tricks.
   */
  if (req.path === "/api/token" && !req.is("application/json")) {
    logSecurityEvent(req, "TOKEN_NON_JSON");
    recordAbuse(req, "TOKEN_NON_JSON");

    return res.status(415).json({
      error: "JSON required"
    });
  }

  /**
   * Strict Origin allowlist.
   * Browser-originated requests from a phishing domain should fail here.
   */
  if (origin && origin !== ALLOW_ORIGIN) {
    logSecurityEvent(req, "BAD_ORIGIN");
    recordAbuse(req, "BAD_ORIGIN");

    return res.status(403).json({
      error: "Forbidden origin"
    });
  }

  /**
   * Fetch Metadata protection.
   * Modern browsers send Sec-Fetch-Site.
   * A phishing/mirrored site usually appears as cross-site.
   */
  if (secFetchSite === "cross-site") {
    logSecurityEvent(req, "CROSS_SITE_FETCH");
    recordAbuse(req, "CROSS_SITE_FETCH");

    return res.status(403).json({
      error: "Cross-site request blocked"
    });
  }

  /**
   * Restrict strange fetch modes for token endpoint.
   */
  if (
    req.path === "/api/token" &&
    secFetchMode &&
    secFetchMode !== "cors" &&
    secFetchMode !== "same-origin"
  ) {
    logSecurityEvent(req, "BAD_FETCH_MODE");
    recordAbuse(req, "BAD_FETCH_MODE");

    return res.status(403).json({
      error: "Bad fetch mode"
    });
  }

  next();
}

/**
 * Security headers.
 */
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"]
      }
    },
    referrerPolicy: {
      policy: "no-referrer"
    }
  })
);

/**
 * Early cheap blocking.
 */
app.use(rejectAutoBlockedIp);
app.use(rejectManuallyBlockedIp);
app.use(earlyPhishingGate);

/**
 * Body parsing after early blocking.
 * Small limits reduce abuse payload size.
 */
app.use(express.json({ limit: "8kb" }));
app.use(express.urlencoded({ extended: false, limit: "8kb" }));

/**
 * Session cookie.
 *
 * SameSite Strict helps prevent a phishing site from using the browser's
 * valid same-site session cookie.
 */
app.use(
  cookieSession({
    name: "sess",
    keys: [COOKIE_SECRET],
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 30 * 60 * 1000
  })
);

/**
 * Anonymous session ID for audit correlation.
 */
app.use((req, _res, next) => {
  if (!req.session) req.session = {};

  if (!req.session.sid) {
    req.session.sid = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  next();
});

/**
 * CSRF protection.
 */
const csrfProtection = csrf();
app.use(csrfProtection);

/**
 * Static files.
 */
app.use(express.static(path.join(__dirname, "public"), { index: false }));

/**
 * Main page.
 */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/**
 * CSRF token endpoint.
 */
app.get("/api/csrf", (req, res) => {
  res.json({
    csrfToken: req.csrfToken()
  });
});

/**
 * Strict same-origin check.
 *
 * This still runs on protected routes as a second layer.
 */
function requireAllowedOrigin(req, res, next) {
  const origin = req.get("origin") || "";

  if (origin !== ALLOW_ORIGIN) {
    logSecurityEvent(req, "FORBIDDEN_ORIGIN_ROUTE_CHECK");
    recordAbuse(req, "FORBIDDEN_ORIGIN_ROUTE_CHECK");

    return res.status(403).json({
      error: "Forbidden origin"
    });
  }

  next();
}

/**
 * Token endpoint rate limiter.
 *
 * This protects local token minting.
 * A 429 here means your app is rate-limiting the requester.
 */
const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.TOKEN_RATE_LIMIT || 30),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logSecurityEvent(req, "LOCAL_RATE_LIMIT_429");
    recordAbuse(req, "LOCAL_RATE_LIMIT_429");

    res.status(429).json({
      error: "Too many token requests"
    });
  }
});

/**
 * Optional basic admin protection for diagnostics endpoint.
 */
function requireAdminKey(req, res, next) {
  const adminKey = process.env.ADMIN_KEY || "";

  if (!adminKey) {
    return res.status(404).json({
      error: "Not found"
    });
  }

  const provided = req.get("x-admin-key") || "";

  if (provided !== adminKey) {
    logSecurityEvent(req, "BAD_ADMIN_KEY");
    return res.status(403).json({
      error: "Forbidden"
    });
  }

  next();
}

/**
 * Token mint endpoint.
 */
app.post(
  "/api/token",
  tokenLimiter,
  requireAllowedOrigin,
  (req, res) => {
    const { accountId: bodyAccountId, streamName: bodyStreamName, tokenId, trackingId } = req.body || {};

    /**
     * Safer mode:
     * If ACCOUNT_ID and STREAM_NAME are set in .env, browser-supplied values are ignored.
     */
    const accountId = LOCKED_ACCOUNT_ID || bodyAccountId;
    const streamName = LOCKED_STREAM_NAME || bodyStreamName;

    if (!accountId || !streamName) {
      logSecurityEvent(req, "MISSING_STREAM_FIELDS", {
        bodyAccountIdPresent: Boolean(bodyAccountId),
        bodyStreamNamePresent: Boolean(bodyStreamName),
        lockedAccountIdEnabled: Boolean(LOCKED_ACCOUNT_ID),
        lockedStreamNameEnabled: Boolean(LOCKED_STREAM_NAME)
      });

      recordAbuse(req, "MISSING_STREAM_FIELDS");

      return res.status(400).json({
        error: "Missing accountId or streamName"
      });
    }

    /**
     * Basic streamName/accountId sanity check.
     * Tune this if your stream names use other characters.
     */
    const safeValue = /^[a-zA-Z0-9._-]+$/;

    if (!safeValue.test(accountId) || !safeValue.test(streamName)) {
      logSecurityEvent(req, "INVALID_STREAM_VALUE", {
        accountId,
        streamName
      });

      recordAbuse(req, "INVALID_STREAM_VALUE");

      return res.status(400).json({
        error: "Invalid accountId or streamName"
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = now + Number(process.env.JWT_TTL_SECONDS || 120);

    const tid = Number.isFinite(Number(tokenId))
      ? Number(tokenId)
      : Math.floor(Math.random() * 1e9);

    /**
     * JWT payload.
     *
     * Important:
     * allowedOrigins should NOT be empty.
     * Binding the token to ALLOW_ORIGIN reduces replay usefulness.
     */
    const payload = {
      streaming: {
        tokenId: tid,
        tokenType: "Subscribe",
        accountId,
        streamName,
        allowedOrigins: [ALLOW_ORIGIN]
      },
      iat: now,
      exp,
      meta: {
        sid: req.session.sid,
        clientIp: getClientIp(req),
        trackingId: trackingId || null,
        lockedStream: Boolean(LOCKED_ACCOUNT_ID && LOCKED_STREAM_NAME)
      }
    };

    const token = jwt.sign(payload, MASTER_TOKEN, {
      algorithm: "HS256"
    });

    console.log(
      "[TOKEN_CREATED]",
      JSON.stringify({
        time: new Date().toISOString(),
        ip: getClientIp(req),
        streamId: `${accountId}/${streamName}`,
        sid: req.session.sid,
        exp
      })
    );

    res.json({
      streamId: `${accountId}/${streamName}`,
      token,
      exp
    });
  }
);

/**
 * Diagnostics endpoint.
 *
 * Requires:
 * ADMIN_KEY=some-long-random-secret
 *
 * Request:
 * curl -H "x-admin-key: YOUR_KEY" https://yourdomain.com/api/security/blocked
 */
app.get("/api/security/blocked", requireAdminKey, (req, res) => {
  const now = Date.now();

  res.json({
    blocked: [...autoBlockedIps.entries()].map(([ip, until]) => ({
      ip,
      until: new Date(until).toISOString(),
      remainingSeconds: Math.max(0, Math.floor((until - now) / 1000))
    })),
    abuse: [...abuseCounts.entries()].map(([ip, data]) => ({
      ip,
      count: data.count,
      firstSeen: new Date(data.firstSeen).toISOString(),
      lastSeen: new Date(data.lastSeen).toISOString(),
      reasons: data.reasons
    }))
  });
});

/**
 * CSRF and general error handler.
 */
app.use((err, req, res, _next) => {
  if (err && err.code === "EBADCSRFTOKEN") {
    logSecurityEvent(req, "BAD_CSRF_TOKEN");
    recordAbuse(req, "BAD_CSRF_TOKEN");

    return res.status(403).json({
      error: "Bad CSRF token"
    });
  }

  console.error(err);

  res.status(500).json({
    error: "Server error"
  });
});

app.listen(PORT, () => {
  console.log(`Listening on :${PORT}`);
  console.log(`Allowed origin: ${ALLOW_ORIGIN}`);

  if (LOCKED_ACCOUNT_ID && LOCKED_STREAM_NAME) {
    console.log(`Locked stream mode enabled: ${LOCKED_ACCOUNT_ID}/${LOCKED_STREAM_NAME}`);
  } else {
    console.log("Locked stream mode disabled: browser may provide accountId/streamName");
  }
});
