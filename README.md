Millicast Secure Viewer Token Gateway (Node.js)

This project provides a secure, server-side JWT token gateway for Millicast (Dolby OptiView) viewers.
It exposes a simple “View Stream” page that requests a short-lived subscribe token from your server and opens the official Millicast viewer. The master token never leaves the server.

What This Solves
✅ What this setup protects
The Millicast master token is never exposed to browsers
Only your allowed domain (e.g. https://YOURSITE.com) can mint viewer tokens
A copied / mirrored site cannot call your token endpoint
Tokens are short-lived (seconds or minutes)
Token requests are protected by:
Same-origin cookies (SameSite=Strict)
CSRF tokens
Origin validation
Rate limiting

⚠️ Important reality check

No public website can be made literally impossible to proxy or mirror.
However, this setup prevents a mirrored page from generating valid tokens, which is what actually matters.

Requirements
Millicast / Dolby OptiView
You must have:
A Millicast account
A stream configured for secure playback
A master token (used to sign subscribe JWTs)
You will need:
accountId (example: KnWAD9)
streamName (example: secure)
Millicast hosted viewer format:

https://viewer.millicast.com/?streamId={AccountId}/{StreamName}&token={SubscribeToken}
Official Documentation

Securing Stream Playback (Subscribe Tokens)
https://docs.dolby.io/streaming/docs/securing-stream-playback

Subscribe Tokens Overview
https://docs.dolby.io/streaming/docs/subscribe-token

Hosted Viewer Usage
https://docs.dolby.io/streaming/docs/hosted-player

Token APIs
https://docs.dolby.io/streaming/docs/tokens-api

Environment Variables

You must set these in production.

MASTER_TOKEN

Your Millicast master token.
Used to sign JWTs (HS256)
Must never be exposed to frontend code
Treat like a private key

Example:
MASTER_TOKEN=your-millicast-master-token

ALLOW_ORIGIN
The only website allowed to request tokens.

Example:

ALLOW_ORIGIN=https://nerdits.com
Requests from any other origin will be rejected.
COOKIE_SECRET
A long random secret used to sign session cookies.
Generate one:
openssl rand -hex 32


Example:
COOKIE_SECRET=2d9b3e6b5c7c0f5a8e6e1b9e4d1a7f3a

Installation
1. Install Node.js

Use Node.js LTS (recommended).

Check version:

node -v

2. Install dependencies
npm install

3. Set environment variables (local example)
export MASTER_TOKEN="YOUR_MILLICAST_MASTER_TOKEN"
export ALLOW_ORIGIN="http://localhost:3000"
export COOKIE_SECRET="change-this-to-a-long-random-string"

4. Start the server
npm start

Open:
http://localhost:3000
Production Deployment (Beginner Friendly)
✅ HTTPS is REQUIRED

This project uses secure cookies:

SameSite=Strict
Secure=true

That means:
❌ HTTP will NOT work
✅ You must use HTTPS

Common deployment options
Option	Notes
VPS + Nginx	Most control, recommended
Cloudflare	Excellent WAF + TLS
Render / Railway	Easy managed hosting
Fly.io	Good for edge deployment
Example: Nginx reverse proxy

Node runs on localhost:3000, Nginx serves HTTPS.
server {
  listen 443 ssl;
  server_name nerdits.com;

  ssl_certificate     /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}

How the Token Flow Works

User opens:
https://YOURSITE.com/
Page requests a CSRF token:
GET /api/csrf
Page requests a viewer token:
POST /api/token
Server validates:
Origin matches ALLOW_ORIGIN
Session cookie exists
CSRF token is valid
IP not blocked
Server returns:

{
  "streamId": "accountID/streamName",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "exp": 1764792436
}


Browser opens:
https://viewer.millicast.com/?streamId=LZsuF8/secure&token=...
Security Features Included

✅ Master token never exposed

✅ Short-lived subscribe tokens

✅ SameSite=Strict cookies

✅ CSRF protection

✅ Origin validation

✅ Rate limiting

✅ IP allow/block support (IPv4 + IPv6)

✅ Clickjacking protection (frame-ancestors 'none')

Optional Hardening (Recommended)
If you want even stronger protection:
Put /api/token behind Cloudflare WAF
Add Cloudflare Turnstile / CAPTCHA
Require login (Cloudflare Access, OAuth, etc.)
Lower token TTL to 60–120 seconds
Restrict playback using Millicast secure playback rules

Troubleshooting

Viewer opens but playback fails
Confirm the stream is secure / requires subscribe tokens
Confirm accountId and streamName
Confirm token is not expired
Confirm hosted viewer URL format is correct
403 errors from /api/token
Check ALLOW_ORIGIN exactly matches your site
Confirm HTTPS is enabled
Check cookies are being set




