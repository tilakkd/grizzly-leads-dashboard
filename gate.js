// ===== PASSWORD GATE — Grizzly Insulations leads dashboard =====
// Every request goes through here (see vercel.json "routes"). Without a valid
// cookie the visitor gets a login screen; with one, the requested file is served.
//
// The password itself is NEVER in this file or in the repo. It lives only in the
// Vercel project's Environment Variables as DASHBOARD_PASSWORD.
// If that variable is missing, this gate denies everyone (fails closed) rather
// than silently leaving the dashboard open.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const COOKIE_NAME = 'grizzly_gate';
const STAMP = 'grizzly-dashboard-v1';           // bump this to log everyone out
const MAX_AGE = 60 * 60 * 24 * 30;              // 30 days
const WRONG_PASSWORD_DELAY_MS = 400;            // slows down guessing

// The cookie holds an HMAC of a fixed string keyed by the password — never the
// password itself. Nobody can forge it without knowing the password.
function tokenFor(password) {
  return crypto.createHmac('sha256', password).update(STAMP).digest('hex');
}

function constantTimeEqual(a, b) {
  const bufA = Buffer.from(String(a || ''));
  const bufB = Buffer.from(String(b || ''));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  const hit = raw
    .split(';')
    .map(s => s.trim())
    .find(s => s.startsWith(name + '='));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : null;
}

function readBody(req) {
  return new Promise(resolve => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 10000) req.destroy(); // no reason for a big body here
    });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(''));
  });
}

// Only the dashboard and its month archives may be served. Anything else — and
// any attempt at path traversal — is refused.
function resolveFile(rawUrl) {
  let p = (rawUrl || '/').split('?')[0];
  try { p = decodeURIComponent(p); } catch (e) { return null; }
  if (p === '' || p === '/') p = '/index.html';
  if (p.endsWith('/')) p += 'index.html';

  const rel = path.posix.normalize(p).replace(/^\/+/, '');
  if (rel.includes('..')) return null;

  const allowed = rel === 'index.html' || /^archives\/[A-Za-z0-9._-]+\.html$/.test(rel);
  if (!allowed) return null;

  const abs = path.join(process.cwd(), rel);
  return fs.existsSync(abs) ? abs : null;
}

function loginPage(nextPath, showError) {
  const safeNext = String(nextPath || '/').replace(/"/g, '&quot;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="googlebot" content="noindex, nofollow">
<title>Sign in — Leads Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#f4f6fa;color:#1f2937;font-family:'Inter',system-ui,Arial,sans-serif;font-size:14px;padding:20px;}
.card{width:100%;max-width:390px;background:#fff;border:1px solid #e6e9ef;border-radius:14px;
      box-shadow:0 6px 18px rgba(19,49,79,.10);overflow:hidden;}
.head{background:linear-gradient(100deg,#13314f,#1d4d77);color:#fff;padding:20px 22px;display:flex;align-items:center;gap:12px;}
.logo{width:40px;height:40px;border-radius:10px;background:rgba(255,255,255,.14);
      display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;}
h1{margin:0;font-size:17px;font-weight:800;letter-spacing:.2px;}
.sub{font-size:12px;color:#c9d8e8;margin-top:2px;}
form{padding:22px;}
label{display:block;font-size:12px;font-weight:700;color:#6b7280;margin-bottom:7px;text-transform:uppercase;letter-spacing:.4px;}
input{width:100%;padding:11px 13px;border:1px solid #e6e9ef;border-radius:9px;font-size:14px;
      font-family:inherit;background:#f9fafc;color:#1f2937;}
input:focus{outline:none;border-color:#2563eb;background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,.12);}
button{width:100%;margin-top:14px;padding:11px 13px;border:0;border-radius:9px;background:#2563eb;color:#fff;
       font-size:14px;font-weight:700;font-family:inherit;cursor:pointer;}
button:hover{background:#1d4ed8;}
.err{margin:0 0 14px;padding:9px 12px;border-radius:8px;background:#fdecec;color:#b42318;font-size:13px;font-weight:600;}
.foot{padding:0 22px 20px;font-size:12px;color:#6b7280;line-height:1.5;}
</style>
</head>
<body>
<div class="card">
  <div class="head">
    <div class="logo">GI</div>
    <div>
      <h1>Leads Dashboard</h1>
      <div class="sub">Grizzly Insulations</div>
    </div>
  </div>
  <form method="POST" action="${safeNext}">
    ${showError ? '<p class="err">That password is not right. Please try again.</p>' : ''}
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Sign in</button>
  </form>
  <div class="foot">This dashboard is private and holds customer contact details. Please do not share the password outside your team.</div>
</div>
</body>
</html>`;
}

function configErrorPage() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="robots" content="noindex, nofollow"><title>Not configured</title>
<style>body{font-family:system-ui,Arial,sans-serif;background:#f4f6fa;color:#1f2937;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;text-align:center;}
div{max-width:420px;}h1{font-size:17px;margin:0 0 8px;}p{color:#6b7280;font-size:14px;line-height:1.6;margin:0;}</style>
</head><body><div><h1>Dashboard not configured</h1>
<p>The <code>DASHBOARD_PASSWORD</code> environment variable has not been set on this Vercel project,
so access is blocked. Add it in Project Settings &rarr; Environment Variables and redeploy.</p>
</div></body></html>`;
}

module.exports = async function handler(req, res) {
  const password = process.env.DASHBOARD_PASSWORD;

  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Fail closed: no password configured means nobody gets in.
  if (!password) {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.end(configErrorPage());
  }

  const expected = tokenFor(password);
  const urlPath = (req.url || '/').split('?')[0];

  // Sign out: /?logout=1
  if ((req.url || '').includes('logout=1')) {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
    res.statusCode = 302;
    res.setHeader('Location', '/');
    return res.end();
  }

  // Login attempt
  if (req.method === 'POST') {
    const body = await readBody(req);
    const submitted = new URLSearchParams(body).get('password') || '';

    if (constantTimeEqual(tokenFor(submitted), expected)) {
      res.setHeader(
        'Set-Cookie',
        `${COOKIE_NAME}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`
      );
      res.statusCode = 303; // redirect so a refresh does not re-submit
      res.setHeader('Location', urlPath);
      return res.end();
    }

    await new Promise(r => setTimeout(r, WRONG_PASSWORD_DELAY_MS));
    res.statusCode = 401;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.end(loginPage(urlPath, true));
  }

  // Already signed in?
  const cookie = readCookie(req, COOKIE_NAME);
  if (!cookie || !constantTimeEqual(cookie, expected)) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.end(loginPage(urlPath, false));
  }

  // Signed in — serve the requested file.
  const file = resolveFile(urlPath);
  if (!file) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.end('<!DOCTYPE html><meta charset="utf-8"><p style="font-family:system-ui;padding:24px">Not found.</p>');
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, must-revalidate');
  return res.end(fs.readFileSync(file));
};
