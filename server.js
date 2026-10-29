'use strict';
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
if (!ACCESS_TOKEN || ACCESS_TOKEN.length < 24) {
  console.error('Set ACCESS_TOKEN to a random string of at least 24 characters.');
  process.exit(1);
}

// Only origins you control. Example: https://my-site.example.com
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const targets = new Map();
for (const raw of allowedOrigins) {
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('ALLOWED_ORIGINS must contain HTTPS origins only');
  }
  const id = crypto.createHash('sha256').update(url.origin).digest('hex').slice(0, 16);
  targets.set(id, url.origin);
}
if (!targets.size) throw new Error('Set ALLOWED_ORIGINS to your own HTTPS sites');

app.use(express.static('public'));
app.get('/api/sites', (req, res) => {
  res.json([...targets].map(([id, origin]) => ({id, origin})));
});

// Browser authentication: token kept in an HttpOnly cookie after a one-time login.
app.use(express.urlencoded({extended:false, limit:'2kb'}));
app.post('/login', (req, res) => {
  const provided = Buffer.from(String(req.body.token || ''));
  const expected = Buffer.from(ACCESS_TOKEN);
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    return res.status(403).send('Invalid token');
  }
  res.cookie('quvo_auth', ACCESS_TOKEN, {httpOnly:true, secure:process.env.NODE_ENV === 'production', sameSite:'lax', path:'/'});
  res.redirect('/');
});
function isAuthed(req) {
  const match = (req.headers.cookie || '').match(/(?:^|;\s*)quvo_auth=([^;]+)/);
  if (!match) return false;
  const provided = Buffer.from(decodeURIComponent(match[1]));
  const expected = Buffer.from(ACCESS_TOKEN);
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}

// Each origin is mounted under its own path. This is a limited reverse proxy,
// not a universal browser; absolute URLs, CSP and complex authentication can fail.
for (const [id, origin] of targets) {
  app.use(`/site/${id}`, (req, res, next) => {
    if (!isAuthed(req)) return res.status(401).send('Login required');
    next();
  }, createProxyMiddleware({
    target: origin,
    changeOrigin: true,
    ws: false,
    secure: true,
    pathRewrite: (path) => path.replace(new RegExp(`^/site/${id}`), '') || '/',
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.removeHeader('cookie');
        proxyReq.removeHeader('authorization');
      },
      proxyRes: (proxyRes) => {
        delete proxyRes.headers['set-cookie'];
        delete proxyRes.headers['content-security-policy'];
        delete proxyRes.headers['x-frame-options'];
      },
      error: (_err, _req, res) => {
        if (!res.headersSent) res.writeHead(502, {'Content-Type':'text/plain; charset=utf-8'});
        res.end('Proxy request failed');
      }
    }
  }));
}
app.listen(PORT, () => console.log(`Quvo Browser listening on ${PORT}`));
