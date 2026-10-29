# Quvo Browser

Node.js 20+ required.

1. `npm install`
2. Set environment variables `ACCESS_TOKEN` (random 24+ characters) and `ALLOWED_ORIGINS` (comma-separated HTTPS origins you control).
3. `npm start`
4. Open `http://localhost:3000`, enter your token in the login form (if it is not shown, use POST /login), and choose a site.

This is a **limited reverse proxy**, not a full browser. Site-root-relative links, authentication, cookies, cross-origin APIs, CSP and WebSocket features may not work. Do not use for third-party websites. Use a dedicated hostname, HTTPS, and private access in production. The login cookie is not a substitute for platform-level access controls.
