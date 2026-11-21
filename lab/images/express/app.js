// Public status page: Express with a session cookie and wildcard CORS.
const express = require('express');
const session = require('express-session');

const app = express();
app.use(session({ secret: 'lab-only-not-a-secret', resave: false, saveUninitialized: true }));
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  next();
});

const page = `<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Status usług — panel publiczny</title></head>
<body><h1>Status usług</h1><ul><li>Poczta: działa</li><li>USOS: działa</li><li>VPN: przerwa techniczna</li></ul></body>
</html>
`;

app.get('/', (req, res) => res.send(page));
app.get('/api/status', (req, res) => res.json({ mail: 'ok', usos: 'ok', vpn: 'maintenance' }));

app.listen(3000, '0.0.0.0');
