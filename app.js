// ============================================================
//  Vulnerable App - DevSecOps Lab 04 — VERSION REMEDIADA
//  Hallazgos SAST corregidos. Uso academico.
// ============================================================

require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// FIX X-Powered-By (CWE-200): Helmet oculta cabeceras que filtran info
app.use(helmet());
app.disable('x-powered-by');

// FIX rate-limiting (CWE-770): limita peticiones por IP
const limiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
app.use(limiter);

// FIX secretos embebidos (CWE-798): todo sale de variables de entorno
const JWT_SECRET = process.env.JWT_SECRET;
const DB_PASSWORD = process.env.DB_PASSWORD;
const API_KEY = process.env.API_KEY;

const connection = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: DB_PASSWORD,
  database: process.env.DB_NAME || 'app'
});

// FIX hashing debil (CWE-327/916): MD5 -> bcrypt (con costo)
async function hashPassword(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

// FIX SQL Injection (CWE-89): consulta parametrizada con placeholders (?)
app.post('/login', (req, res) => {
  const user = req.body.username;
  const pass = req.body.password;

  const query = 'SELECT * FROM users WHERE username = ?';
  connection.query(query, [user], async (err, results) => {
    if (err) return res.status(500).send('DB error');
    if (results && results.length > 0) {
      const match = await bcrypt.compare(pass, results[0].password);
      if (match) return res.json({ status: 'ok' }); // FIX XSS: no refleja input
    }
    return res.status(401).json({ status: 'invalid' });
  });
});

// FIX Command Injection (CWE-78): execFile con args separados + validacion
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // valida que solo sea hostname/IP permitido
  if (!/^[a-zA-Z0-9.\-]+$/.test(host || '')) {
    return res.status(400).send('Invalid host');
  }
  execFile('ping', ['-c', '1', host], (err, stdout, stderr) => {
    if (err) return res.status(500).send('ping failed');
    res.type('text/plain').send(stdout);
  });
});

// FIX Path Traversal (CWE-22/23): normaliza y confina a /uploads
app.get('/download', (req, res) => {
  const uploadsDir = path.resolve(__dirname, 'uploads');
  const requested = path.resolve(uploadsDir, path.basename(req.query.file || ''));
  if (!requested.startsWith(uploadsDir + path.sep)) {
    return res.status(400).send('Invalid path');
  }
  fs.readFile(requested, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.type('text/plain').send(data);
  });
});

// FIX Prototype Pollution (CWE-1321): whitelist de claves, sin merge de req.body
app.post('/profile', (req, res) => {
  const allowed = ['theme'];
  const profile = { role: 'user', theme: 'light' };
  for (const key of allowed) {
    if (typeof req.body[key] === 'string') profile[key] = req.body[key];
  }
  res.json(profile);
});

app.listen(3000, () => {
  console.log('App listening on http://localhost:3000');
});
