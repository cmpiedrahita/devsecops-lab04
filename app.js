// ============================================================
//  Vulnerable App - DevSecOps Lab 04
//  USO ACADEMICO. Contiene fallos de seguridad A PROPOSITO
//  para ser detectados por un analisis SAST (Snyk).
//  NO desplegar en produccion.
// ============================================================

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const _ = require('lodash');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------------------------------------------
// VULN 3 - Secreto embebido en el codigo (hard-coded secret)
// CWE-798 | OWASP A07:2021
// ------------------------------------------------------------
const JWT_SECRET = 'sk_live_9f8a2b1c7d3e4f5a6b8c9d0e1f2a3b4c';
const DB_PASSWORD = 'Admin1234!';
const API_KEY = 'AKIA1234567890ABCDEF';

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: DB_PASSWORD,
  database: 'app'
});

// ------------------------------------------------------------
// VULN 4 - Hashing debil (MD5) para contrasenas
// CWE-327 | OWASP A02:2021
// ------------------------------------------------------------
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// ------------------------------------------------------------
// VULN 1 - SQL Injection (concatenacion de input sin sanitizar)
// CWE-89 | OWASP A03:2021
// ------------------------------------------------------------
app.post('/login', (req, res) => {
  const user = req.body.username;
  const pass = hashPassword(req.body.password);

  const query = "SELECT * FROM users WHERE username = '" + user +
                "' AND password = '" + pass + "'";

  connection.query(query, (err, results) => {
    if (err) return res.status(500).send('DB error');
    if (results && results.length > 0) {
      return res.send('Welcome ' + user);
    }
    return res.status(401).send('Invalid credentials');
  });
});

// ------------------------------------------------------------
// VULN 2 - Command Injection (exec sobre input del usuario)
// CWE-78 | OWASP A03:2021
// ------------------------------------------------------------
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr);
    res.send(stdout);
  });
});

// ------------------------------------------------------------
// VULN 5 - Path Traversal (lectura de archivo sin validar ruta)
// CWE-22 | OWASP A01:2021
// ------------------------------------------------------------
app.get('/download', (req, res) => {
  const fileName = req.query.file;
  fs.readFile('./uploads/' + fileName, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});

// ------------------------------------------------------------
// VULN 6 - Prototype Pollution via lodash.merge sobre input
// (ademas de la dependencia lodash 4.17.4 vulnerable, CVE-2019-10744)
// CWE-1321 | OWASP A06:2021 (componentes desactualizados)
// ------------------------------------------------------------
app.post('/profile', (req, res) => {
  const defaults = { role: 'user', theme: 'light' };
  const merged = _.merge({}, defaults, req.body);
  res.json(merged);
});

app.listen(3000, () => {
  console.log('Vulnerable app listening on http://localhost:3000');
  console.log('API_KEY in use: ' + API_KEY + ' | JWT: ' + JWT_SECRET);
});
