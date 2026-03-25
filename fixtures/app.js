const express = require("express");
const mysql = require("mysql");
const app = express();

// Hardcoded credentials (secrets finding)
const DB_PASSWORD = "SuperSecret123!";
const API_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// SQL Injection vulnerability
app.get("/user", (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// XSS vulnerability — reflecting user input without sanitization
app.get("/search", (req, res) => {
  const term = req.query.q;
  res.send(`<h1>Results for: ${term}</h1>`);
});

// Command injection
const { exec } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
});

// Path traversal
const fs = require("fs");
const path = require("path");
app.get("/file", (req, res) => {
  const filename = req.query.name;
  const content = fs.readFileSync("/data/" + filename, "utf-8");
  res.send(content);
});

// Insecure crypto
const crypto = require("crypto");
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// Insecure eval
app.post("/calculate", (req, res) => {
  const expression = req.body.expr;
  const result = eval(expression);
  res.json({ result });
});

// Weak JWT secret
const jwt = require("jsonwebtoken");
function createToken(user) {
  return jwt.sign(user, "secret123");
}

// No rate limiting, no helmet, no CORS configured
app.listen(3000, () => {
  console.log("Server running on port 3000");
});
