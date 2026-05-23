"""Vulnerable Node.js/Express code for SAST testing."""

const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql2");

const app = express();
app.use(express.json());

// Command injection
app.get("/ping", (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (error, stdout) => {
        res.send(stdout);
    });
});

// SQL injection
app.get("/user", (req, res) => {
    const id = req.query.id;
    const connection = mysql.createConnection({
        host: "localhost",
        user: "root",
        password: "hardcoded_password_123",
        database: "test",
    });
    connection.query(`SELECT * FROM users WHERE id = '${id}'`, (err, results) => {
        res.json(results);
    });
});

// XSS - reflected
app.get("/greet", (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);
});

// Hardcoded secret
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

app.listen(3000);
