const express = require('express');
const app = express();

const name = '<script>alert("xss")</script>';

// Positive: res.send with template literal interpolation
// ruleid: javascript.security.xss-response-send
res.send(`<h1>${name}</h1>`);

// ruleid: javascript.security.xss-response-send
res.send(`<div>Welcome ${req.query.name}</div>`);

// Positive: res.write with template literal
// ruleid: javascript.security.xss-response-send
res.write(`<p>${userInput}</p>`);

// Positive: string concatenation
// ruleid: javascript.security.xss-response-send
res.send("<h1>" + name + "</h1>");

// ruleid: javascript.security.xss-response-send
res.write("Hello " + req.query.name);

// Negative: escaped output
// ok: javascript.security.xss-response-send
res.send(escapeHtml(name));

// ok: javascript.security.xss-response-send
res.write(escapeHtml(userInput));

// ok: javascript.security.xss-response-send
res.send("<h1>Static content</h1>");
