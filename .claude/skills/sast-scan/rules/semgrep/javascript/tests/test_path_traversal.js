const fs = require('fs');
const path = require('path');

// Positive: readFile with template literal
// ruleid: javascript.security.path-traversal
fs.readFile(`./uploads/${userInput}`, (err, data) => {});

// Positive: readFileSync with string concat
// ruleid: javascript.security.path-traversal
fs.readFileSync("./data/" + userFile);

// Positive: writeFile with interpolation
// ruleid: javascript.security.path-traversal
fs.writeFile(`./output/${fileName}`, content, () => {});

// Positive: unlink with user input
// ruleid: javascript.security.path-traversal
fs.unlink(`./tmp/${userFile}`);

// Positive: path.join with user input
// ruleid: javascript.security.path-traversal
const p = path.join(baseDir, userInput);

// Negative: path.join with literals
// ok: javascript.security.path-traversal
const safe = path.join("src", "components", "App.js");

// Negative: readFile with literal
// ok: javascript.security.path-traversal
fs.readFile("/etc/hostname", (err, data) => {});

// Negative: writeFile with literal
// ok: javascript.security.path-traversal
fs.writeFile("/tmp/output.txt", data, () => {});
