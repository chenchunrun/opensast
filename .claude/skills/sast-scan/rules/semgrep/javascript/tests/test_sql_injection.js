const mysql = require('mysql2');
const connection = mysql.createConnection({});

const id = "1; DROP TABLE users";

// Positive: template literal in SQL
// ruleid: javascript.security.sql-injection-string-concat
connection.query(`SELECT * FROM users WHERE id = '${id}'`);

// ruleid: javascript.security.sql-injection-string-concat
connection.query(`DELETE FROM users WHERE name = '${name}'`);

// Positive: string concatenation in SQL
// ruleid: javascript.security.sql-injection-string-concat
connection.query("SELECT * FROM users WHERE id = " + id);

// ruleid: javascript.security.sql-injection-string-concat
connection.execute(`SELECT * FROM products WHERE id = '${pid}'`);

// Negative: parameterized query
// ok: javascript.security.sql-injection-string-concat
connection.query("SELECT * FROM users WHERE id = ?", [id]);

// ok: javascript.security.sql-injection-string-concat
connection.execute("SELECT * FROM products WHERE id = ?", [pid]);
