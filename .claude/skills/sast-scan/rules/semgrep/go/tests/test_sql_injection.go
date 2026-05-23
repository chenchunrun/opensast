package main

import (
	"database/sql"
	"fmt"
	"os/exec"
)

func vulnerable(db *sql.DB, id string) {
	// Positive: fmt.Sprintf in Query
	// ruleid: go.security.sql-injection-string-concat
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))

	// ruleid: go.security.sql-injection-string-concat
	db.Query(fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", name))

	// Positive: string concatenation in Exec
	// ruleid: go.security.sql-injection-string-concat
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %s", id))

	// ruleid: go.security.sql-injection-string-concat
	db.QueryRow(fmt.Sprintf("SELECT name FROM users WHERE id = %s", id))
}

func safe(db *sql.DB, id string) {
	// Negative: parameterized query with placeholder
	// ok: go.security.sql-injection-string-concat
	db.Query("SELECT * FROM users WHERE id = $1", id)

	// ok: go.security.sql-injection-string-concat
	db.Query("SELECT * FROM products WHERE name = ? AND active = ?", name, true)

	// ok: go.security.sql-injection-string-concat
	db.Exec("DELETE FROM users WHERE id = $1", id)

	// ok: go.security.sql-injection-string-concat
	db.QueryRow("SELECT name FROM users WHERE id = ?", id)
}
