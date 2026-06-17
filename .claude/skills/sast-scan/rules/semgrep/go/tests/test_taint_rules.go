package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// --- taint-sql-injection ---

func searchHandler_Unsafe(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	db, _ := sql.Open("postgres", "...")
	// ruleid: go.security.taint-sql-injection
	db.Query("SELECT * FROM users WHERE name LIKE '%" + q + "%'")
}

func searchHandler_UnsafeFmt(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	sqlStr := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", q)
	db, _ := sql.Open("postgres", "...")
	// ruleid: go.security.taint-sql-injection
	db.Exec(sqlStr)
}

func searchHandler_Safe(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	db, _ := sql.Open("postgres", "...")
	// ok: go.security.taint-sql-injection
	db.Query("SELECT * FROM users WHERE name LIKE $1", "%"+q+"%")
}

// --- taint-command-injection ---

func pingHandler_Unsafe(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// ruleid: go.security.taint-command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

func pingHandler_UnsafeFmt(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmdStr := fmt.Sprintf("ping -c 1 %s", host)
	// ruleid: go.security.taint-command-injection
	exec.Command("sh", "-c", cmdStr).Run()
}

func pingHandler_Safe(w http.ResponseWriter, r *http.Request) {
	// ok: go.security.taint-command-injection
	exec.Command("ping", "-c", "1", "localhost").Run()
}

// --- taint-path-traversal ---

func exportHandler_Unsafe(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	path := "/var/exports/" + filename
	// ruleid: go.security.taint-path-traversal
	os.Open(path)
}

func exportHandler_Safe(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	clean := filepath.Clean(filename)
	// ok: go.security.taint-path-traversal
	os.Open("/var/exports/" + filepath.Base(clean))
}

// --- taint-ssrf ---

func proxyHandler_Unsafe(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	// ruleid: go.security.taint-ssrf
	http.Get(url)
}

func proxyHandler_UnsafePost(w http.ResponseWriter, r *http.Request) {
	endpoint := r.URL.Query().Get("callback")
	// ruleid: go.security.taint-ssrf
	http.Post(endpoint, "application/json", nil)
}

func proxyHandler_Safe(w http.ResponseWriter, r *http.Request) {
	// ok: go.security.taint-ssrf
	http.Get("https://api.example.com/health")
}

// --- taint-xss-template ---

func greetHandler_Unsafe(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	tmpl, _ := template.New("greet").Parse("Hello {{.}}")
	// ruleid: go.security.taint-xss-template
	tmpl.Execute(w, name)
}

func greetHandler_UnsafeFprintf(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go.security.taint-xss-template
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func greetHandler_Safe(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// ok: go.security.taint-xss-template
	io.WriteString(w, template.HTMLEscapeString(name))
}

// --- taint-open-redirect ---

func redirectHandler_Unsafe(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("redirect")
	// ruleid: go.security.taint-open-redirect
	http.Redirect(w, r, target, 302)
}

func redirectHandler_Safe(w http.ResponseWriter, r *http.Request) {
	// ok: go.security.taint-open-redirect
	http.Redirect(w, r, "/home", 302)
}
