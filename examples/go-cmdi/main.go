package main

import (
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		// Vulnerable: user input in shell command
		cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
		out, _ := cmd.CombinedOutput()
		w.Write(out)
	})
	http.ListenAndServe(":8080", nil)
}
