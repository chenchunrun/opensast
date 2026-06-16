package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"html/template"
	"log"
	mathrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
)

type User struct{}
type fileInfo struct{ Size int64 }
type gormStub struct{}

func (g gormStub) Where(query string, args ...any) gormStub { return g }
func (g gormStub) Find(dest any)                            {}

var (
	w      http.ResponseWriter
	info   fileInfo
	cache  = map[string]string{}
	gormDB gormStub
)

func miscVulnerable(client *http.Client, req *http.Request, db any, url string, base string, userInput string, data []byte) {
	// ruleid: go.security.defer-close
	resp, err := http.Get("https://api.example.com")
	_ = resp
	_ = err

	// ok: go.security.defer-close
	safeResp, safeErr := http.Get("https://api.example.com")
	if safeErr == nil {
		defer safeResp.Body.Close()
	}

	// ruleid: go.security.ssrf-http-get
	http.Get(url)

	// ruleid: go.security.ssrf-http-client
	client.Get(url)

	// ok: go.security.ssrf-http-client
	client.Get("https://api.example.com")

	// ruleid: go.security.path-traversal
	os.Open(filepath.Join(base, userInput))

	// ok: go.security.path-traversal
	os.Open(filepath.Join("/srv/data", "static.txt"))

	// ruleid: go.security.insecure-random
	mathrand.Intn(10)

	// ok: go.security.insecure-random
	cryptorand.Read(data)

	// ruleid: go.security.template-injection
	template.Must(template.New(userInput))

	// ok: go.security.template-injection
	template.Must(template.New("fixed-template"))

	// ruleid: go.security.log-injection
	log.Printf(userInput)

	// ok: go.security.log-injection
	log.Printf("user=%s", userInput)

	// ruleid: go.security.header-injection
	w.Header().Set("X-User", userInput)

	// ok: go.security.header-injection
	w.Header().Set("X-User", "alice")

	// ruleid: go.security.multipart-upload
	req.FormFile("upload")

	// ok: go.security.multipart-upload
	if info.Size > 1024 {
		_, _ = req.FormFile("upload")
	}

	// ruleid: go.security.weak-hash-md5
	md5.Sum(data)

	// ruleid: go.security.weak-hash-sha1
	sha1.New()

	// ruleid: go.security.insecure-tls-config
	tls.Config{InsecureSkipVerify: true}

	// ruleid: go.security.deserialization-gob
	gob.NewDecoder(bytes.NewReader(data)).Decode(&User{})

	go func() {
		// ruleid: go.security.race-condition-map
		cache[userInput] = "value"
	}()

	// ruleid: go.security.hardcoded-credentials
	password := "supersecret123"
	_ = password

	// ok: go.security.hardcoded-credentials
	password = os.Getenv("DB_PASSWORD")

	// ruleid: go.security.tempfile-insecure
	os.CreateTemp("/tmp", "report")

	// ruleid: go.security.file-permission
	os.OpenFile("data.txt", os.O_CREATE, 0666)

	// ruleid: go.security.env-default-secret
	apiSecret := os.Getenv("SECRET")
	if apiSecret == "" {
		apiSecret = "fallback-secret"
	}

	// ok: go.security.env-default-secret
	configuredSecret := os.Getenv("SECRET")
	if configuredSecret == "" {
		return
	}

	// ruleid: go.security.sql-injection-gorm
	gormDB.Where(fmt.Sprintf("id = %s", userInput)).Find(&User{})

	// ruleid: go.security.goroutine-leak
	go func() {
		log.Println("running")
	}()
}
