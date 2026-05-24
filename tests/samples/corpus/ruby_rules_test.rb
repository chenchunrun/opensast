# Test corpus for Ruby rules
# Lines with # ruleid: should trigger
# Lines with # ok: should NOT trigger

# --- sql-injection ---

# ruleid: ruby.security.sql-injection-string
User.where("name = #{params[:name]}")

# ok: ruby.security.sql-injection-string
User.where("name = ?", params[:name])

# --- command-injection ---

# ruleid: ruby.security.command-injection
system("ls #{params[:dir]}")

# ok: ruby.security.command-injection
system("ls", "-la")

# --- eval ---

# ruleid: ruby.security.eval-usage
eval(params[:code])

# --- xss ---

# ruleid: ruby.security.xss-raw
raw(params[:content])

# --- deserialization ---

# ruleid: ruby.security.deserialization-yaml
YAML.load(params[:data])

# --- csrf ---

# ruleid: ruby.security.csrf-disabled
skip_before_action :verify_authenticity_token

# --- mass-assignment ---

# ruleid: ruby.security.mass-assignment
User.new(params[:user])

# --- debug ---

# ruleid: ruby.security.debug-mode
config.consider_all_requests_local = true

# --- weak-hash ---

# ruleid: ruby.security.weak-hash-md5
Digest::MD5.hexdigest(password)

# ruleid: ruby.security.weak-hash-sha1
Digest::SHA1.hexdigest(password)

# --- ssrf ---

# ruleid: ruby.security.ssrf-open-uri
open(params[:url])

# ok: ruby.security.ssrf-open-uri
URI.parse("https://api.example.com")

# --- path-traversal ---

# ruleid: ruby.security.path-traversal
File.open(params[:path])

# ok: ruby.security.path-traversal
File.open("/etc/hosts")

# --- insecure-random ---

# ruleid: ruby.security.insecure-random
rand(100)
