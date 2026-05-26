# ruleid: ruby.security.sql-injection-string
User.where("name = #{params[:name]}")

# ok: ruby.security.sql-injection-string
User.where("name = ?", params[:name])

# ruleid: ruby.security.command-injection
system("ls #{params[:dir]}")

# ok: ruby.security.command-injection
system("ls", "-la")

# ruleid: ruby.security.eval-usage
eval(params[:code])

# ok: ruby.security.eval-usage
eval("2 + 2")

# ruleid: ruby.security.xss-raw
raw(params[:content])

# ok: ruby.security.xss-raw
raw(h(params[:content]))

# ruleid: ruby.security.deserialization-yaml
YAML.load(params[:data])

# ok: ruby.security.deserialization-yaml
YAML.safe_load(params[:data])

# ruleid: ruby.security.csrf-disabled
skip_before_action :verify_authenticity_token

# ok: ruby.security.csrf-disabled
protect_from_forgery with: :exception

# ruleid: ruby.security.mass-assignment
User.new(params[:user])

# ok: ruby.security.mass-assignment
User.new(params.require(:user).permit(:name))

# ruleid: ruby.security.insecure-cookie
cookies.permanent[:session] = token

# ok: ruby.security.insecure-cookie
cookies.permanent.signed[:session] = token

# ruleid: ruby.security.session-secret-hardcoded
secret_key_base = "hardcoded-secret"

# ok: ruby.security.session-secret-hardcoded
secret_key_base = ENV["SECRET_KEY_BASE"]

# ruleid: ruby.security.debug-mode
config.consider_all_requests_local = true

# ok: ruby.security.debug-mode
config.consider_all_requests_local = false

# ruleid: ruby.security.hardcoded-credentials
db_password = "supersecret123"

# ok: ruby.security.hardcoded-credentials
db_password = ENV["DB_PASSWORD"]

# ruleid: ruby.security.weak-password-hash
Digest::MD5.hexdigest(password)

# ok: ruby.security.weak-password-hash
BCrypt::Password.create(password)

# ruleid: ruby.security.insecure-compare
if api_token == params[:token]
  allow!
end

# ok: ruby.security.insecure-compare
secure_compare(api_token, params[:token])

# ruleid: ruby.security.path-traversal
File.open(params[:path])

# ok: ruby.security.path-traversal
File.open("/etc/hosts")

# ruleid: ruby.security.ssrf-open-uri
open(params[:url])

# ok: ruby.security.ssrf-open-uri
URI.open("https://api.example.com")

# ruleid: ruby.security.insecure-random
rand(100)

# ok: ruby.security.insecure-random
SecureRandom.random_number(100)

# ruleid: ruby.security.tempfile-insecure
Tempfile.new("report")

# ok: ruby.security.tempfile-insecure
Tempfile.new(SecureRandom.hex(8))

# ruleid: ruby.security.weak-hash-md5
Digest::MD5.new

# ruleid: ruby.security.weak-hash-sha1
Digest::SHA1.hexdigest(password)

# ok: ruby.security.weak-hash-md5
Digest::SHA256.hexdigest(password)

# ruleid: ruby.security.ssl-verify-disabled
OpenSSL::SSL::VERIFY_NONE

# ok: ruby.security.ssl-verify-disabled
OpenSSL::SSL::VERIFY_PEER
