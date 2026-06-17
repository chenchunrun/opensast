# CWE-916 / CWE-328: Weak Crypto / CWE-798: Hardcoded Credentials
def test_weak_crypto(password)
  # ruleid: ruby.security.weak-password-hash
  Digest::MD5.hexdigest(password)

  # ruleid: ruby.security.weak-hash-md5
  Digest::MD5.new

  # ruleid: ruby.security.weak-hash-sha1
  Digest::SHA1.new

  # ok: ruby.security.weak-password-hash
  BCrypt::Password.create(password)

  # ok: ruby.security.weak-hash-md5
  Digest::SHA256.hexdigest("data")
end

def test_hardcoded_credentials
  # ruleid: ruby.security.session-secret-hardcoded
  secret_key_base = "abcdef1234567890"
  # ruleid: ruby.security.hardcoded-credentials
  password = "super_secret_pass"

  # ok: ruby.security.session-secret-hardcoded
  secret_key_base = ENV['SECRET_KEY_BASE']
  # ok: ruby.security.hardcoded-credentials
  token = ENV['API_TOKEN']
end
