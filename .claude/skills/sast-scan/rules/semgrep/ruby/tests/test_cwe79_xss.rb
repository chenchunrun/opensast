# CWE-79: XSS / CWE-601: Open Redirect
def test_xss(user_input)
  # ruleid: ruby.security.xss-raw
  raw(user_input)
  # ruleid: ruby.security.xss-raw
  user_input.html_safe

  # ok: ruby.security.xss-raw
  raw(h(user_input))
  # ok: ruby.security.xss-raw
  h(user_input)
end
