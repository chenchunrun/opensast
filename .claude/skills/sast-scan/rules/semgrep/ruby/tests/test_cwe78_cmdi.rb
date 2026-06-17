# CWE-78: Command Injection
def test_command_injection(user_input)
  # ruleid: ruby.security.command-injection
  system("ls #{user_input}")
  # ruleid: ruby.security.command-injection
  exec("cat #{user_input}")
  # ruleid: ruby.security.command-injection
  `ping #{user_input}`

  # ok: ruby.security.command-injection
  system("ls", "-la")
  # ok: ruby.security.command-injection
  system("echo", "hello")
end
