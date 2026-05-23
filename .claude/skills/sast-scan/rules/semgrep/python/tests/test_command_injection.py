import subprocess
import os

# Positive: shell=True with variable input
# ruleid: python.security.command-injection-subprocess
subprocess.run(cmd, shell=True)

# ruleid: python.security.command-injection-subprocess
subprocess.run(user_input, shell=True, capture_output=True)

# ruleid: python.security.command-injection-subprocess
subprocess.call(command, shell=True)

# Negative: shell=True with literal string (may be acceptable)
# ok: python.security.command-injection-subprocess
subprocess.run("echo hello", shell=True)

# Negative: no shell=True
# ok: python.security.command-injection-subprocess
subprocess.run(["ping", "-c", "3", host])

# ok: python.security.command-injection-subprocess
subprocess.run(["ls", "-la"])
