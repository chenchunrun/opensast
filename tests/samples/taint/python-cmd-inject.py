from flask import Flask, request

app = Flask(__name__)

# ruleid: taint.command - user input flows to command execution
@app.route("/ping")
def ping():
    host = request.args.get("host")
    import subprocess
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout
