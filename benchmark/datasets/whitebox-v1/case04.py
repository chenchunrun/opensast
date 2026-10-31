from flask import request
import subprocess

def resolve_host():
    host = request.args.get("host")
    return subprocess.check_output(["nslookup", host], shell=False)
