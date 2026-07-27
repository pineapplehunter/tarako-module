import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/sign", methods=["POST"])
def sign():
    nonce_hex = request.json["nonce"]
    result = subprocess.check_output(["/mnt/tarako-app", nonce_hex])
    return result, 200, {"Content-Type": "text/plain"}


app.run(host="0.0.0.0", port=5000)
