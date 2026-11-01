import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BUNDLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bundle.bin")

PAGE = """
<h2>PQC OTA bundle server</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file" required>
  <button type="submit">Upload bundle</button>
</form>
<p>Current bundle: {info}</p>
"""


@app.get("/")
def index():
    if os.path.exists(BUNDLE_PATH):
        info = f"{os.path.getsize(BUNDLE_PATH)} bytes"
    else:
        info = "none uploaded yet"
    return PAGE.format(info=info)

@app.post("/upload")
def upload():
    f = request.files.get("file")
    if f is None or f.filename == "":
        abort(400, "no file")
    f.save(BUNDLE_PATH)
    size = os.path.getsize(BUNDLE_PATH)
    print(f"[server] stored bundle: {size} bytes")
    return f"Uploaded OK ({size} bytes). <a href='/'>back</a>"


@app.get("/firmware")
def firmware():
    if not os.path.exists(BUNDLE_PATH):
        abort(404, "no bundle uploaded yet")
    print("[server] ESP32 requested /firmware")
    return send_file(BUNDLE_PATH, mimetype="application/octet-stream")



if __name__ == "__main__":
    # 0.0.0.0 = reachable from other devices on your Wi-Fi/LAN
    app.run(host="0.0.0.0", port=8080)