from flask import Flask, redirect, send_from_directory
from flask_cors import CORS
from pathlib import Path

WEB_DIR = Path(__file__).parent / "web"

app = Flask(__name__)
CORS(app)

def serve(filename: str):
    return send_from_directory(WEB_DIR, filename)

@app.get("/")
def root():
    return redirect("/dashboard", code=302)

@app.get("/dashboard")
def dashboard():
    return serve("dashboard.html")

@app.get("/login")
def login():
    return serve("login.html")

@app.get("/register")
def register():
    return serve("register.html")

@app.get("/logout")
def logout():
    # Browser clears localStorage; this is just a convenience route.
    return redirect("/login", code=302)

# Static files (css/js/images/etc.)
@app.get("/<path:path>")
def static_files(path: str):
    return send_from_directory(WEB_DIR, path)

if __name__ == "__main__":
    print("Serving from:", WEB_DIR)
    app.run(host="127.0.0.1", port=8080, debug=True)
