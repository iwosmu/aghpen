"""Room booking demo: a Flask app behind gunicorn. It stores a guest marker in
the signed Flask session, so every visitor gets a 'session' cookie whose value
is base64 JSON, like a JWT. The key below protects nothing."""
from flask import Flask, session

app = Flask(__name__)
app.secret_key = "lab-only-not-a-secret"

PAGE = """<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Rezerwacja sal — WIMiIP</title></head>
<body>
<h1>Rezerwacja sal</h1>
<p>Zaloguj się, aby zarezerwować salę.</p>
<form method="get" action="/login"><input name="user"><input type="password" name="pass"><button>Zaloguj</button></form>
</body>
</html>
"""


@app.route("/")
def index():
    session["user"] = "gosc"
    session["role"] = "anon"
    return PAGE


@app.route("/login")
def login():
    return PAGE
