"""HTTP routes for the demo app."""
from flask import Flask, request

from app.db import check_login

app = Flask(__name__)


@app.get("/")
def index():
    return "ok"


@app.post("/login")
def login():
    form = request.form
    user = form.get("user")  # attacker-controlled
    password = form.get("pass")
    # line 20: no validation, flows straight to the query builder
    ok = check_login(user, password)
    return "welcome" if ok else "denied"
