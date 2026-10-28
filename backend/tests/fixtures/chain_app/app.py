"""Test fixture: weaknesses that connect into chains, and some that must not.

Never run. Read by tests/test_chain_analysis.py.

- run_query() is one SQL sink reached from two routes (branching):
  /admin/users: session check (forgeable: hardcoded secret key) + blocklist validation
  /report: no authentication, no validation
- /ping: command injection blocked by an allowlist regex (mitigated chain)
- /token-report: JWT-protected; the hardcoded key must NOT be linked to it
- /health, debug=True and API_TOKEN: findings with no data-flow relationship
"""
import re
import sqlite3
import subprocess

from flask import Flask, abort, request, session
from flask_jwt_extended import jwt_required

app = Flask(__name__)
app.secret_key = "dev-secret-do-not-use"
API_TOKEN = "tok_live_0123456789abcdef"


def get_db():
    return sqlite3.connect("app.db")


def run_query(sql):
    cursor = get_db().cursor()
    cursor.execute(sql)
    return cursor.fetchall()


@app.route("/admin/users")
def admin_users():
    if not session.get("is_admin"):
        abort(403)
    name = request.args.get("name", "")
    if "'" in name:
        abort(400)
    return str(run_query("SELECT * FROM users WHERE name = '" + name + "'"))


@app.route("/report")
def report():
    team = request.args.get("team", "")
    return str(run_query(f"SELECT * FROM reports WHERE team = '{team}'"))


@app.route("/token-report")
@jwt_required()
def token_report():
    region = request.args.get("region", "")
    cursor = get_db().cursor()
    cursor.execute(f"SELECT * FROM sales WHERE region = '{region}'")
    return str(cursor.fetchall())


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "")
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        abort(400)
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/health")
def health():
    cursor = get_db().cursor()
    cursor.execute("SELECT 1")
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
