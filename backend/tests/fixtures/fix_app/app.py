"""Test fixture for the post-fix validation loop. Never run.

/login has two SQL sinks fed by the same input: fixing only the first one
leaves an alternative path to the same outcome (SQL injection via /login).
/search is already parameterized and must stay untouched.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    cursor = get_db().cursor()
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    cursor.execute(f"INSERT INTO audit (username) VALUES ('{username}')")
    if user:
        return "ok"
    return "invalid credentials", 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    cursor = get_db().cursor()
    cursor.execute("SELECT name FROM items WHERE name = ?", (term,))
    return str(cursor.fetchall())
