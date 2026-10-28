import sqlite3
import subprocess
import pickle
from flask import Flask, request

app = Flask(__name__)
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))
