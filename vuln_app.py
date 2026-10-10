#!/usr/bin/env python3
"""
vuln_app.py — deliberately vulnerable web app for testing pymap/pyscan.
Runs against the local MariaDB instance started by the test harness.
NEVER expose this app to a network - it is intentionally full of SQLi.

Endpoints (all injectable in different ways):
  GET  /product?id=1       numeric injection, results echoed  (error/bool/union)
  GET  /user?name=alice    string injection, results echoed    (error/bool/union)
  GET  /exists?id=1         numeric injection, only FOUND/NOT FOUND diff (blind)
  GET  /vote?id=1           constant output - only time-based works
  GET  /search?q=widget    LIKE-context injection
  POST /login              POST-body string injection (username field)
  GET  /account             cookie-based numeric injection (uid cookie)
"""
import os
import pymysql
from flask import Flask, request

DB_SOCKET = os.environ.get("PYMAP_DB_SOCKET", "/home/ed/pysqlmap/mysqldata/mysql.sock")
DB_USER = os.environ.get("PYMAP_DB_USER", "root")
DB_NAME = os.environ.get("PYMAP_DB_NAME", "shopdb")

app = Flask(__name__)


def db():
    return pymysql.connect(unix_socket=DB_SOCKET, user=DB_USER, database=DB_NAME,
                          cursorclass=pymysql.cursors.DictCursor)


def q(sql):
    """Run query, return rows. Errors are deliberately echoed (verbose errors)."""
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()
    except Exception as e:
        return {"__error__": str(e)}
    finally:
        conn.close()


@app.route("/")
def index():
    return """<h1>vuln shop</h1>
<ul>
<li><a href="/product?id=1">product?id=1</a></li>
<li><a href="/user?name=alice">user?name=alice</a></li>
<li><a href="/exists?id=1">exists?id=1</a></li>
<li><a href="/vote?id=1">vote?id=1</a></li>
<li><a href="/search?q=widget">search?q=widget</a></li>
<li><a href="/account">account (cookie uid=1)</a></li>
</ul>
<form method="POST" action="/login"><input type="hidden" name="csrf_token" value="abc123"><input name="username" value="alice">
<input name="password" value="x"><button>login</button></form>
"""


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    rows = q(f"SELECT id, name, price FROM products WHERE id={pid}")
    if "__error__" in rows:
        return f"<html><body>product error: {rows['__error__']}</body></html>", 500
    out = ["<html><body><table>"]
    for r in rows:
        out.append(f"<tr><td>{r['id']}</td><td>{r['name']}</td><td>{r['price']}</td></tr>")
    out.append("</table></body></html>")
    return "".join(out)


@app.route("/user")
def user():
    name = request.args.get("name", "alice")
    rows = q(f"SELECT username, email FROM users WHERE username='{name}'")
    if isinstance(rows, dict):
        return f"<html><body>user error: {rows['__error__']}</body></html>", 500
    out = ["<html><body><table>"]
    for r in rows:
        out.append(f"<tr><td>{r['username']}</td><td>{r['email']}</td></tr>")
    out.append("</table></body></html>")
    return "".join(out)


@app.route("/exists")
def exists():
    uid = request.args.get("id", "1")
    rows = q(f"SELECT id FROM users WHERE id={uid}")
    if isinstance(rows, dict):
        return "server error", 500
    return "FOUND" if rows else "NOT FOUND"


@app.route("/vote")
def vote():
    pid = request.args.get("id", "1")
    q(f"SELECT id FROM products WHERE id={pid}")
    return "Vote recorded. Thank you!"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    rows = q(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'")
    if isinstance(rows, dict):
        return f"<html><body>search error: {rows['__error__']}</body></html>", 500
    out = ["<html><body><table>"]
    for r in rows:
        out.append(f"<tr><td>{r['name']}</td><td>{r['price']}</td></tr>")
    out.append("</table></body></html>")
    return "".join(out)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return '<form method="POST"><input name="username"><input name="password"></form>'
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    rows = q(f"SELECT username, email FROM users WHERE username='{u}' "
             f"AND password_hash='{p}'")
    if isinstance(rows, dict):
        return f"login error: {rows['__error__']}", 500
    if rows:
        return f"Welcome back, {rows[0]['username']} ({rows[0]['email']})"
    return "Invalid credentials"


@app.route("/account")
def account():
    uid = request.cookies.get("uid", "1")
    rows = q(f"SELECT username, email FROM users WHERE id={uid}")
    if isinstance(rows, dict):
        return f"account error: {rows['__error__']}", 500
    if not rows:
        return "no such account"
    r = rows[0]
    return f"Account: {r['username']} &lt;{r['email']}&gt;"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
