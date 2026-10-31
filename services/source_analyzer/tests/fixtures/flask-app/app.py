from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.get("/search")
def search():
    q = request.args.get("q")
    return sqlite3.connect("db").execute(f"SELECT * FROM t WHERE x = '{q}'").fetchall()
