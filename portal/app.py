#!/usr/bin/env python3
"""SentinelForge supplier portal: deliberately vulnerable Flask app for the lab.
Vulns: CWE-89 SQLi at GET /flights/search?origin= ; CWE-521+307 weak auth at POST /admin/login ;
CWE-434 arbitrary upload at POST /admin/upload"""
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory
import sqlite3, os, bcrypt

app = Flask(__name__)
app.secret_key = 'sf-lab-key-not-a-secret'
UPLOAD_FOLDER = '/opt/sf-portal/uploads'
DB_PATH = '/opt/sf-portal/flights.db'

def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/flights/search')
def flights_search():
    origin = request.args.get('origin', '')
    conn = get_db(); cursor = conn.cursor()
    query = f"SELECT flight_no, origin, destination, departure, price FROM flights WHERE origin = '{origin}'"  # SQLi on purpose
    try:
        cursor.execute(query); results = cursor.fetchall(); error = None
    except Exception as e:
        results = []; error = str(e)
    conn.close()
    return render_template('search.html', results=results, origin=origin, error=error, query=query)

@app.route('/admin', methods=['GET'])
def admin_index():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    return render_template('admin_upload.html', username=session.get('username'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html', error=None)
    username = request.form.get('username', ''); password = request.form.get('password', '')
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone(); conn.close()
    if row and bcrypt.checkpw(password.encode(), row['password_hash'].encode()):
        session['admin'] = True; session['username'] = username
        return redirect(url_for('admin_index'))
    return render_template('admin_login.html', error='Invalid credentials'), 401

@app.route('/admin/logout')
def admin_logout():
    session.clear(); return redirect(url_for('index'))

@app.route('/admin/upload', methods=['POST'])
def admin_upload():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if 'file' not in request.files:
        return 'No file part', 400
    f = request.files['file']
    if f.filename == '':
        return 'No selected file', 400
    filepath = os.path.join(UPLOAD_FOLDER, f.filename); f.save(filepath)
    return f'File uploaded to {filepath}', 200

@app.route('/uploads/<path:filename>')
def uploads_serve(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/debug/health')
def debug_health():
    return {'status': 'ok', 'service': 'sf-portal', 'version': '1.0.0'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
