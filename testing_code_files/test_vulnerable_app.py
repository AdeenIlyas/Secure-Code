from flask import Flask, request, render_template_string, redirect, session
import os
import subprocess
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "very_secret_key_for_testing"  # Insecure hardcoded secret key

# Create a simple database
conn = sqlite3.connect('test_database.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    message TEXT
)
''')
conn.commit()
conn.close()

@app.route('/')
def index():
    # Vulnerable template (XSS)
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Vulnerable App</title>
    </head>
    <body>
        <h1>Welcome to the Test Vulnerable App</h1>
        <p>This app has intentional vulnerabilities for ZAP scanning.</p>
        
        <h2>Login</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <input type="submit" value="Login">
        </form>
        
        <h2>Search</h2>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search term">
            <input type="submit" value="Search">
        </form>
        
        <h2>Execute Command (Dangerous!)</h2>
        <form action="/execute" method="POST">
            <input type="text" name="command" placeholder="System command">
            <input type="submit" value="Execute">
        </form>
        
        {% if query %}
        <h3>Search Results for: {{ query }}</h3>
        {% endif %}
    </body>
    </html>
    '''
    query = request.args.get('q', '')
    return render_template_string(template, query=query)  # XSS vulnerability

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "Missing username or password"
    
    # Insecure authentication (plain text passwords)
    conn = sqlite3.connect('test_database.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        return redirect('/')
    
    # Create user if not exists (insecure password storage)
    conn = sqlite3.connect('test_database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    session['user_id'] = user_id
    return redirect('/')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return redirect(f'/?q={query}')  # Open redirect vulnerability

@app.route('/execute', methods=['POST'])
def execute():
    # Command injection vulnerability
    command = request.form.get('command', 'echo "No command provided"')
    output = subprocess.check_output(command, shell=True)
    return f"Command output: {output.decode()}"

@app.route('/api/user/<user_id>')
def user_api(user_id):
    # IDOR vulnerability
    conn = sqlite3.connect('test_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"id": user_id, "username": user[0]}
    return {"error": "User not found"}

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Path traversal vulnerability
    with open(filename, 'r') as f:
        content = f.read()
    return content

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Write the port to a status file for the scanning container
    with open('app_status.json', 'w') as f:
        f.write('{"status": "running", "port": ' + str(port) + '}')
    
    print(f"Test vulnerable app running on port {port}")
    app.run(host='0.0.0.0', port=port) 
