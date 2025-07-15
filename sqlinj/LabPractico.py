#!/usr/bin/env python3
"""

Instalación:
pip install flask

"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
import os
import json

app = Flask(__name__)

class VulnerableDatabase:
    def __init__(self, db_name="vulnerable_lab.db"):
        self.db_name = db_name
        self.setup_database()
    
    def setup_database(self):
        """Configura la base de datos de prueba"""
        if os.path.exists(self.db_name):
            os.remove(self.db_name)
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Crear tablas
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                secret_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL,
                description TEXT,
                category TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                product_id INTEGER,
                quantity INTEGER,
                total REAL
            )
        ''')
        
        # Datos de prueba
        test_users = [
            (1, 'admin', 'admin123', 'admin@lab.com', 'admin', 'FLAG{admin_secret_data}'),
            (2, 'user1', 'password1', 'user1@lab.com', 'user', 'user1_private_info'),
            (3, 'user2', 'password2', 'user2@lab.com', 'user', 'user2_private_info'),
            (4, 'guest', 'guest123', 'guest@lab.com', 'guest', 'guest_info'),
            (5, 'testuser', 'test123', 'test@lab.com', 'user', 'FLAG{hidden_flag}')
        ]
        
        test_products = [
            (1, 'Laptop Pro', 1299.99, 'High-end laptop', 'electronics'),
            (2, 'Wireless Mouse', 29.99, 'Ergonomic mouse', 'accessories'),
            (3, 'Mechanical Keyboard', 89.99, 'RGB keyboard', 'accessories'),
            (4, 'Monitor 4K', 399.99, '27-inch monitor', 'electronics'),
            (5, 'USB Cable', 9.99, 'USB-C cable', 'accessories')
        ]
        
        test_orders = [
            (1, 1, 1, 1, 1299.99),
            (2, 2, 2, 2, 59.98),
            (3, 1, 3, 1, 89.99)
        ]
        
        cursor.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)', test_users)
        cursor.executemany('INSERT INTO products VALUES (?, ?, ?, ?, ?)', test_products)
        cursor.executemany('INSERT INTO orders VALUES (?, ?, ?, ?, ?)', test_orders)
        
        conn.commit()
        conn.close()

# Inicializar base de datos
db = VulnerableDatabase()

# Templates HTML
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login - SQL Injection Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 400px; margin: 0 auto; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 10px; text-decoration: none; color: #007cba; }
        .result { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Login</a>
            <a href="/search">Search Products</a>
            <a href="/user">User Profile</a>
            <a href="/api/users">API Users</a>
        </div>
        <h2>Login System</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if result %}
        <div class="result">
            <h3>SQL Query:</h3>
            <code>{{ query }}</code>
            <h3>Result:</h3>
            <pre>{{ result }}</pre>
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666;">
            <p><strong>Test Credentials:</strong></p>
            <p>admin / admin123</p>
            <p>user1 / password1</p>
            <p><strong>Try SQL Injection!</strong></p>
        </div>
    </div>
</body>
</html>
'''

SEARCH_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Product Search - SQL Injection Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        input { width: 70%; padding: 10px; margin: 5px 0; }
        button { width: 25%; padding: 10px; background: #007cba; color: white; border: none; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 10px; text-decoration: none; color: #007cba; }
        .result { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        .product { border: 1px solid #ddd; padding: 10px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Login</a>
            <a href="/search">Search Products</a>
            <a href="/user">User Profile</a>
            <a href="/api/users">API Users</a>
        </div>
        <h2>Product Search</h2>
        <form method="POST">
            <input type="text" name="search" placeholder="Search products..." value="{{ search_term }}">
            <button type="submit">Search</button>
        </form>
        {% if result %}
        <div class="result">
            <h3>SQL Query:</h3>
            <code>{{ query }}</code>
            <h3>Results:</h3>
            {% for item in result %}
            <div class="product">
                <strong>{{ item[1] }}</strong> - ${{ item[2] }}<br>
                <small>{{ item[3] }}</small>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666;">
            <p><strong>Try searching for:</strong> Laptop, Mouse, etc.</p>
            <p><strong>Try SQL Injection!</strong></p>
        </div>
    </div>
</body>
</html>
'''

USER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>User Profile - SQL Injection Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        input { width: 70%; padding: 10px; margin: 5px 0; }
        button { width: 25%; padding: 10px; background: #007cba; color: white; border: none; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 10px; text-decoration: none; color: #007cba; }
        .result { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        .user { border: 1px solid #ddd; padding: 10px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Login</a>
            <a href="/search">Search Products</a>
            <a href="/user">User Profile</a>
            <a href="/api/users">API Users</a>
        </div>
        <h2>User Profile</h2>
        <form method="POST">
            <input type="text" name="user_id" placeholder="User ID" value="{{ user_id }}">
            <button type="submit">Get Profile</button>
        </form>
        {% if result %}
        <div class="result">
            <h3>SQL Query:</h3>
            <code>{{ query }}</code>
            <h3>Profile:</h3>
            {% for user in result %}
            <div class="user">
                <strong>ID:</strong> {{ user[0] }}<br>
                <strong>Username:</strong> {{ user[1] }}<br>
                <strong>Email:</strong> {{ user[3] }}<br>
                <strong>Role:</strong> {{ user[4] }}<br>
                <strong>Secret:</strong> {{ user[5] }}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666;">
            <p><strong>Try User IDs:</strong> 1, 2, 3, 4, 5</p>
            <p><strong>Try SQL Injection!</strong></p>
        </div>
    </div>
</body>
</html>
'''

# Rutas vulnerables
@app.route('/', methods=['GET', 'POST'])
def login():
    result = None
    query = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: Concatenación directa
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = sqlite3.connect('vulnerable_lab.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
        except Exception as e:
            result = f"Error: {str(e)}"
        
        conn.close()
    
    return render_template_string(LOGIN_TEMPLATE, result=result, query=query)

@app.route('/search', methods=['GET', 'POST'])
def search():
    result = None
    query = None
    search_term = ""
    
    if request.method == 'POST':
        search_term = request.form['search']
        
        # VULNERABLE: Sin escape de caracteres
        query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"
        
        conn = sqlite3.connect('vulnerable_lab.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
        except Exception as e:
            result = [("Error", str(e), "", "")]
        
        conn.close()
    
    return render_template_string(SEARCH_TEMPLATE, result=result, query=query, search_term=search_term)

@app.route('/user', methods=['GET', 'POST'])
def user_profile():
    result = None
    query = None
    user_id = ""
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        
        # VULNERABLE: Sin validación de tipo
        query = f"SELECT * FROM users WHERE id = {user_id}"
        
        conn = sqlite3.connect('vulnerable_lab.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
        except Exception as e:
            result = [("Error", str(e), "", "", "", "")]
        
        conn.close()
    
    return render_template_string(USER_TEMPLATE, result=result, query=query, user_id=user_id)

@app.route('/api/users')
def api_users():
    user_id = request.args.get('id', '1')
    
    # VULNERABLE: API endpoint
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    
    conn = sqlite3.connect('vulnerable_lab.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        
        users = []
        for row in result:
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3]
            })
        
        return jsonify({
            'query': query,
            'users': users
        })
    except Exception as e:
        return jsonify({
            'query': query,
            'error': str(e)
        })
    finally:
        conn.close()

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE WEB APPLICATION - SQL INJECTION LAB")
    print("=" * 60)
    print("WARNING: This application is INTENTIONALLY vulnerable!")
    print("Only for educational purposes in controlled environments")
    print("NEVER use this code in production!")
    print("=" * 60)
    print("\nStarting server on http://localhost:5000")
    print("\nAvailable endpoints:")
    print("- http://localhost:5000/        (Login)")
    print("- http://localhost:5000/search  (Product Search)")
    print("- http://localhost:5000/user    (User Profile)")
    print("- http://localhost:5000/api/users (API)")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
