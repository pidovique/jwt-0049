#!/usr/bin/env python3
"""
APLICACIÓN SEMI-SEGURA - SQL INJECTION PREVENTION
Implementa algunas medidas de seguridad básicas pero aún tiene vulnerabilidades

Esta versión muestra:
- Validación básica de entrada
- Algunas consultas parametrizadas
- Filtrado de caracteres peligrosos
- Pero aún tiene algunas vulnerabilidades sutiles

Instalación:
pip install flask

Uso:
python nombresapp.....py
"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
import os
import re
import html

app = Flask(__name__)

class PartiallySecureDatabase:
    def __init__(self, db_name="partially_secure_lab.db"):
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
        
        # Datos de prueba (contraseñas hasheadas básicamente)
        test_users = [
            (1, 'admin', 'hashed_admin123', 'admin@lab.com', 'admin', 'FLAG{admin_secret_data}'),
            (2, 'user1', 'hashed_password1', 'user1@lab.com', 'user', 'user1_private_info'),
            (3, 'user2', 'hashed_password2', 'user2@lab.com', 'user', 'user2_private_info'),
            (4, 'guest', 'hashed_guest123', 'guest@lab.com', 'guest', 'guest_info'),
            (5, 'testuser', 'hashed_test123', 'test@lab.com', 'user', 'FLAG{hidden_flag}')
        ]
        
        test_products = [
            (1, 'Laptop Pro', 1299.99, 'High-end laptop', 'electronics'),
            (2, 'Wireless Mouse', 29.99, 'Ergonomic mouse', 'accessories'),
            (3, 'Mechanical Keyboard', 89.99, 'RGB keyboard', 'accessories'),
            (4, 'Monitor 4K', 399.99, '27-inch monitor', 'electronics'),
            (5, 'USB Cable', 9.99, 'USB-C cable', 'accessories')
        ]
        
        cursor.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)', test_users)
        cursor.executemany('INSERT INTO products VALUES (?, ?, ?, ?, ?)', test_products)
        
        conn.commit()
        conn.close()

# Funciones de seguridad básicas
def basic_sanitize(input_str):
    """Sanitización básica - remueve algunos caracteres peligrosos"""
    if not input_str:
        return ""
    
    # Remover caracteres más obviamente peligrosos
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "xp_", "sp_"]
    
    sanitized = str(input_str)
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")
    
    return sanitized

def validate_numeric(value):
    """Validación básica para valores numéricos"""
    try:
        return int(value)
    except ValueError:
        return None

def hash_password(password):
    """Simulación de hash de contraseña (muy básico)"""
    return f"hashed_{password}"

# Inicializar base de datos
db = PartiallySecureDatabase()

# Templates HTML (similares pero con mensajes de seguridad)
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Partially Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 400px; margin: 0 auto; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background: #28a745; color: white; border: none; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 10px; text-decoration: none; color: #28a745; }
        .result { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        .security-info { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0; }
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
        <div class="security-info">
            <strong>🛡️ Security Measures:</strong><br>
            ✓ Basic input sanitization<br>
            ✓ Some dangerous characters filtered<br>
            ⚠️ Still has some vulnerabilities
        </div>
        <h2>Partially Secure Login</h2>
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
        </div>
    </div>
</body>
</html>
'''

SEARCH_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Partially Secure Search</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        input { width: 70%; padding: 10px; margin: 5px 0; }
        button { width: 25%; padding: 10px; background: #28a745; color: white; border: none; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 10px; text-decoration: none; color: #28a745; }
        .result { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        .product { border: 1px solid #ddd; padding: 10px; margin: 5px 0; }
        .security-info { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0; }
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
        <div class="security-info">
            <strong>🛡️ Security Measures:</strong><br>
            ✓ Input sanitization applied<br>
            ✓ Dangerous characters filtered<br>
            ⚠️ Still vulnerable to advanced techniques
        </div>
        <h2>Product Search (Partially Secured)</h2>
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
    </div>
</body>
</html>
'''

USER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Partially Secure User Profile</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        input { width: 70%; padding: 10px; margin: 5px 0; }
        button { width: 25%; padding: 10px; background: #28a745; color: white; border: none; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 10px; text-decoration: none; color: #28a745; }
        .result { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        .user { border: 1px solid #ddd; padding: 10px; margin: 5px 0; }
        .security-info { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0; }
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
        <div class="security-info">
            <strong>🛡️ Security Measures:</strong><br>
            ✓ Numeric validation for user ID<br>
            ✓ Parameterized query used<br>
            ✓ Data type validation
        </div>
        <h2>User Profile (Secured)</h2>
        <form method="POST">
            <input type="text" name="user_id" placeholder="User ID (numbers only)" value="{{ user_id }}">
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
                <strong>Role:</strong> {{ user[4] }}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666;">
            <p><strong>Try User IDs:</strong> 1, 2, 3, 4, 5</p>
            <p><strong>Note:</strong> Only numeric IDs accepted</p>
        </div>
    </div>
</body>
</html>
'''

# Rutas con seguridad parcial
@app.route('/', methods=['GET', 'POST'])
def login():
    result = None
    query = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Aplicar sanitización básica
        username = basic_sanitize(username)
        password = basic_sanitize(password)
        
        # Hash de la contraseña para comparación
        hashed_password = hash_password(password)
        
        
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
        
        conn = sqlite3.connect('partially_secure_lab.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            if result:
                result = f"Login successful! Welcome {result[0][1]}"
            else:
                result = "Invalid credentials"
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
        
        # Aplicar sanitización básica
        sanitized_term = basic_sanitize(search_term)
        
        # Escape adicional de HTML
        sanitized_term = html.escape(sanitized_term)
        
        
        query = f"SELECT * FROM products WHERE name LIKE '%{sanitized_term}%' OR description LIKE '%{sanitized_term}%'"
        
        conn = sqlite3.connect('partially_secure_lab.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
        except Exception as e:
            result = [("Error", str(e), "", "", "")]
        
        conn.close()
    
    return render_template_string(SEARCH_TEMPLATE, result=result, query=query, search_term=search_term)

@app.route('/user', methods=['GET', 'POST'])
def user_profile():
    result = None
    query = None
    user_id = ""
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        
        # MEJORADO: Validación numérica estricta
        validated_id = validate_numeric(user_id)
        
        if validated_id is None:
            result = "Error: User ID must be a valid number"
            query = "No query executed - invalid input"
        else:
            
            query = "SELECT id, username, email, role FROM users WHERE id = ?"
            
            conn = sqlite3.connect('partially_secure_lab.db')
            cursor = conn.cursor()
            
            try:
                cursor.execute(query, (validated_id,))
                result = cursor.fetchall()
            except Exception as e:
                result = [("Error", str(e), "", "")]
            
            conn.close()
    
    return render_template_string(USER_TEMPLATE, result=result, query=query, user_id=user_id)

@app.route('/api/users')
def api_users():
    user_id = request.args.get('id', '1')
    
    # Validación mejorada para API
    validated_id = validate_numeric(user_id)
    
    if validated_id is None:
        return jsonify({
            'error': 'Invalid user ID - must be numeric',
            'query': 'No query executed'
        }), 400
    
    
    query = "SELECT id, username, email, role FROM users WHERE id = ?"
    
    conn = sqlite3.connect('partially_secure_lab.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(query, (validated_id,))
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
            'query': f'{query} with parameter: {validated_id}',
            'users': users
        })
    except Exception as e:
        return jsonify({
            'query': query,
            'error': str(e)
        }), 500
    finally:
        conn.close()

if __name__ == '__main__':
    
    
    app.run(debug=True, host='0.0.0.0', port=5001)
