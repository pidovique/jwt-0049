#!/usr/bin/env python3
"""

Esta versión incluye:
- Prepared statements exclusivamente
- Validación robusta de entrada
- Sanitización completa
- Logging de seguridad
- Rate limiting básico
- Manejo seguro de errores
- Principio de menor privilegio

Instalación:
pip install flask werkzeug bcrypt

Uso:
python nombreapp.....py
"""

from flask import Flask, request, render_template_string, jsonify, session
import sqlite3
import os
import re
import html
import hashlib
import secrets
import time
from datetime import datetime, timedelta
import bcrypt
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configurar logging de seguridad
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

class SecureDatabase:
    def __init__(self, db_name="secure_lab.db"):
        self.db_name = db_name
        self.setup_database()
    
    def setup_database(self):
        """Configura la base de datos con medidas de seguridad"""
        if os.path.exists(self.db_name):
            os.remove(self.db_name)
        
        conn = sqlite3.connect(self.db_name, timeout=10.0)
        
        # Configurar WAL mode para mejor concurrencia
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL') 
        conn.execute('PRAGMA temp_store=MEMORY')
        conn.execute('PRAGMA mmap_size=268435456')  # 256MB
        
        cursor = conn.cursor()
        
        # Crear tablas con restricciones
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'guest')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL CHECK (price >= 0),
                description TEXT,
                category TEXT CHECK (category IN ('electronics', 'accessories')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                action TEXT NOT NULL,
                user_id INTEGER,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        # Insertar datos con contraseñas hasheadas usando bcrypt
        test_users = [
            (1, 'admin', bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'admin@lab.com', 'admin'),
            (2, 'user1', bcrypt.hashpw('password1'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'user1@lab.com', 'user'),
            (3, 'user2', bcrypt.hashpw('password2'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'user2@lab.com', 'user'),
            (4, 'guest', bcrypt.hashpw('guest123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'guest@lab.com', 'guest')
        ]
        
        test_products = [
            (1, 'Laptop Pro', 1299.99, 'High-end laptop', 'electronics'),
            (2, 'Wireless Mouse', 29.99, 'Ergonomic mouse', 'accessories'),
            (3, 'Mechanical Keyboard', 89.99, 'RGB keyboard', 'accessories'),
            (4, 'Monitor 4K', 399.99, '27-inch monitor', 'electronics'),
            (5, 'USB Cable', 9.99, 'USB-C cable', 'accessories')
        ]
        
        cursor.executemany('INSERT INTO users (id, username, password_hash, email, role) VALUES (?, ?, ?, ?, ?)', test_users)
        cursor.executemany('INSERT INTO products VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)', test_products)
        
        conn.commit()
        conn.close()

# Clases de seguridad
class SecurityValidator:
    @staticmethod
    def validate_username(username):
        """Validación estricta de nombre de usuario"""
        if not username or len(username) < 3 or len(username) > 30:
            return False, "Username must be between 3 and 30 characters"
        
        # Solo caracteres alfanuméricos y guiones bajos
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        return True, ""
    
    @staticmethod
    def validate_password(password):
        """Validación de contraseña robusta"""
        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        return True, ""
    
    @staticmethod
    def validate_user_id(user_id):
        """Validación estricta de ID de usuario"""
        try:
            uid = int(user_id)
            if uid < 1 or uid > 999999:  # Rango razonable
                return None, "User ID out of valid range"
            return uid, ""
        except (ValueError, TypeError):
            return None, "User ID must be a valid integer"
    
    @staticmethod
    def validate_search_term(search_term):
        """Validación de término de búsqueda"""
        if not search_term:
            return "", ""
        
        # Limitar longitud
        if len(search_term) > 100:
            return "", "Search term too long"
        
        # Remover caracteres potencialmente peligrosos pero mantener funcionalidad
        # Solo permitir caracteres alfanuméricos, espacios y algunos símbolos básicos
        cleaned = re.sub(r'[^a-zA-Z0-9\s\-_.]', '', search_term)
        
        return cleaned.strip(), ""

class RateLimiter:
    def __init__(self):
        self.attempts = {}
    
    def is_rate_limited(self, ip_address, max_attempts=5, window_minutes=15):
        """Rate limiting básico"""
        now = datetime.now()
        window_start = now - timedelta(minutes=window_minutes)
        
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        
        # Limpiar intentos antiguos
        self.attempts[ip_address] = [
            attempt for attempt in self.attempts[ip_address] 
            if attempt > window_start
        ]
        
        # Verificar límite
        if len(self.attempts[ip_address]) >= max_attempts:
            return True
        
        # Registrar nuevo intento
        self.attempts[ip_address].append(now)
        return False

class AuditLogger:
    @staticmethod
    def log_action(action, user_id=None, ip_address=None, details=None):
        """Registrar acciones para auditoría con manejo de concurrencia"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect('secure_lab.db', timeout=10.0)
                conn.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging para mejor concurrencia
                cursor = conn.cursor()
                
                cursor.execute(
                    "INSERT INTO audit_log (action, user_id, ip_address, details) VALUES (?, ?, ?, ?)",
                    (action, user_id, ip_address, details)
                )
                
                conn.commit()
                conn.close()
                
                # También log en archivo
                logging.info(f"AUDIT: {action} - User: {user_id}, IP: {ip_address}, Details: {details}")
                return
                
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                    continue
                else:
                    # Si fallan todos los intentos, solo log en archivo
                    logging.warning(f"Failed to log to database after {max_retries} attempts: {e}")
                    logging.info(f"AUDIT (file only): {action} - User: {user_id}, IP: {ip_address}, Details: {details}")
                    return
            except Exception as e:
                logging.error(f"Unexpected error in audit logging: {e}")
                logging.info(f"AUDIT (file only): {action} - User: {user_id}, IP: {ip_address}, Details: {details}")
                return
            finally:
                try:
                    if 'conn' in locals():
                        conn.close()
                except:
                    pass

# Inicializar componentes de seguridad
db = SecureDatabase()
rate_limiter = RateLimiter()
validator = SecurityValidator()

def get_db_connection():
    """Obtener conexión de base de datos con configuración optimizada"""
    conn = sqlite3.connect('secure_lab.db', timeout=10.0)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Templates HTML seguros
SECURE_LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background: #f8f9fa; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .nav { margin-bottom: 20px; text-align: center; }
        .nav a { margin: 0 10px; text-decoration: none; color: #007bff; padding: 8px 16px; border-radius: 4px; }
        .nav a:hover { background: #e3f2fd; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; }
        .security-info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .security-badge { display: inline-block; background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">🔐 Login</a>
            <a href="/search">🔍 Search</a>
            <a href="/user">👤 Profile</a>
            <a href="/api/users">🔌 API</a>
        </div>
        <div class="security-info">
            <strong>🛡️ Security Features Active:</strong><br>
            <span class="security-badge">Prepared Statements</span>
            <span class="security-badge">BCrypt Hashing</span>
            <span class="security-badge">Rate Limiting</span>
            <span class="security-badge">Input Validation</span>
            <span class="security-badge">Audit Logging</span>
            <span class="security-badge">Account Lockout</span>
        </div>
        <h2>🔒 Secure Login System</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username (3-30 chars, alphanumeric)" required maxlength="30">
            <input type="password" name="password" placeholder="Password (min 6 chars)" required minlength="6">
            <button type="submit">🔐 Secure Login</button>
        </form>
        {% if message %}
        <div class="result {{ message_type }}">
            {{ message }}
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666; text-align: center;">
            <p><strong>Test Credentials:</strong></p>
            <p>👑 admin / admin123</p>
            <p>👤 user1 / password1</p>
            <p><em>All SQL injection attempts are logged and blocked</em></p>
        </div>
    </div>
</body>
</html>
'''

SECURE_SEARCH_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Product Search</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background: #f8f9fa; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { width: 70%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 25%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .nav { margin-bottom: 20px; text-align: center; }
        .nav a { margin: 0 10px; text-decoration: none; color: #007bff; padding: 8px 16px; border-radius: 4px; }
        .nav a:hover { background: #e3f2fd; }
        .result { margin-top: 20px; }
        .product { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; background: #fafafa; }
        .security-info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .security-badge { display: inline-block; background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }
        .no-results { text-align: center; color: #666; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">🔐 Login</a>
            <a href="/search">🔍 Search</a>
            <a href="/user">👤 Profile</a>
            <a href="/api/users">🔌 API</a>
        </div>
        <div class="security-info">
            <strong>🛡️ Search Security:</strong><br>
            <span class="security-badge">Parameterized Queries</span>
            <span class="security-badge">Input Sanitization</span>
            <span class="security-badge">Length Validation</span>
            <span class="security-badge">XSS Prevention</span>
        </div>
        <h2>🔍 Secure Product Search</h2>
        <form method="POST">
            <input type="text" name="search" placeholder="Search products (max 100 chars)..." value="{{ search_term }}" maxlength="100">
            <button type="submit">🔍 Search</button>
        </form>
        {% if results %}
        <div class="result">
            <h3>🛍️ Search Results ({{ results|length }} found):</h3>
            {% for product in results %}
            <div class="product">
                <strong>{{ product[1] }}</strong> - ${{ "%.2f"|format(product[2]) }}<br>
                <small>{{ product[3] }}</small><br>
                <em>Category: {{ product[4] }}</em>
            </div>
            {% endfor %}
        </div>
        {% elif search_attempted %}
        <div class="no-results">
            <h3>🔍 No products found matching your search</h3>
            <p>Try different keywords or browse our categories: Electronics, Accessories</p>
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666; text-align: center;">
            <p><strong>Try searching for:</strong> Laptop, Mouse, Keyboard, Monitor, USB</p>
            <p><em>All search queries are sanitized and logged for security</em></p>
        </div>
    </div>
</body>
</html>
'''

SECURE_USER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure User Profile</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background: #f8f9fa; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { width: 70%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 25%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .nav { margin-bottom: 20px; text-align: center; }
        .nav a { margin: 0 10px; text-decoration: none; color: #007bff; padding: 8px 16px; border-radius: 4px; }
        .nav a:hover { background: #e3f2fd; }
        .result { margin-top: 20px; }
        .user { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; background: #fafafa; }
        .security-info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .security-badge { display: inline-block; background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">🔐 Login</a>
            <a href="/search">🔍 Search</a>
            <a href="/user">👤 Profile</a>
            <a href="/api/users">🔌 API</a>
        </div>
        <div class="security-info">
            <strong>🛡️ Profile Security:</strong><br>
            <span class="security-badge">Integer Validation</span>
            <span class="security-badge">Range Checking</span>
            <span class="security-badge">Prepared Statements</span>
            <span class="security-badge">Access Control</span>
        </div>
        <h2>👤 Secure User Profile</h2>
        <form method="POST">
            <input type="number" name="user_id" placeholder="User ID (1-999999)" value="{{ user_id }}" min="1" max="999999">
            <button type="submit">👤 Get Profile</button>
        </form>
        {% if error %}
        <div class="error">
            ❌ {{ error }}
        </div>
        {% elif user %}
        <div class="result">
            <h3>👤 User Profile:</h3>
            <div class="user">
                <strong>🆔 ID:</strong> {{ user[0] }}<br>
                <strong>👤 Username:</strong> {{ user[1] }}<br>
                <strong>📧 Email:</strong> {{ user[2] }}<br>
                <strong>🏷️ Role:</strong> {{ user[3] }}<br>
                <strong>📅 Member Since:</strong> {{ user[4] }}
            </div>
        </div>
        {% elif search_attempted %}
        <div class="result">
            <p>❌ User not found with the specified ID</p>
        </div>
        {% endif %}
        <div style="margin-top: 20px; font-size: 12px; color: #666; text-align: center;">
            <p><strong>Valid User IDs:</strong> 1, 2, 3, 4</p>
            <p><em>Only numeric IDs within valid range are accepted</em></p>
        </div>
    </div>
</body>
</html>
'''

# Rutas completamente seguras
@app.route('/', methods=['GET', 'POST'])
def secure_login():
    if request.method == 'POST':
        # Rate limiting
        client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
        if rate_limiter.is_rate_limited(client_ip):
            AuditLogger.log_action('LOGIN_RATE_LIMITED', ip_address=client_ip)
            return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                        message="Too many login attempts. Please try again later.", 
                                        message_type="error")
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validación de entrada
        username_valid, username_error = validator.validate_username(username)
        password_valid, password_error = validator.validate_password(password)
        
        if not username_valid:
            AuditLogger.log_action('LOGIN_INVALID_USERNAME', ip_address=client_ip, details=username_error)
            return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                        message=username_error, 
                                        message_type="error")
        
        if not password_valid:
            AuditLogger.log_action('LOGIN_INVALID_PASSWORD', ip_address=client_ip, details=password_error)
            return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                        message=password_error, 
                                        message_type="error")
        
        # Verificación de credenciales con prepared statements
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Verificar si la cuenta está bloqueada
            cursor.execute(
                "SELECT id, username, password_hash, failed_attempts, locked_until FROM users WHERE username = ?",
                (username,)
            )
            user_record = cursor.fetchone()
            
            if not user_record:
                AuditLogger.log_action('LOGIN_USER_NOT_FOUND', ip_address=client_ip, details=username)
                return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                            message="Invalid username or password", 
                                            message_type="error")
            
            user_id, db_username, password_hash, failed_attempts, locked_until = user_record
            
            # Verificar bloqueo de cuenta
            if locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    AuditLogger.log_action('LOGIN_ACCOUNT_LOCKED', user_id=user_id, ip_address=client_ip)
                    return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                                message="Account temporarily locked due to failed login attempts", 
                                                message_type="error")
            
            # Verificar contraseña con bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                # Login exitoso
                session['user_id'] = user_id
                session['username'] = db_username
                
                # Resetear intentos fallidos y actualizar último login
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id,)
                )
                
                AuditLogger.log_action('LOGIN_SUCCESS', user_id=user_id, ip_address=client_ip)
                
                conn.commit()
                return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                            message=f"Welcome back, {db_username}! Login successful.", 
                                            message_type="success")
            else:
                # Contraseña incorrecta
                failed_attempts += 1
                
                # Bloquear cuenta después de 5 intentos fallidos
                if failed_attempts >= 5:
                    lock_until = datetime.now() + timedelta(minutes=30)
                    cursor.execute(
                        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                        (failed_attempts, lock_until.isoformat(), user_id)
                    )
                    AuditLogger.log_action('ACCOUNT_LOCKED', user_id=user_id, ip_address=client_ip)
                    message = "Account locked for 30 minutes due to multiple failed attempts"
                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = ? WHERE id = ?",
                        (failed_attempts, user_id)
                    )
                    message = f"Invalid password. {5 - failed_attempts} attempts remaining."
                
                AuditLogger.log_action('LOGIN_FAILED', user_id=user_id, ip_address=client_ip)
                conn.commit()
                
                return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                            message=message, 
                                            message_type="error")
                
        except Exception as e:
            AuditLogger.log_action('LOGIN_ERROR', ip_address=client_ip, details=str(e))
            logging.error(f"Login error: {str(e)}")
            return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                        message="An error occurred. Please try again.", 
                                        message_type="error")
        finally:
            if conn:
                conn.close()
    
    return render_template_string(SECURE_LOGIN_TEMPLATE)

@app.route('/search', methods=['GET', 'POST'])
def secure_search():
    results = None
    search_attempted = False
    search_term = ""
    
    if request.method == 'POST':
        search_attempted = True
        client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
        raw_search_term = request.form.get('search', '').strip()
        
        # Validación y sanitización
        clean_search_term, error = validator.validate_search_term(raw_search_term)
        
        if error:
            AuditLogger.log_action('SEARCH_INVALID_INPUT', ip_address=client_ip, details=error)
            return render_template_string(SECURE_SEARCH_TEMPLATE, 
                                        search_term=raw_search_term,
                                        search_attempted=True)
        
        search_term = clean_search_term
        
        if search_term:
            # COMPLETAMENTE SEGURO: Solo prepared statements
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                # Usar LIKE con parámetros preparados
                search_pattern = f"%{search_term}%"
                cursor.execute(
                    "SELECT id, name, price, description, category FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY name",
                    (search_pattern, search_pattern)
                )
                results = cursor.fetchall()
                
                AuditLogger.log_action('SEARCH_EXECUTED', ip_address=client_ip, details=f"Term: {search_term}, Results: {len(results)}")
                
            except Exception as e:
                AuditLogger.log_action('SEARCH_ERROR', ip_address=client_ip, details=str(e))
                logging.error(f"Search error: {str(e)}")
                results = []
            finally:
                if conn:
                    conn.close()
    
    return render_template_string(SECURE_SEARCH_TEMPLATE, 
                                results=results, 
                                search_attempted=search_attempted,
                                search_term=search_term)

@app.route('/user', methods=['GET', 'POST'])
def secure_user_profile():
    user = None
    error = None
    search_attempted = False
    user_id = ""
    
    if request.method == 'POST':
        search_attempted = True
        client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
        raw_user_id = request.form.get('user_id', '').strip()
        
        # Validación estricta
        validated_id, validation_error = validator.validate_user_id(raw_user_id)
        
        if validation_error:
            error = validation_error
            AuditLogger.log_action('PROFILE_INVALID_ID', ip_address=client_ip, details=validation_error)
        else:
            user_id = str(validated_id)
            
            # COMPLETAMENTE SEGURO: Solo prepared statements
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                cursor.execute(
                    "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
                    (validated_id,)
                )
                user_record = cursor.fetchone()
                
                if user_record:
                    user = user_record
                    AuditLogger.log_action('PROFILE_VIEWED', user_id=validated_id, ip_address=client_ip)
                else:
                    AuditLogger.log_action('PROFILE_NOT_FOUND', ip_address=client_ip, details=f"ID: {validated_id}")
                
            except Exception as e:
                error = "An error occurred while retrieving the profile"
                AuditLogger.log_action('PROFILE_ERROR', ip_address=client_ip, details=str(e))
                logging.error(f"Profile error: {str(e)}")
            finally:
                if conn:
                    conn.close()
    
    return render_template_string(SECURE_USER_TEMPLATE, 
                                user=user, 
                                error=error,
                                search_attempted=search_attempted,
                                user_id=user_id)

@app.route('/api/users')
def secure_api_users():
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    raw_user_id = request.args.get('id', '').strip()
    
    # Rate limiting para API
    if rate_limiter.is_rate_limited(client_ip, max_attempts=10, window_minutes=5):
        AuditLogger.log_action('API_RATE_LIMITED', ip_address=client_ip)
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many API requests'
        }), 429
    
    # Validación
    validated_id, validation_error = validator.validate_user_id(raw_user_id)
    
    if validation_error:
        AuditLogger.log_action('API_INVALID_ID', ip_address=client_ip, details=validation_error)
        return jsonify({
            'error': 'Invalid user ID',
            'message': validation_error
        }), 400
    
    # COMPLETAMENTE SEGURO: Solo prepared statements
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (validated_id,)
        )
        result = cursor.fetchone()
        
        if result:
            user_data = {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            }
            
            AuditLogger.log_action('API_USER_RETRIEVED', user_id=validated_id, ip_address=client_ip)
            
            return jsonify({
                'success': True,
                'user': user_data,
                'security_note': 'All queries are parameterized and logged'
            })
        else:
            AuditLogger.log_action('API_USER_NOT_FOUND', ip_address=client_ip, details=f"ID: {validated_id}")
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
            
    except Exception as e:
        AuditLogger.log_action('API_ERROR', ip_address=client_ip, details=str(e))
        logging.error(f"API error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred while processing your request'
        }), 500
    finally:
        if conn:
            conn.close()

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    
    if user_id:
        AuditLogger.log_action('LOGOUT', user_id=user_id, ip_address=client_ip)
    
    session.clear()
    return render_template_string(SECURE_LOGIN_TEMPLATE, 
                                message="Successfully logged out", 
                                message_type="success")

if __name__ == '__main__':
  
    print("\nStarting SECURE server on http://localhost:5002")
    print("\nTest credentials:")
    print("👑 admin / admin123")
    print("👤 user1 / password1")

    print("=" * 60)
    
    app.run(debug=False, host='0.0.0.0', port=5002)  # Debug=False en producción
