#!/usr/bin/env python3

from flask import Flask, render_template_string, request, redirect, url_for, session, flash, make_response
import hashlib
import json
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = 'csrf_demo_key_not_secure'  # No usar en producción

# Base de datos simple en memoria
users_db = {
    'superuser': {
        'password': hashlib.md5('123123'.encode()).hexdigest(),
        'role': 'user',
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    },
    'tyler': {
        'password': hashlib.md5('admin123'.encode()).hexdigest(),
        'role': 'admin',
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
}

# Log de peticiones para análisis
request_log = []

def log_request(method, endpoint, data, user=None):
    """Registrar peticiones HTTP para análisis"""
    # Manejar contexto de petición
    try:
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
    except RuntimeError:
        # Fuera del contexto de petición (ej. al iniciar la app)
        ip = 'localhost'
        user_agent = 'System'
    
    request_log.append({
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'method': method,
        'endpoint': endpoint,
        'data': data,
        'user': user,
        'ip': ip,
        'user_agent': user_agent
    })

def hash_password(password):
    """Hash simple de contraseña (no usar en producción)"""
    return hashlib.md5(password.encode()).hexdigest()

# ============================================================================
# PLANTILLAS HTML
# ============================================================================

# Plantilla base
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Aplicación Vulnerable CSRF{% endblock %}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #007bff;
        }
        .nav {
            background: #007bff;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .nav a {
            color: white;
            text-decoration: none;
            margin-right: 15px;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .nav a:hover {
            background: rgba(255,255,255,0.2);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"], textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background: #0056b3;
        }
        .alert {
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .alert-danger {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .alert-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        .user-info {
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .csrf-warning {
            background: #ffc107;
            color: #212529;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 5px solid #ff6b35;
        }
        .code-block {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        .log-entry {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 10px;
            margin: 5px 0;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎓 Aplicación Vulnerable CSRF</h1>
        </div>
        
        {% if session.username %}
        <div class="nav">
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('change_password') }}">Cambiar Contraseña</a>
            <a href="{{ url_for('contact') }}">Contacto</a>
            <a href="{{ url_for('admin_panel') }}">Admin Panel</a>
            <a href="{{ url_for('request_logs') }}">Logs</a>
            <a href="{{ url_for('logout') }}">Cerrar Sesión</a>
        </div>
        
        <div class="user-info">
            👤 <strong>Usuario:</strong> {{ session.username }} 
            | <strong>Rol:</strong> {{ session.role }}
            | <strong>Sesión:</strong> {{ session.get('session_id', 'N/A')[:8] }}...
        </div>
        {% endif %}

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-warning">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

# Página de inicio/login
LOGIN_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>🔐 Iniciar Sesión</h2>

<form method="POST">
    <div class="form-group">
        <label for="username">Nombre de usuario:</label>
        <input type="text" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Contraseña:</label>
        <input type="password" id="password" name="password" required>
    </div>
    <button type="submit">Iniciar Sesión</button>
</form>

<hr>
<h3>👥 Usuarios de Prueba</h3>
<div class="alert alert-warning">
    <strong>Usuario normal:</strong> superuser / 123123<br>
    <strong>Administrador:</strong> tyler / admin123
</div>

<hr>
<p><a href="{{ url_for('register') }}">¿No tienes cuenta? Regístrate aquí</a></p>
{% endblock %}
""")

# Página de registro
REGISTER_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>📝 Registro de Usuario</h2>

<form method="POST">
    <div class="form-group">
        <label for="username">Nombre de usuario:</label>
        <input type="text" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Contraseña:</label>
        <input type="password" id="password" name="password" required>
    </div>
    <div class="form-group">
        <label for="confirm_password">Confirmar contraseña:</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
    </div>
    <button type="submit">Registrarse</button>
</form>

<p><a href="{{ url_for('login') }}">¿Ya tienes cuenta? Inicia sesión aquí</a></p>
{% endblock %}
""")

# Dashboard principal
DASHBOARD_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>🏠 Dashboard</h2>

<div class="alert alert-success">
    ¡Bienvenido {{ session.username }}! Has iniciado sesión correctamente.
</div>

<h3>🎯 Escenario de Demostración CSRF</h3>
<p>Esta aplicación está diseñada para demostrar vulnerabilidades CSRF. Sigue estos pasos:</p>

<ol>
    <li><strong>Cambiar contraseña:</strong> Ve a "Cambiar Contraseña" e intenta cambiarla</li>
    <li><strong>Interceptar con Burp Suite:</strong> Configura Burp como proxy y captura la petición</li>
    <li><strong>Modificar método:</strong> Cambia la petición de POST a GET</li>
    <li><strong>Generar URL maliciosa:</strong> Copia la URL con parámetros</li>
    <li><strong>Ataque CSRF:</strong> Envía la URL a otro usuario via "Contacto"</li>
</ol>

<div class="csrf-warning">
    <strong>⚠️ VULNERABILIDAD CSRF PRESENTE</strong><br>
    Esta aplicación es intencionalmente vulnerable. El endpoint de cambio de contraseña 
    acepta tanto peticiones POST como GET sin protección CSRF.
</div>

<h3>📊 Estadísticas</h3>
<p><strong>Total de usuarios:</strong> {{ user_count }}</p>
<p><strong>Peticiones registradas:</strong> {{ request_count }}</p>
<p><strong>Última actividad:</strong> {{ last_activity }}</p>
{% endblock %}
""")

# Página de cambio de contraseña (VULNERABLE)
CHANGE_PASSWORD_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>🔑 Cambiar Contraseña</h2>

<div class="csrf-warning">
    <strong>⚠️ ENDPOINT VULNERABLE</strong><br>
    Este formulario acepta tanto POST como GET y NO tiene protección CSRF.
    Los parámetros se pueden manipular en la URL.
</div>

<form method="POST" action="{{ url_for('change_password') }}">
    <div class="form-group">
        <label for="old_password">Contraseña actual:</label>
        <input type="password" id="old_password" name="old_password" required>
    </div>
    <div class="form-group">
        <label for="new_password">Nueva contraseña:</label>
        <input type="password" id="new_password" name="new_password" required>
    </div>
    <div class="form-group">
        <label for="confirm_password">Confirmar nueva contraseña:</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
    </div>
    <button type="submit">Cambiar Contraseña</button>
</form>

<hr>
<h3>🔍 Para Burp Suite:</h3>
<div class="code-block">
1. Configura Burp Suite como proxy en tu navegador<br>
2. Intercept ON en Proxy tab<br>
3. Envía el formulario arriba<br>
4. En Burp: Click derecho → "Change request method"<br>
5. Copia la URL GET resultante<br>
6. Úsala como enlace malicioso
</div>

<h3>🎯 Ejemplo de URL maliciosa:</h3>
<div class="code-block">
http://localhost:5000/change_password?old_password=123123&new_password=hackeado&confirm_password=hackeado
</div>
{% endblock %}
""")

# Página de contacto
CONTACT_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>📧 Contactar Administrador</h2>

<div class="alert alert-warning">
    <strong>Simulación de phishing:</strong> Aquí es donde enviarías el enlace malicioso al administrador.
</div>

<form method="POST">
    <div class="form-group">
        <label for="subject">Asunto:</label>
        <input type="text" id="subject" name="subject" required>
    </div>
    <div class="form-group">
        <label for="message">Mensaje:</label>
        <textarea id="message" name="message" rows="5" required 
                  placeholder="Incluye aquí tu enlace malicioso..."></textarea>
    </div>
    <button type="submit">Enviar Mensaje</button>
</form>

<hr>
<h3>🎯 Ejemplo de mensaje de ataque:</h3>
<div class="code-block">
Asunto: Verificación urgente de seguridad<br><br>
Mensaje:<br>
Estimado administrador,<br>
Hemos detectado actividad sospechosa en su cuenta.<br>
Por favor verifique su información haciendo clic aquí:<br>
http://localhost:5000/change_password?old_password=admin123&new_password=pwned123&confirm_password=pwned123<br><br>
Atentamente,<br>
Equipo de Seguridad
</div>

<h3>📨 Mensajes Enviados:</h3>
{% for msg in messages %}
<div class="log-entry">
    <strong>[{{ msg.timestamp }}]</strong> De: {{ msg.from_user }}<br>
    <strong>Asunto:</strong> {{ msg.subject }}<br>
    <strong>Mensaje:</strong> {{ msg.message[:100] }}{% if msg.message|length > 100 %}...{% endif %}
</div>
{% endfor %}
{% endblock %}
""")

# Panel de administración
ADMIN_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>⚙️ Panel de Administración</h2>

{% if session.role != 'admin' %}
<div class="alert alert-danger">
    ❌ Acceso denegado. Solo administradores pueden ver esta página.
</div>
{% else %}

<div class="alert alert-success">
    ✅ Bienvenido al panel de administración, {{ session.username }}
</div>

<h3>👥 Usuarios del Sistema</h3>
<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
    <tr style="background: #f8f9fa; border-bottom: 2px solid #dee2e6;">
        <th style="padding: 10px; text-align: left;">Usuario</th>
        <th style="padding: 10px; text-align: left;">Rol</th>
        <th style="padding: 10px; text-align: left;">Creado</th>
        <th style="padding: 10px; text-align: left;">Hash Contraseña</th>
    </tr>
    {% for username, data in users.items() %}
    <tr style="border-bottom: 1px solid #dee2e6;">
        <td style="padding: 10px;">{{ username }}</td>
        <td style="padding: 10px;">
            <span style="background: {% if data.role == 'admin' %}#dc3545{% else %}#28a745{% endif %}; 
                         color: white; padding: 2px 6px; border-radius: 3px; font-size: 12px;">
                {{ data.role }}
            </span>
        </td>
        <td style="padding: 10px;">{{ data.created_at }}</td>
        <td style="padding: 10px; font-family: monospace; font-size: 11px;">{{ data.password[:16] }}...</td>
    </tr>
    {% endfor %}
</table>

<h3>🔒 Acciones de Administrador</h3>
<div style="display: flex; gap: 10px; margin: 20px 0;">
    <button onclick="alert('Función de administrador ejecutada')">Gestionar Usuarios</button>
    <button onclick="alert('Configuración actualizada')">Configuración</button>
    <button onclick="alert('Logs exportados')">Exportar Logs</button>
</div>

{% endif %}
{% endblock %}
""")

# Logs de peticiones
LOGS_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2>📋 Logs de Peticiones HTTP</h2>

<div class="alert alert-warning">
    <strong>Análisis de Tráfico:</strong> Aquí puedes ver todas las peticiones HTTP para identificar ataques CSRF.
</div>

<div style="margin: 20px 0;">
    <strong>Total de peticiones:</strong> {{ logs|length }}<br>
    <strong>Filtros:</strong> 
    <button onclick="filterLogs('GET')">Solo GET</button>
    <button onclick="filterLogs('POST')">Solo POST</button>
    <button onclick="filterLogs('all')">Todas</button>
</div>

{% for log in logs %}
<div class="log-entry" data-method="{{ log.method }}">
    <strong>[{{ log.timestamp }}]</strong> 
    <span style="background: {% if log.method == 'GET' %}#ffc107{% else %}#28a745{% endif %}; 
                 color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">
        {{ log.method }}
    </span>
    {{ log.endpoint }}<br>
    
    <strong>Usuario:</strong> {{ log.user or 'Anónimo' }} | 
    <strong>IP:</strong> {{ log.ip }}<br>
    
    {% if log.data %}
    <strong>Datos:</strong> 
    {% for key, value in log.data.items() %}
        {{ key }}={{ value }}{% if not loop.last %}&{% endif %}
    {% endfor %}
    {% endif %}
    
    <br><strong>User-Agent:</strong> {{ log.user_agent[:50] }}{% if log.user_agent|length > 50 %}...{% endif %}
</div>
{% endfor %}

<script>
function filterLogs(method) {
    const logs = document.querySelectorAll('.log-entry');
    logs.forEach(log => {
        if (method === 'all' || log.dataset.method === method) {
            log.style.display = 'block';
        } else {
            log.style.display = 'none';
        }
    });
}
</script>
{% endblock %}
""")

# ============================================================================
# RUTAS DE LA APLICACIÓN
# ============================================================================

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        log_request('POST', '/login', {
            'username': username,
            'password': '[REDACTED]'
        })
        
        if username in users_db and users_db[username]['password'] == hash_password(password):
            session['username'] = username
            session['role'] = users_db[username]['role']
            session['session_id'] = secrets.token_hex(16)
            flash(f'¡Bienvenido {username}!')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        log_request('POST', '/register', {
            'username': username,
            'password': '[REDACTED]'
        })
        
        if username in users_db:
            flash('El usuario ya existe')
        elif password != confirm_password:
            flash('Las contraseñas no coinciden')
        elif len(password) < 3:
            flash('La contraseña debe tener al menos 3 caracteres')
        else:
            users_db[username] = {
                'password': hash_password(password),
                'role': 'user',
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            flash(f'Usuario {username} registrado exitosamente')
            return redirect(url_for('login'))
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    log_request('GET', '/dashboard', {}, session['username'])
    
    return render_template_string(DASHBOARD_TEMPLATE,
        user_count=len(users_db),
        request_count=len(request_log),
        last_activity=request_log[-1]['timestamp'] if request_log else 'N/A'
    )

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash('Debe iniciar sesión primero')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # VULNERABILIDAD: Acepta tanto GET como POST
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        method_used = 'POST'
    else:  # GET - VULNERABLE
        old_password = request.args.get('old_password')
        new_password = request.args.get('new_password')
        confirm_password = request.args.get('confirm_password')
        method_used = 'GET'
    
    # Log de la petición
    log_request(method_used, '/change_password', {
        'old_password': '[REDACTED]',
        'new_password': '[REDACTED]',
        'confirm_password': '[REDACTED]'
    }, username)
    
    if old_password and new_password and confirm_password:
        # Validar contraseña actual
        if users_db[username]['password'] != hash_password(old_password):
            flash(f'❌ Contraseña actual incorrecta (método: {method_used})')
        elif new_password != confirm_password:
            flash(f'❌ Las contraseñas nuevas no coinciden (método: {method_used})')
        else:
            # VULNERABILIDAD: Cambio exitoso sin protección CSRF
            users_db[username]['password'] = hash_password(new_password)
            flash(f'✅ ¡Contraseña cambiada exitosamente! (método: {method_used})')
            
            # Log especial para cambios de contraseña
            log_request(f'{method_used}_PASSWORD_CHANGE', '/change_password', {
                'victim': username,
                'new_password_hint': new_password[:3] + '*' * (len(new_password) - 3),
                'method': method_used,
                'csrf_vulnerable': 'YES' if method_used == 'GET' else 'PARTIAL'
            }, username)
            
            if method_used == 'GET':
                flash('⚠️ ATAQUE CSRF DETECTADO: Contraseña cambiada via URL GET!')
    
    return render_template_string(CHANGE_PASSWORD_TEMPLATE)

# Variable global para almacenar mensajes
contact_messages = []

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        subject = request.form['subject']
        message = request.form['message']
        
        # Guardar mensaje
        contact_messages.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'from_user': session['username'],
            'subject': subject,
            'message': message
        })
        
        log_request('POST', '/contact', {
            'subject': subject,
            'message_length': len(message),
            'contains_url': 'change_password' in message.lower()
        }, session['username'])
        
        flash('✅ Mensaje enviado al administrador')
        
        # Simular que el admin hace clic en enlaces maliciosos
        if 'change_password' in message and 'http' in message:
            flash('🎯 SIMULACIÓN: El administrador ha hecho clic en tu enlace...')
    
    return render_template_string(CONTACT_TEMPLATE, messages=contact_messages)

@app.route('/admin_panel')
def admin_panel():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    log_request('GET', '/admin_panel', {}, session['username'])
    
    return render_template_string(ADMIN_TEMPLATE, users=users_db)

@app.route('/request_logs')
def request_logs():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Los logs más recientes primero
    sorted_logs = sorted(request_log, key=lambda x: x['timestamp'], reverse=True)
    
    return render_template_string(LOGS_TEMPLATE, logs=sorted_logs)

@app.route('/logout')
def logout():
    username = session.get('username', 'Anónimo')
    session.clear()
    flash(f'Sesión cerrada para {username}')
    return redirect(url_for('login'))

# Ruta especial para demostrar el ataque automatizado
@app.route('/simulate_attack')
def simulate_attack():
    """Simula automáticamente el ataque CSRF"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Generar URL maliciosa
    target_user = 'tyler'
    malicious_url = url_for('change_password', 
                           old_password='admin123',
                           new_password='pwned123',
                           confirm_password='pwned123',
                           _external=True)
    
    flash(f'🎯 URL maliciosa generada: {malicious_url}')
    flash('💡 Copia esta URL y envíala via "Contacto" para simular el ataque')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    print("🎓 APLICACIÓN WEB CSRF - DEMOSTRACIÓN ACADÉMICA")
    print("=" * 50)
    print("🌐 Servidor iniciado en: http://localhost:5000")
    print("👤 Usuarios de prueba:")
    print("   • superuser / 123123 (usuario normal)")
    print("   • tyler / admin123 (administrador)")
    print("=" * 50)
    print()
    
    # Crear algunos logs iniciales
    log_request('SYSTEM', '/startup', {'message': 'Aplicación iniciada'})
    
    app.run(debug=True, host='0.0.0.0', port=5001)
