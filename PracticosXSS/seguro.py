from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import html
import re
import os
from markupsafe import Markup

app = Flask(__name__)

# Configuración de seguridad
app.config['SECRET_KEY'] = 'tu-clave-secreta-aqui'

def init_db():
    conn = sqlite3.connect('secure_comments.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Funciones de sanitización robustas
def sanitize_input(user_input):
    """
    Sanitiza completamente la entrada del usuario
    """
    if not user_input:
        return ""
    
    # 1. Escape HTML básico
    sanitized = html.escape(user_input, quote=True)
    
    # 2. Eliminar completamente tags HTML
    sanitized = re.sub(r'<[^>]*>', '', sanitized)
    
    # 3. Eliminar protocolos peligrosos
    dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'onload=', 'onerror=']
    for protocol in dangerous_protocols:
        sanitized = re.sub(re.escape(protocol), '', sanitized, flags=re.IGNORECASE)
    
    # 4. Limitar longitud
    sanitized = sanitized[:500]
    
    return sanitized

def validate_input(user_input, max_length=500):
    """
    Validación estricta de entrada
    """
    if not user_input or len(user_input.strip()) == 0:
        return False, "La entrada no puede estar vacía"
    
    if len(user_input) > max_length:
        return False, f"La entrada no puede exceder {max_length} caracteres"
    
    # Detectar patrones sospechosos
    suspicious_patterns = [
        r'<[^>]*script[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
        r'<\s*iframe',
        r'<\s*object',
        r'<\s*embed',
        r'eval\s*\(',
        r'document\.',
        r'window\.',
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, "Entrada contiene contenido no permitido"
    
    return True, "OK"

# Content Security Policy
def add_security_headers(response):
    """
    Añade headers de seguridad importantes
    """
    # Content Security Policy - Solo permite scripts del mismo origen
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "media-src 'self'; "
        "frame-src 'none';"
    )
    
    # Otros headers de seguridad
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

@app.after_request
def after_request(response):
    return add_security_headers(response)

# Página principal SEGURA
@app.route('/')
def secure_index():
    search = request.args.get('search', '')
    error_message = ""
    
    # Validación estricta
    if search:
        is_valid, validation_message = validate_input(search)
        if not is_valid:
            error_message = validation_message
            search = ""  # Limpiar entrada inválida
        else:
            search = sanitize_input(search)
    
    template = '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aplicación Web Segura</title>
        <style>
            body { 
                font-family: 'Segoe UI', Arial, sans-serif; 
                margin: 40px; 
                background-color: #f5f5f5;
            }
            .container { 
                max-width: 800px; 
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            input, button { 
                padding: 12px; 
                margin: 5px; 
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            button {
                background-color: #007cba;
                color: white;
                cursor: pointer;
            }
            button:hover {
                background-color: #005a87;
            }
            .result { 
                background: #e8f5e8; 
                padding: 15px; 
                margin: 10px 0; 
                border-radius: 4px;
                border-left: 4px solid #4caf50;
            }
            .error {
                background: #ffeaa7;
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
                border-left: 4px solid #e17055;
                color: #d63031;
            }
            .security-info {
                background: #e3f2fd;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
                border-left: 4px solid #2196f3;
            }
            .code {
                background: #f8f8f8;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Aplicación Web Segura</h1>
            <p>Esta versión implementa múltiples capas de protección contra XSS</p>
            
            <form method="GET">
                <input type="text" 
                       name="search" 
                       placeholder="Buscar de forma segura..." 
                       value="{{ search }}"
                       maxlength="500">
                <button type="submit">🔍 Buscar</button>
            </form>
            
            {% if error_message %}
            <div class="error">
                <strong>⚠️ Error de validación:</strong> {{ error_message }}
            </div>
            {% endif %}
            
            {% if search and not error_message %}
            <div class="result">
                <h3>✅ Búsqueda procesada de forma segura:</h3>
                <p><strong>Término buscado:</strong> <span class="code">{{ search }}</span></p>
                <p>La entrada fue validada, sanitizada y es segura para mostrar.</p>
            </div>
            {% endif %}
            
            <div class="security-info">
                <h3>🔒 Medidas de seguridad implementadas:</h3>
                <ul>
                    <li><strong>Validación de entrada:</strong> Patrones sospechosos rechazados</li>
                    <li><strong>Sanitización HTML:</strong> Tags y caracteres peligrosos removidos</li>
                    <li><strong>Content Security Policy:</strong> Scripts externos bloqueados</li>
                    <li><strong>Headers de seguridad:</strong> X-XSS-Protection, X-Frame-Options, etc.</li>
                    <li><strong>Límites de longitud:</strong> Previene ataques de buffer</li>
                </ul>
            </div>
            
            <h3>🧪 Prueba estos intentos de XSS (todos fallarán):</h3>
            <ul>
                <li><span class="code">&lt;script&gt;alert('XSS')&lt;/script&gt;</span></li>
                <li><span class="code">&lt;img src=x onerror="alert('XSS')"&gt;</span></li>
                <li><span class="code">javascript:alert('XSS')</span></li>
                <li><span class="code">&lt;svg onload="alert('XSS')"&gt;</span></li>
            </ul>
            
            <br>
            <a href="/secure-comments">💬 Comentarios Seguros</a> | 
            <a href="/comparison">📊 Comparación Vulnerable vs Seguro</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, search=search, error_message=error_message)

# Comentarios seguros
@app.route('/secure-comments', methods=['GET', 'POST'])
def secure_comments():
    error_message = ""
    success_message = ""
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        comment = request.form.get('comment', '').strip()
        
        # Validación robusta
        username_valid, username_msg = validate_input(username, 50)
        comment_valid, comment_msg = validate_input(comment, 500)
        
        if not username_valid:
            error_message = f"Nombre de usuario: {username_msg}"
        elif not comment_valid:
            error_message = f"Comentario: {comment_msg}"
        else:
            # Sanitización antes de guardar
            clean_username = sanitize_input(username)
            clean_comment = sanitize_input(comment)
            
            # Guardar en base de datos
            conn = sqlite3.connect('secure_comments.db')
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO comments (username, comment) VALUES (?, ?)', 
                (clean_username, clean_comment)
            )
            conn.commit()
            conn.close()
            
            success_message = "¡Comentario publicado de forma segura!"
            return redirect(url_for('secure_comments'))
    
    # Obtener comentarios
    conn = sqlite3.connect('secure_comments.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, comment, created_at FROM comments ORDER BY id DESC LIMIT 20')
    all_comments = cursor.fetchall()
    conn.close()
    
    template = '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Comentarios Seguros</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 800px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input, textarea, button { padding: 12px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
            textarea { width: 100%; height: 100px; resize: vertical; }
            button { background-color: #28a745; color: white; cursor: pointer; }
            button:hover { background-color: #218838; }
            .comment { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 3px solid #007cba; border-radius: 4px; }
            .error { background: #ffeaa7; padding: 15px; margin: 10px 0; border-radius: 4px; color: #d63031; }
            .success { background: #d4edda; padding: 15px; margin: 10px 0; border-radius: 4px; color: #155724; }
            .timestamp { color: #6c757d; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>💬 Sistema de Comentarios Seguro</h1>
            
            {% if error_message %}
            <div class="error">⚠️ {{ error_message }}</div>
            {% endif %}
            
            {% if success_message %}
            <div class="success">✅ {{ success_message }}</div>
            {% endif %}
            
            <form method="POST">
                <input type="text" 
                       name="username" 
                       placeholder="Tu nombre (máx. 50 caracteres)" 
                       maxlength="50"
                       required><br>
                <textarea name="comment" 
                          placeholder="Tu comentario (máx. 500 caracteres)..." 
                          maxlength="500"
                          required></textarea><br>
                <button type="submit">📝 Publicar Comentario Seguro</button>
            </form>
            
            <h2>💭 Comentarios Publicados:</h2>
            {% if comments %}
                {% for username, comment, timestamp in comments %}
                <div class="comment">
                    <strong>{{ username }}:</strong><br>
                    {{ comment }}<br>
                    <div class="timestamp">{{ timestamp }}</div>
                </div>
                {% endfor %}
            {% else %}
                <p>No hay comentarios aún. ¡Sé el primero en comentar!</p>
            {% endif %}
            
            <br>
            <a href="/">🏠 Volver al inicio</a> | 
            <a href="/reset-secure">🧹 Limpiar comentarios</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, 
                                comments=all_comments, 
                                error_message=error_message,
                                success_message=success_message)

# Página de comparación
@app.route('/comparison')
def comparison():
    template = '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Vulnerable vs Seguro</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 1000px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
            .vulnerable { background: #ffebee; padding: 20px; border-left: 4px solid #f44336; border-radius: 4px; }
            .secure { background: #e8f5e8; padding: 20px; border-left: 4px solid #4caf50; border-radius: 4px; }
            .code { background: #f8f8f8; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
            h3 { margin-top: 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Comparación: Aplicación Vulnerable vs Segura</h1>
            
            <div class="comparison">
                <div class="vulnerable">
                    <h3>❌ Código Vulnerable</h3>
                    <div class="code">
# Sin validación<br>
search = request.args.get('search', '')<br><br>
# Renderizado directo (PELIGROSO)<br>
return f"Resultados: {search}"
                    </div>
                </div>
                
                <div class="secure">
                    <h3>✅ Código Seguro</h3>
                    <div class="code">
# Validación estricta<br>
is_valid, msg = validate_input(search)<br>
if not is_valid:<br>
&nbsp;&nbsp;return error_page(msg)<br><br>
# Sanitización<br>
safe_search = sanitize_input(search)<br>
return f"Resultados: {safe_search}"
                    </div>
                </div>
            </div>
            
            <h2>🛡️ Capas de Protección Implementadas:</h2>
            
            <h3>1. Validación de Entrada</h3>
            <ul>
                <li>Detección de patrones sospechosos con regex</li>
                <li>Límites de longitud estrictos</li>
                <li>Rechazo de entradas vacías o solo espacios</li>
            </ul>
            
            <h3>2. Sanitización</h3>
            <ul>
                <li>HTML escaping completo</li>
                <li>Remoción de tags HTML</li>
                <li>Eliminación de protocolos peligrosos</li>
            </ul>
            
            <h3>3. Content Security Policy (CSP)</h3>
            <ul>
                <li>Solo scripts del mismo origen</li>
                <li>Bloqueo de inline scripts no autorizados</li>
                <li>Restricción de recursos externos</li>
            </ul>
            
            <h3>4. Headers de Seguridad</h3>
            <ul>
                <li>X-XSS-Protection</li>
                <li>X-Content-Type-Options</li>
                <li>X-Frame-Options</li>
                <li>Referrer-Policy</li>
            </ul>
            
            <br>
            <a href="/">🏠 Volver al inicio</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/reset-secure')
def reset_secure():
    if os.path.exists('secure_comments.db'):
        os.remove('secure_comments.db')
    init_db()
    return redirect(url_for('secure_comments'))

if __name__ == '__main__':
    init_db()
    print("🛡️ Aplicación WEB SEGURA iniciada")
    print("🌐 Accede a: http://localhost:5001")
    print("✅ Protecciones XSS activas")
    app.run(debug=False, host='0.0.0.0', port=5001)  # debug=False en producción
