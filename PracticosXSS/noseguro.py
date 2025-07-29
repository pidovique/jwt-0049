from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# Crear base de datos
def init_db():
    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            comment TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Página principal con XSS Reflejado
@app.route('/')
def index():
    search = request.args.get('search', '')
    
    # VULNERABLE: Sin sanitización
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Lab - Búsqueda</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .container { max-width: 800px; }
            input, button { padding: 10px; margin: 5px; }
            .result { background: #f0f0f0; padding: 15px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Búsqueda XSS Lab</h1>
            
            <form method="GET">
                <input type="text" name="search" placeholder="Buscar..." value="{{ search }}">
                <button type="submit">Buscar</button>
            </form>
            
            <h2>Ejemplos de payloads para probar:</h2>
            <ul>
                <li><code>&lt;script&gt;alert('XSS Básico')&lt;/script&gt;</code></li>
                <li><code>&lt;img src=x onerror="alert('XSS con img')"&gt;</code></li>
                <li><code>&lt;svg onload="alert('XSS con SVG')"&gt;</code></li>
            </ul>
            
            {% if search %}
            <div class="result">
                <h3>Resultados para: {{ search|safe }}</h3>
                <p>No se encontraron resultados para tu búsqueda.</p>
            </div>
            {% endif %}
            
            <br>
            <a href="/comments">💬 Ver Comentarios (XSS Stored)</a>
            <br><br>
            <a href="/advanced">🎯 XSS Avanzado</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, search=search)

# XSS Almacenado - Comentarios
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        username = request.form.get('username', '')
        comment = request.form.get('comment', '')
        
        # VULNERABLE: Guardar sin sanitizar
        conn = sqlite3.connect('comments.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO comments (username, comment) VALUES (?, ?)', 
                      (username, comment))
        conn.commit()
        conn.close()
        
        return redirect(url_for('comments'))
    
    # Mostrar comentarios
    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, comment FROM comments ORDER BY id DESC')
    all_comments = cursor.fetchall()
    conn.close()
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Lab - Comentarios</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .container { max-width: 800px; }
            input, textarea, button { padding: 10px; margin: 5px; }
            textarea { width: 100%; height: 80px; }
            .comment { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 3px solid #007cba; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>💬 Comentarios</h1>
            
            <form method="POST">
                <input type="text" name="username" placeholder="Tu nombre" required><br>
                <textarea name="comment" placeholder="Tu comentario..." required></textarea><br>
                <button type="submit">Publicar Comentario</button>
            </form>
            
            <h2>Payloads para probar:</h2>
            <ul>
                <li><code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></li>
                <li><code>&lt;img src=x onerror="document.body.style.background='red'"&gt;</code></li>
                <li><code>&lt;script&gt;document.cookie="stolen=true"&lt;/script&gt;</code></li>
            </ul>
            
            <h2>Comentarios:</h2>
            {% for username, comment in comments %}
            <div class="comment">
                <strong>{{ username|safe }}:</strong><br>
                {{ comment|safe }}
            </div>
            {% endfor %}
            
            <br>
            <a href="/">🔍 Volver a Búsqueda</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, comments=all_comments)

# XSS Avanzado - Bypass de filtros
@app.route('/advanced')
def advanced():
    user_input = request.args.get('input', '')
    
    # Filtro básico (bypasseable)
    filtered_input = user_input.replace('<script>', '').replace('</script>', '')
    filtered_input = filtered_input.replace('javascript:', '')
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Lab - Técnicas Avanzadas</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .container { max-width: 800px; }
            input, button { padding: 10px; margin: 5px; }
            .result { background: #ffe6e6; padding: 15px; margin: 10px 0; }
            .bypass { background: #e6f3ff; padding: 10px; margin: 5px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 XSS Avanzado - Bypass de Filtros</h1>
            
            <form method="GET">
                <input type="text" name="input" placeholder="Prueba bypasses..." value="{{ user_input }}">
                <button type="submit">Probar</button>
            </form>
            
            <p><strong>Filtros activos:</strong> Se bloquean &lt;script&gt; y javascript:</p>
            
            <h2>Técnicas de Bypass:</h2>
            
            <div class="bypass">
                <h3>1. Mayúsculas/Minúsculas:</h3>
                <code>&lt;SCRIPT&gt;alert('bypass')&lt;/SCRIPT&gt;</code>
            </div>
            
            <div class="bypass">
                <h3>2. Eventos de HTML:</h3>
                <code>&lt;img src=x onerror="alert('bypass')"&gt;</code><br>
                <code>&lt;svg onload="alert('bypass')"&gt;</code><br>
                <code>&lt;body onload="alert('bypass')"&gt;</code>
            </div>
            
            <div class="bypass">
                <h3>3. JavaScript ofuscado:</h3>
                <code>&lt;img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))"&gt;</code>
            </div>
            
            <div class="bypass">
                <h3>4. Bypass de javascript::</h3>
                <code>&lt;a href="java&amp;#115;cript:alert('bypass')"&gt;Click&lt;/a&gt;</code>
            </div>
            
            <div class="bypass">
                <h3>5. Nested tags:</h3>
                <code>&lt;scr&lt;script&gt;ipt&gt;alert('bypass')&lt;/scr&lt;/script&gt;ipt&gt;</code>
            </div>
            
            {% if user_input %}
            <div class="result">
                <h3>Input procesado:</h3>
                <p>Original: <code>{{ user_input }}</code></p>
                <p>Filtrado: <code>{{ filtered_input }}</code></p>
                <p>Resultado: {{ filtered_input|safe }}</p>
            </div>
            {% endif %}
            
            <br>
            <a href="/">🔍 Volver al inicio</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, user_input=user_input, filtered_input=filtered_input)

# Limpiar base de datos
@app.route('/reset')
def reset():
    if os.path.exists('comments.db'):
        os.remove('comments.db')
    init_db()
    return redirect(url_for('comments'))

if __name__ == '__main__':
    init_db()
    print("🚨 ADVERTENCIA: Esta aplicación es INTENCIONALMENTE vulnerable")
    print("📚 Solo para propósitos educativos - NO usar en producción")
    print("🌐 Accede a: http://localhost:5000")
    print("🧹 Para limpiar comentarios: http://localhost:5000/reset")
    app.run(debug=True, host='0.0.0.0', port=8000)
