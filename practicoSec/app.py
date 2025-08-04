from flask import Flask, request, render_template_string, redirect, url_for, make_response, session, send_from_directory
import sqlite3
import os
import hashlib
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'clave_super_secreta_123'  

# Configuración de archivos
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configuración de base de datos
def init_db():
    conn = sqlite3.connect('edusmart.db')
    cursor = conn.cursor()
    
    # Tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            tipo TEXT NOT NULL,
            nombre TEXT NOT NULL
        )
    ''')
    
    # Tabla de calificaciones
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calificaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            estudiante TEXT NOT NULL,
            materia TEXT NOT NULL,
            calificacion REAL NOT NULL,
            comentarios TEXT
        )
    ''')
    
    # Tabla de reportes disciplinarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reportes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            estudiante TEXT NOT NULL,
            fecha TEXT NOT NULL,
            incidente TEXT NOT NULL,
            profesor TEXT NOT NULL
        )
    ''')
    
    # Insertar datos de ejemplo
    cursor.execute("INSERT OR IGNORE INTO usuarios VALUES (1, 'admin', 'admin123', 'administrador', 'Administrador Sistema')")
    cursor.execute("INSERT OR IGNORE INTO usuarios VALUES (2, 'prof_garcia', 'password', 'profesor', 'María García')")
    cursor.execute("INSERT OR IGNORE INTO usuarios VALUES (3, 'tomas', '123456', 'estudiante', 'Tomás Rodríguez')")
    cursor.execute("INSERT OR IGNORE INTO usuarios VALUES (4, 'ana_lopez', 'qwerty', 'estudiante', 'Ana López')")
    
    cursor.execute("INSERT OR IGNORE INTO calificaciones VALUES (1, 'Tomás Rodríguez', 'Matemáticas', 8.5, 'Buen desempeño')")
    cursor.execute("INSERT OR IGNORE INTO calificaciones VALUES (2, 'Ana López', 'Historia', 9.0, 'Excelente participación')")
    
    conn.commit()
    conn.close()

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>EduSmart - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f0f8ff; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .logo { text-align: center; color: #2c5aa0; margin-bottom: 30px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background-color: #2c5aa0; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background-color: #1e3d72; }
        .alert { background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .info { background-color: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 5px; margin: 20px 0; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="logo">🎓 EduSmart</h1>
        <h3>Iniciar Sesión</h3>
        
        {% if error %}
            <div class="alert">{{ error|safe }}</div>
        {% endif %}
        
        <form method="POST">
            <input type="text" name="username" placeholder="Usuario" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Ingresar</button>
        </form>
        
        <div class="info">
            <strong>👨‍🎓 Cuentas de Demostración:</strong><br>
            • Admin: admin / admin123<br>
            • Profesor: prof_garcia / password<br>
            • Estudiante: tomas / 123456<br><br>
      
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>EduSmart - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f5f5f5; }
        .header { background-color: #2c5aa0; color: white; padding: 15px; }
        .nav { display: flex; justify-content: space-between; align-items: center; }
        .menu { display: flex; gap: 20px; }
        .menu a { color: white; text-decoration: none; padding: 10px; border-radius: 5px; }
        .menu a:hover { background-color: rgba(255,255,255,0.2); }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; }
        .card { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .form-group { margin: 15px 0; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        button:hover { background-color: #218838; }
        .danger { background-color: #dc3545; }
        .danger:hover { background-color: #c82333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .alert { padding: 15px; margin: 15px 0; border-radius: 5px; }
        .alert-success { background-color: #d4edda; color: #155724; }
        .alert-danger { background-color: #f8d7da; color: #721c24; }
        .alert-info { background-color: #d1ecf1; color: #0c5460; }
        .vulnerability-note { background-color: #fff3cd; color: #856404; padding: 10px; border-radius: 5px; margin: 10px 0; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="nav">
            <h2>🎓 EduSmart - Bienvenido {{ usuario }}</h2>
            <div class="menu">
                <a href="/dashboard">Dashboard</a>
                <a href="/calificaciones">Calificaciones</a>
                <a href="/reportes">Reportes</a>
                <a href="/subir_archivo">Subir Archivo</a>
                <a href="/logout">Cerrar Sesión</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        {{ content|safe }}
    </div>
</body>
</html>
'''

def allowed_file(filename):
    # VULNERABILIDAD: Validación insuficiente de archivos
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
       
        conn = sqlite3.connect('edusmart.db')
        cursor = conn.cursor()
        
        query = f"SELECT * FROM usuarios WHERE username = '{username}' AND password = '{password}'"
        print(f"Consulta ejecutada: {query}")  # Para fines educativos
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
               
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('user_id', str(user[0]), httponly=False, secure=False)
                response.set_cookie('username', user[1], httponly=False, secure=False)
                response.set_cookie('user_type', user[3], httponly=False, secure=False)
                
             
                session['logged_in'] = True
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['user_type'] = user[3]
                
                return response
            else:
        
                error = f"Usuario o contraseña incorrectos para: {username}"
                return render_template_string(LOGIN_TEMPLATE, error=error)
                
        except sqlite3.Error as e:
      
            error = f"Error en la base de datos: {str(e)}"
            conn.close()
            return render_template_string(LOGIN_TEMPLATE, error=error)
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    
    user_id = request.cookies.get('user_id')
    username = request.cookies.get('username')
    
    if not user_id:
        return redirect(url_for('login'))
    
    content = f'''
    <div class="card">
        <h3>Panel Principal</h3>
        <p>Bienvenido al sistema EduSmart, {username}!</p>
        
        <div class="vulnerability-note">
          
        </div>
        
        <div class="alert alert-info">
            <strong>📊 Funcionalidades Disponibles:</strong><br>
            • <a href="/calificaciones">Gestión de Calificaciones</a><br>
            • <a href="/reportes">Reportes Disciplinarios</a><br>
            • <a href="/subir_archivo">Subida de Archivos</a><br>
        </div>
    </div>
    '''
    
    return render_template_string(DASHBOARD_TEMPLATE, usuario=username, content=content)

@app.route('/calificaciones', methods=['GET', 'POST'])
def calificaciones():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        estudiante = request.form['estudiante']
        materia = request.form['materia']
        calificacion = request.form['calificacion']
        comentarios = request.form['comentarios']
        
       
        conn = sqlite3.connect('edusmart.db')
        cursor = conn.cursor()
        
        query = f"INSERT INTO calificaciones (estudiante, materia, calificacion, comentarios) VALUES ('{estudiante}', '{materia}', {calificacion}, '{comentarios}')"
        
        try:
            cursor.execute(query)
            conn.commit()
            conn.close()
            mensaje = "Calificación registrada exitosamente"
        except Exception as e:
            mensaje = f"Error: {str(e)}"
    
    # Obtener calificaciones
    conn = sqlite3.connect('edusmart.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM calificaciones")
    calificaciones_list = cursor.fetchall()
    conn.close()
    
  
    busqueda = request.args.get('buscar', '')
    
    content = f'''
    <div class="card">
        <h3>Gestión de Calificaciones</h3>
        
        <form method="GET">
            <div class="form-group">
                <label>Buscar estudiante:</label>
                <input type="text" name="buscar" value="{busqueda}" placeholder="Nombre del estudiante">
                <button type="submit">Buscar</button>
            </div>
        </form>
        
        {f"<div class='alert alert-info'>Buscando: {busqueda}</div>" if busqueda else ""}
        
        <form method="POST">
            <div class="form-group">
                <label>Estudiante:</label>
                <input type="text" name="estudiante" required>
            </div>
            <div class="form-group">
                <label>Materia:</label>
                <input type="text" name="materia" required>
            </div>
            <div class="form-group">
                <label>Calificación:</label>
                <input type="number" name="calificacion" step="0.1" min="0" max="10" required>
            </div>
            <div class="form-group">
                <label>Comentarios:</label>
                <textarea name="comentarios"></textarea>
            </div>
            <button type="submit">Registrar Calificación</button>
        </form>
        
      
    </div>
    
    <div class="card">
        <h3>Calificaciones Registradas</h3>
        <table>
            <tr>
                <th>ID</th>
                <th>Estudiante</th>
                <th>Materia</th>
                <th>Calificación</th>
                <th>Comentarios</th>
            </tr>
    '''
    
    for cal in calificaciones_list:
        content += f'''
            <tr>
                <td>{cal[0]}</td>
                <td>{cal[1]}</td>
                <td>{cal[2]}</td>
                <td>{cal[3]}</td>
                <td>{cal[4] or ''}</td>
            </tr>
        '''
    
    content += '''
        </table>
    </div>
    '''
    
    return render_template_string(DASHBOARD_TEMPLATE, usuario=username, content=content)

@app.route('/reportes', methods=['GET', 'POST'])
def reportes():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        estudiante = request.form['estudiante']
        fecha = request.form['fecha']
        incidente = request.form['incidente']
        
       
        conn = sqlite3.connect('edusmart.db')
        cursor = conn.cursor()
        
        query = f"INSERT INTO reportes (estudiante, fecha, incidente, profesor) VALUES ('{estudiante}', '{fecha}', '{incidente}', '{username}')"
        
        try:
            cursor.execute(query)
            conn.commit()
            mensaje = "Reporte registrado exitosamente"
        except Exception as e:
            mensaje = f"Error: {str(e)}"
        
        conn.close()
    

    filtro_estudiante = request.args.get('estudiante', '')
    conn = sqlite3.connect('edusmart.db')
    cursor = conn.cursor()
    
    if filtro_estudiante:
        query = f"SELECT * FROM reportes WHERE estudiante LIKE '%{filtro_estudiante}%'"
    else:
        query = "SELECT * FROM reportes"
    
    cursor.execute(query)
    reportes_list = cursor.fetchall()
    conn.close()
    
    content = f'''
    <div class="card">
        <h3>Reportes Disciplinarios</h3>
        
        <form method="GET">
            <div class="form-group">
                <label>Filtrar por estudiante:</label>
                <input type="text" name="estudiante" value="{filtro_estudiante}" placeholder="Nombre del estudiante">
                <button type="submit">Filtrar</button>
            </div>
        </form>
        
        <form method="POST">
            <div class="form-group">
                <label>Estudiante:</label>
                <input type="text" name="estudiante" required>
            </div>
            <div class="form-group">
                <label>Fecha:</label>
                <input type="date" name="fecha" required>
            </div>
            <div class="form-group">
                <label>Descripción del Incidente:</label>
                <textarea name="incidente" required></textarea>
            </div>
            <button type="submit">Registrar Reporte</button>
        </form>
        
       
    </div>
    
    <div class="card">
        <h3>Reportes Existentes</h3>
        <table>
            <tr>
                <th>ID</th>
                <th>Estudiante</th>
                <th>Fecha</th>
                <th>Incidente</th>
                <th>Profesor</th>
            </tr>
    '''
    
    for reporte in reportes_list:
        content += f'''
            <tr>
                <td>{reporte[0]}</td>
                <td>{reporte[1]}</td>
                <td>{reporte[2]}</td>
                <td>{reporte[3]}</td>
                <td>{reporte[4]}</td>
            </tr>
        '''
    
    content += '''
        </table>
    </div>
    '''
    
    return render_template_string(DASHBOARD_TEMPLATE, usuario=username, content=content)

@app.route('/subir_archivo', methods=['GET', 'POST'])
def subir_archivo():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    
    mensaje = ""
    
    if request.method == 'POST':
        if 'archivo' not in request.files:
            mensaje = "No se seleccionó ningún archivo"
        else:
            file = request.files['archivo']
            if file.filename == '':
                mensaje = "No se seleccionó ningún archivo"
            else:
              
                
                filename = file.filename  # No usa secure_filename()
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                try:
                    file.save(file_path)
                    mensaje = f"Archivo '{filename}' subido exitosamente a {file_path}"
                except Exception as e:
                    mensaje = f"Error al subir archivo: {str(e)}"
    
 
    archivos = []
    if os.path.exists(UPLOAD_FOLDER):
        archivos = os.listdir(UPLOAD_FOLDER)
    
    content = f'''
    <div class="card">
        <h3>Subida de Archivos</h3>
        
        {f"<div class='alert alert-info'>{mensaje}</div>" if mensaje else ""}
        
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label>Seleccionar archivo:</label>
                <input type="file" name="archivo" required>
            </div>
            <button type="submit">Subir Archivo</button>
        </form>
        
    </div>
    
    <div class="card">
        <h3>Archivos Subidos</h3>
        <ul>
    '''
    
    for archivo in archivos:
        content += f'<li><a href="/descargar/{archivo}" target="_blank">{archivo}</a></li>'
    
    content += '''
        </ul>
    </div>
    '''
    
    return render_template_string(DASHBOARD_TEMPLATE, usuario=username, content=content)

@app.route('/descargar/<filename>')
def descargar_archivo(filename):
  
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
   
    response = make_response(redirect(url_for('login')))
    
    response.set_cookie('user_id', '', expires=0)
    return response


@app.route('/admin_panel')
def admin_panel():
    username = request.cookies.get('username')
    user_type = request.cookies.get('user_type')
    
  
    if user_type != 'administrador':
        
        error_msg = f"Acceso denegado para usuario: {username}"
        return f"<h1>Error</h1><p>{error_msg}</p><a href='/dashboard'>Volver</a>"
    
    return f"<h1>Panel de Administrador</h1><p>Bienvenido {username}</p>"

if __name__ == '__main__':
    init_db()
    print("🎓 EduSmart - Plataforma Educativa Iniciada")
    print("\n🔗 Accede en: http://localhost:5010")
    
    app.run(debug=True, host='0.0.0.0', port=5010)
