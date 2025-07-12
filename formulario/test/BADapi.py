# API vulnerable para testing de seguridad


from flask import Flask, request, jsonify, render_template_string, session, make_response
import sqlite3
import os
import time
import hashlib
import json
import pickle
import base64
from datetime import datetime
import subprocess
import urllib.parse

app = Flask(__name__)
app.secret_key = "vulnerable_secret_key_123"  # VULNERABILIDAD: Clave secreta débil

# Base de datos vulnerable (SQLite en memoria)
def init_vulnerable_db():
    """Inicializa base de datos con vulnerabilidades SQL"""
    conn = sqlite3.connect('vulnerable_students.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Crear tabla sin prepared statements
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            nombre TEXT,
            apellido TEXT,
            curso TEXT,
            nivel TEXT,
            password TEXT,
            email TEXT,
            admin INTEGER DEFAULT 0,
            created_at TEXT
        )
    ''')
    
    # Insertar datos de ejemplo con contraseñas en texto plano
    sample_data = [
        (1, 'admin', 'system', 'Administración', 'L5', 'admin123', 'admin@test.com', 1, '2024-01-01'),
        (2, 'María', 'González', 'Python', 'L4', 'password', 'maria@test.com', 0, '2024-01-02'),
        (3, 'Carlos', 'Rodríguez', 'Web Security', 'L5', '123456', 'carlos@test.com', 0, '2024-01-03'),
    ]
    
    cursor.executemany('''
        INSERT OR REPLACE INTO students 
        (id, nombre, apellido, curso, nivel, password, email, admin, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_data)
    
    conn.commit()
    return conn

# Conexión global (VULNERABILIDAD: Conexión compartida)
db_conn = init_vulnerable_db()

# Variables globales para tracking (VULNERABILIDAD: Estado global)
failed_login_attempts = {}
session_data = {}

@app.route('/')
def index():
    """Página principal con información de la API vulnerable"""
    return jsonify({
        "message": "API Vulnerable para Testing de Seguridad",
        "warning": "⚠️ Esta API contiene vulnerabilidades intencionalmente",
        "endpoints": {
            "authentication": [
                "POST /api/login - Login vulnerable",
                "POST /api/register - Registro sin validación",
                "GET /api/admin - Panel de administración"
            ],
            "students": [
                "GET /api/students - Listar estudiantes (SQL injection)",
                "POST /api/students - Crear estudiante (XSS, injection)",
                "GET /api/students/<id> - Ver estudiante (IDOR)",
                "PUT /api/students/<id> - Actualizar estudiante",
                "DELETE /api/students/<id> - Eliminar estudiante"
            ],
            "files": [
                "GET /api/files/<filename> - Descargar archivo (Path traversal)",
                "POST /api/upload - Subir archivo (File upload vuln)"
            ],
            "utilities": [
                "POST /api/search - Búsqueda (NoSQL injection)",
                "GET /api/debug - Información de debug",
                "POST /api/execute - Ejecución de comandos"
            ]
        }
    })

# =================== VULNERABILIDADES DE AUTENTICACIÓN ===================

@app.route('/api/login', methods=['POST'])
def vulnerable_login():
    """Login vulnerable a SQL injection y bypass de autenticación"""
    try:
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')
        
        # VULNERABILIDAD 1: SQL Injection en login
        cursor = db_conn.cursor()
        query = f"SELECT * FROM students WHERE nombre = '{username}' AND password = '{password}'"
        print(f"🔍 Ejecutando query: {query}")  # VULNERABILIDAD: Debug info en logs
        
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            # VULNERABILIDAD 2: Información sensible en response
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[7]
            
            return jsonify({
                "success": True,
                "message": "Login exitoso",
                "user": {
                    "id": user[0],
                    "nombre": user[1],
                    "apellido": user[2],
                    "email": user[6],
                    "admin": user[7],
                    "password": user[5]  # VULNERABILIDAD: Password en response
                },
                "session_token": hashlib.md5(f"{user[0]}{user[1]}".encode()).hexdigest()
            })
        else:
            # VULNERABILIDAD 3: Información de timing attack
            time.sleep(0.5)  # Delay diferente para usuarios inválidos
            return jsonify({"success": False, "message": "Credenciales inválidas"}), 401
            
    except Exception as e:
        # VULNERABILIDAD 4: Error disclosure
        return jsonify({
            "success": False, 
            "error": str(e),
            "query": query if 'query' in locals() else "N/A"
        }), 500

@app.route('/api/register', methods=['POST'])
def vulnerable_register():
    """Registro sin validación adecuada"""
    try:
        data = request.get_json() or {}
        
        # VULNERABILIDAD: Sin validación de entrada
        nombre = data.get('nombre', '')
        apellido = data.get('apellido', '')
        curso = data.get('curso', '')
        nivel = data.get('nivel', '')
        password = data.get('password', '')
        email = data.get('email', '')
        admin = data.get('admin', 0)  # VULNERABILIDAD: Admin controllable por usuario
        
        # VULNERABILIDAD: SQL injection en INSERT
        cursor = db_conn.cursor()
        query = f"""
        INSERT INTO students (nombre, apellido, curso, nivel, password, email, admin, created_at) 
        VALUES ('{nombre}', '{apellido}', '{curso}', '{nivel}', '{password}', '{email}', {admin}, '{datetime.now()}')
        """
        
        cursor.execute(query)
        db_conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Usuario registrado",
            "user_id": cursor.lastrowid,
            "admin_granted": bool(admin)  # VULNERABILIDAD: Confirma escalación de privilegios
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =================== VULNERABILIDADES EN GESTIÓN DE ESTUDIANTES ===================

@app.route('/api/students', methods=['GET'])
def vulnerable_list_students():
    """Listado vulnerable a SQL injection"""
    try:
        # VULNERABILIDAD: Parámetros de query sin sanitizar
        search = request.args.get('search', '')
        order_by = request.args.get('order_by', 'id')
        limit = request.args.get('limit', '100')
        
        cursor = db_conn.cursor()
        
        if search:
            # VULNERABILIDAD: SQL injection en WHERE clause
            query = f"SELECT * FROM students WHERE nombre LIKE '%{search}%' OR apellido LIKE '%{search}%'"
        else:
            query = f"SELECT * FROM students ORDER BY {order_by} LIMIT {limit}"
        
        print(f"🔍 Query ejecutada: {query}")
        cursor.execute(query)
        students = cursor.fetchall()
        
        # VULNERABILIDAD: Exposición de passwords
        return jsonify({
            "success": True,
            "students": [
                {
                    "id": s[0], "nombre": s[1], "apellido": s[2], 
                    "curso": s[3], "nivel": s[4], "password": s[5],
                    "email": s[6], "admin": s[7], "created_at": s[8]
                } for s in students
            ],
            "query_executed": query  # VULNERABILIDAD: Query disclosure
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/students', methods=['POST'])
def vulnerable_create_student():
    """Creación vulnerable a XSS y injection"""
    try:
        data = request.get_json() or {}
        
        # VULNERABILIDAD: Sin sanitización de HTML/JavaScript
        nombre = data.get('nombre', '')
        apellido = data.get('apellido', '')
        curso = data.get('curso', '')
        nivel = data.get('nivel', '')
        
        # VULNERABILIDAD: SQL injection
        cursor = db_conn.cursor()
        query = f"""
        INSERT INTO students (nombre, apellido, curso, nivel, created_at) 
        VALUES ('{nombre}', '{apellido}', '{curso}', '{nivel}', '{datetime.now()}')
        """
        
        cursor.execute(query)
        db_conn.commit()
        
        # VULNERABILIDAD: XSS en response (reflejado)
        return jsonify({
            "success": True,
            "message": f"Estudiante {nombre} {apellido} creado exitosamente",
            "student": {
                "id": cursor.lastrowid,
                "nombre": nombre,  # Sin escape
                "apellido": apellido,  # Sin escape
                "curso": curso,  # Sin escape
                "nivel": nivel
            }
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/students/<student_id>', methods=['GET'])
def vulnerable_get_student(student_id):
    """Consulta vulnerable a IDOR e injection"""
    try:
        # VULNERABILIDAD: Sin validación de autorización (IDOR)
        # VULNERABILIDAD: SQL injection en parámetro
        cursor = db_conn.cursor()
        query = f"SELECT * FROM students WHERE id = {student_id}"
        
        cursor.execute(query)
        student = cursor.fetchone()
        
        if student:
            return jsonify({
                "success": True,
                "student": {
                    "id": student[0], "nombre": student[1], "apellido": student[2],
                    "curso": student[3], "nivel": student[4], "password": student[5],
                    "email": student[6], "admin": student[7]
                }
            })
        else:
            return jsonify({"success": False, "message": "Estudiante no encontrado"}), 404
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/students/<student_id>', methods=['DELETE'])
def vulnerable_delete_student(student_id):
    """Eliminación sin autorización"""
    try:
        # VULNERABILIDAD: Sin verificación de autorización
        # VULNERABILIDAD: SQL injection
        cursor = db_conn.cursor()
        query = f"DELETE FROM students WHERE id = {student_id}"
        
        cursor.execute(query)
        db_conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"Estudiante {student_id} eliminado",
            "rows_affected": cursor.rowcount
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =================== VULNERABILIDADES DE ARCHIVOS ===================

@app.route('/api/files/<path:filename>', methods=['GET'])
def vulnerable_download_file(filename):
    """Descarga vulnerable a path traversal"""
    try:
        # VULNERABILIDAD: Path traversal sin validación
        file_path = f"./uploads/{filename}"
        
        # Simular algunos archivos
        if "../" in filename or "..\\" in filename:
            # VULNERABILIDAD: Acceso a archivos del sistema
            if "etc/passwd" in filename:
                return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            elif "config" in filename:
                return "database_password=super_secret_123\napi_key=sk-1234567890abcdef\n"
        
        # VULNERABILIDAD: Information disclosure
        return jsonify({
            "success": True,
            "file_path": file_path,
            "message": f"Archivo {filename} descargado",
            "server_info": {
                "python_version": "3.9.0",
                "flask_version": "2.0.1",
                "os": "Linux Ubuntu 20.04"
            }
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def vulnerable_upload_file():
    """Upload vulnerable sin validación"""
    try:
        # VULNERABILIDAD: Sin validación de tipo de archivo
        data = request.get_json() or {}
        filename = data.get('filename', 'uploaded_file')
        content = data.get('content', '')
        
        # VULNERABILIDAD: Ejecución de código si es Python
        if filename.endswith('.py'):
            try:
                exec(content)  # VULNERABILIDAD CRÍTICA: Ejecución de código arbitrario
                return jsonify({
                    "success": True,
                    "message": "Archivo Python ejecutado",
                    "filename": filename
                })
            except Exception as exec_error:
                return jsonify({
                    "success": False,
                    "error": f"Error ejecutando Python: {str(exec_error)}"
                })
        
        # VULNERABILIDAD: Deserialización insegura
        if filename.endswith('.pickle'):
            try:
                decoded_content = base64.b64decode(content)
                obj = pickle.loads(decoded_content)  # VULNERABILIDAD: Pickle inseguro
                return jsonify({
                    "success": True,
                    "message": "Objeto deserializado",
                    "content": str(obj)
                })
            except Exception as pickle_error:
                return jsonify({
                    "success": False,
                    "error": f"Error deserializando: {str(pickle_error)}"
                })
        
        return jsonify({
            "success": True,
            "message": "Archivo subido",
            "filename": filename,
            "size": len(content)
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =================== VULNERABILIDADES DE UTILIDADES ===================

@app.route('/api/search', methods=['POST'])
def vulnerable_search():
    """Búsqueda vulnerable a NoSQL injection y XSS"""
    try:
        data = request.get_json() or {}
        query = data.get('query', '')
        
        # VULNERABILIDAD: XSS reflejado
        html_response = f"""
        <h2>Resultados para: {query}</h2>
        <script>
        // VULNERABILIDAD: JavaScript injection
        var searchTerm = "{query}";
        console.log("Búsqueda: " + searchTerm);
        </script>
        """
        
        # VULNERABILIDAD: Evaluación de código en búsqueda
        if query.startswith('eval:'):
            try:
                result = eval(query[5:])  # VULNERABILIDAD: eval() de entrada de usuario
                return jsonify({
                    "success": True,
                    "eval_result": result,
                    "html": html_response
                })
            except Exception as eval_error:
                return jsonify({
                    "success": False,
                    "eval_error": str(eval_error)
                })
        
        return jsonify({
            "success": True,
            "query": query,
            "html": html_response,
            "results": []
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/debug', methods=['GET'])
def vulnerable_debug():
    """Endpoint de debug con información sensible"""
    # VULNERABILIDAD: Information disclosure
    return jsonify({
        "debug_info": {
            "environment_variables": dict(os.environ),  # VULNERABILIDAD: Env vars expuestas
            "session_data": dict(session),
            "request_headers": dict(request.headers),
            "python_path": os.sys.path,
            "current_directory": os.getcwd(),
            "database_file": "vulnerable_students.db",
            "secret_key": app.secret_key,  # VULNERABILIDAD: Secret key expuesta
            "failed_logins": failed_login_attempts
        }
    })

@app.route('/api/execute', methods=['POST'])
def vulnerable_execute():
    """Ejecución de comandos del sistema"""
    try:
        data = request.get_json() or {}
        command = data.get('command', '')
        
        # VULNERABILIDAD CRÍTICA: Command injection
        if command:
            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                return jsonify({
                    "success": True,
                    "command": command,
                    "output": result
                })
            except subprocess.CalledProcessError as e:
                return jsonify({
                    "success": False,
                    "command": command,
                    "error": e.output
                })
        
        return jsonify({"success": False, "message": "No command provided"})
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =================== VULNERABILIDADES DE CONFIGURACIÓN ===================

@app.route('/api/admin', methods=['GET'])
def vulnerable_admin_panel():
    """Panel de administración con bypass de autenticación"""
    # VULNERABILIDAD: Bypass de autenticación
    admin_param = request.args.get('admin')
    if admin_param == 'true':
        session['is_admin'] = True
    
    # VULNERABILIDAD: Weak session management
    if session.get('is_admin') or request.headers.get('X-Admin-Access') == 'granted':
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM students WHERE admin = 1")
        admins = cursor.fetchall()
        
        return jsonify({
            "success": True,
            "admin_panel": True,
            "administrators": [
                {
                    "id": a[0], "nombre": a[1], "password": a[5], "email": a[6]
                } for a in admins
            ],
            "system_info": {
                "database_location": "vulnerable_students.db",
                "backup_location": "/tmp/backup.sql",
                "log_location": "/var/log/app.log"
            }
        })
    
    return jsonify({"success": False, "message": "Acceso denegado"}), 403

# =================== CONFIGURACIÓN VULNERABLE ===================

@app.errorhandler(404)
def not_found(error):
    # VULNERABILIDAD: Information disclosure en errores
    return jsonify({
        "error": "Endpoint no encontrado",
        "path": request.path,
        "method": request.method,
        "available_endpoints": [
            "/api/login", "/api/register", "/api/students", 
            "/api/admin", "/api/debug", "/api/execute"
        ],
        "server_info": "Flask Development Server"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    # VULNERABILIDAD: Stack trace disclosure
    import traceback
    return jsonify({
        "error": "Error interno del servidor",
        "traceback": traceback.format_exc(),
        "locals": {k: str(v) for k, v in locals().items()},
        "request_data": request.get_json() if request.is_json else str(request.data)
    }), 500

if __name__ == '__main__':
    
    print("=" * 60)
    print("🌐 API disponible en: http://localhost:5001")
    print("📖 Documentación: GET /")
    print("🔍 Panel de debug: GET /api/debug")
    print("=" * 60)
    
    # VULNERABILIDAD: Debug mode en producción
    app.run(debug=True, host='0.0.0.0', port=5001)
