# app.py - Sistema de Autenticación y Autorización con JWT
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

# Configuración de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu-clave-secreta-super-segura-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///proyecto_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Filtros personalizados para las plantillas
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime(timestamp):
    """Convierte un timestamp Unix a fecha legible"""
    try:
        return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return 'N/A'

# PASO 1: MODELOS DE BASE DE DATOS

# Modelo de Usuario
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default='Usuario Común')
    
    def set_password(self, password):
        """Hashea la contraseña usando Werkzeug (similar a bcrypt)"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifica la contraseña"""
        return check_password_hash(self.password_hash, password)

# Modelo de Proyecto
class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    creador_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    asignado_a = db.Column(db.Integer, db.ForeignKey('usuario.id'))

# Modelo de Tarea
class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    asignado_a = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    completada = db.Column(db.Boolean, default=False)

# PASO 2: FUNCIONES DE AUTENTICACIÓN JWT

def generar_jwt(usuario_id, username, rol):
    """Genera un JWT con la información del usuario"""
    payload = {
        'user_id': usuario_id,
        'username': username,
        'rol': rol,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),  # Expira en 24 horas
        'iat': datetime.datetime.utcnow()  # Emitido en
    }
    
    # Asegurar que se devuelve como string
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    
    # En PyJWT >= 2.0, jwt.encode devuelve string, no bytes
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    
    print(f"Token generado: {token[:50]}...")  # Debug
    return token

def verificar_jwt(token):
    """Verifica y decodifica un JWT"""
    try:
        # Asegurar que el token sea string
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("Error: Token expirado")
        return None  # Token expirado
    except jwt.InvalidTokenError as e:
        print(f"Error: Token inválido - {e}")
        return None  # Token inválido
    except Exception as e:
        print(f"Error inesperado al verificar JWT: {e}")
        return None

# PASO 3: MIDDLEWARE DE AUTENTICACIÓN

def token_requerido(f):
    """Decorador que requiere un JWT válido"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('jwt_token')
        
        print(f"[token_requerido] Verificando token para ruta: {request.endpoint}")  # Debug
        print(f"[token_requerido] Token presente: {'Sí' if token else 'No'}")  # Debug
        
        if not token:
            print("[token_requerido] No hay token, redirigiendo a login")  # Debug
            flash('Token de acceso requerido', 'error')
            return redirect(url_for('login'))
        
        try:
            data = verificar_jwt(token)
            if data is None:
                print("[token_requerido] Token inválido, redirigiendo a login")  # Debug
                flash('Token inválido o expirado', 'error')
                # Limpiar sesión si el token es inválido
                session.clear()
                return redirect(url_for('login'))
            
            print(f"[token_requerido] Token válido para usuario: {data.get('username')}")  # Debug
            # Pasamos los datos del usuario a la función
            return f(current_user=data, *args, **kwargs)
        except Exception as e:
            print(f"[token_requerido] Error inesperado: {e}")  # Debug
            flash('Error de autenticación', 'error')
            session.clear()
            return redirect(url_for('login'))
    
    return decorated

def rol_requerido(roles_permitidos):
    """Decorador que requiere roles específicos"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = session.get('jwt_token')
            
            print(f"Verificando rol para token: {token[:50] if token else 'NO ENCONTRADO'}...")  # Debug
            
            if not token:
                flash('Acceso denegado - No autenticado', 'error')
                return redirect(url_for('login'))
            
            data = verificar_jwt(token)
            if data is None:
                print("Token inválido en rol_requerido")  # Debug
                flash('Token inválido o expirado', 'error')
                return redirect(url_for('login'))
            
            print(f"Rol del usuario: {data.get('rol')}, Roles permitidos: {roles_permitidos}")  # Debug
            
            if data['rol'] not in roles_permitidos:
                flash(f'Acceso denegado - Rol requerido: {", ".join(roles_permitidos)}', 'error')
                return redirect(url_for('dashboard'))
            
            return f(current_user=data, *args, **kwargs)
        
        return decorated
    return decorator

# PASO 4: RUTAS DE AUTENTICACIÓN

@app.route('/')
def index():
    # Si ya está logueado, redirigir al dashboard
    if session.get('jwt_token'):
        token = session.get('jwt_token')
        data = verificar_jwt(token)
        if data is not None:
            return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        rol = request.form.get('rol', 'Usuario Común')
        
        # Verificar si el usuario ya existe
        if Usuario.query.filter_by(username=username).first():
            flash('El usuario ya existe', 'error')
            return render_template('registro.html')
        
        # Crear nuevo usuario
        nuevo_usuario = Usuario(username=username, rol=rol)
        nuevo_usuario.set_password(password)
        
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        flash('Usuario registrado exitosamente', 'success')
        return redirect(url_for('login'))
    
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si ya está logueado y viene por GET, redirigir al dashboard
    if request.method == 'GET' and session.get('jwt_token'):
        token = session.get('jwt_token')
        data = verificar_jwt(token)
        if data is not None:
            print("[login] Usuario ya logueado, redirigiendo a dashboard")  # Debug
            return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"[login] Intento de login: {username}")  # Debug
        
        usuario = Usuario.query.filter_by(username=username).first()
        
        if usuario and usuario.check_password(password):
            print(f"[login] Credenciales válidas para: {username}")  # Debug
            
            # Generar JWT
            token = generar_jwt(usuario.id, usuario.username, usuario.rol)
            
            # Guardar token en la sesión
            session['jwt_token'] = token
            session['user_role'] = usuario.rol
            session['username'] = usuario.username
            session['user_id'] = usuario.id
            
            print(f"[login] Token generado y almacenado")  # Debug
            
            flash(f'Bienvenido {usuario.username} - Rol: {usuario.rol}', 'success')
            
            # Redirección explícita al dashboard
            print("[login] Redirigiendo al dashboard...")  # Debug
            return redirect(url_for('dashboard'))
        else:
            print(f"[login] Credenciales inválidas para: {username}")  # Debug
            flash('Credenciales inválidas', 'error')
    
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    """PASO 5: Cerrar sesión"""
    session.clear()  # Elimina el JWT del lado del servidor
    flash('Sesión cerrada exitosamente', 'info')
    return redirect(url_for('login'))

# PASO 6: RUTAS PROTEGIDAS

# PASO 6: RUTAS PROTEGIDAS

@app.route('/dashboard', methods=['GET'])
@token_requerido
def dashboard(current_user):
    """Dashboard principal - Accesible para todos los usuarios autenticados"""
    print(f"[dashboard] Cargando dashboard para usuario: {current_user.get('username')}")  # Debug
    
    try:
        proyectos = []
        tareas = []
        
        if current_user['rol'] == 'Administrador':
            # Los administradores ven todo
            proyectos = Proyecto.query.all()
            tareas = Tarea.query.all()
            print(f"[dashboard] Admin ve {len(proyectos)} proyectos y {len(tareas)} tareas")  # Debug
        elif current_user['rol'] == 'Editor':
            # Los editores ven proyectos que crearon o se les asignaron
            proyectos = Proyecto.query.filter(
                (Proyecto.creador_id == current_user['user_id']) |
                (Proyecto.asignado_a == current_user['user_id'])
            ).all()
            tareas = Tarea.query.filter_by(asignado_a=current_user['user_id']).all()
            print(f"[dashboard] Editor ve {len(proyectos)} proyectos y {len(tareas)} tareas")  # Debug
        else:  # Usuario Común
            # Los usuarios comunes solo ven lo que se les asignó
            proyectos = Proyecto.query.filter_by(asignado_a=current_user['user_id']).all()
            tareas = Tarea.query.filter_by(asignado_a=current_user['user_id']).all()
            print(f"[dashboard] Usuario común ve {len(proyectos)} proyectos y {len(tareas)} tareas")  # Debug
        
        print("[dashboard] Renderizando template...")  # Debug
        return render_template('dashboard.html', 
                             proyectos=proyectos, 
                             tareas=tareas, 
                             current_user=current_user)
    except Exception as e:
        print(f"[dashboard] Error al cargar dashboard: {e}")  # Debug
        flash(f'Error al cargar dashboard: {e}', 'error')
        return redirect(url_for('login'))

@app.route('/proyectos/crear', methods=['GET', 'POST'])
@rol_requerido(['Administrador', 'Editor'])
def crear_proyecto(current_user):
    """Solo Administradores y Editores pueden crear proyectos"""
    if request.method == 'POST':
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        asignado_a = request.form.get('asignado_a')
        
        nuevo_proyecto = Proyecto(
            nombre=nombre,
            descripcion=descripcion,
            creador_id=current_user['user_id'],
            asignado_a=int(asignado_a) if asignado_a else None
        )
        
        db.session.add(nuevo_proyecto)
        db.session.commit()
        
        flash('Proyecto creado exitosamente', 'success')
        return redirect(url_for('dashboard'))
    
    usuarios = Usuario.query.all()
    return render_template('crear_proyecto.html', usuarios=usuarios, current_user=current_user)

@app.route('/proyectos/eliminar/<int:proyecto_id>', methods=['GET', 'POST'])
@rol_requerido(['Administrador'])
def eliminar_proyecto(current_user, proyecto_id):
    """Solo Administradores pueden eliminar proyectos"""
    proyecto = Proyecto.query.get_or_404(proyecto_id)
    
    # Eliminar tareas asociadas
    Tarea.query.filter_by(proyecto_id=proyecto_id).delete()
    
    db.session.delete(proyecto)
    db.session.commit()
    
    flash('Proyecto eliminado exitosamente', 'success')
    return redirect(url_for('dashboard'))

@app.route('/tareas/crear', methods=['GET', 'POST'])
@rol_requerido(['Administrador', 'Editor'])
def crear_tarea(current_user):
    """Solo Administradores y Editores pueden crear tareas"""
    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        proyecto_id = request.form['proyecto_id']
        asignado_a = request.form.get('asignado_a')
        
        nueva_tarea = Tarea(
            titulo=titulo,
            descripcion=descripcion,
            proyecto_id=int(proyecto_id),
            asignado_a=int(asignado_a) if asignado_a else None
        )
        
        db.session.add(nueva_tarea)
        db.session.commit()
        
        flash('Tarea creada exitosamente', 'success')
        return redirect(url_for('dashboard'))
    
    # Obtener proyectos según el rol
    if current_user['rol'] == 'Administrador':
        proyectos = Proyecto.query.all()
    else:  # Editor
        proyectos = Proyecto.query.filter(
            (Proyecto.creador_id == current_user['user_id']) |
            (Proyecto.asignado_a == current_user['user_id'])
        ).all()
    
    usuarios = Usuario.query.all()
    return render_template('crear_tarea.html', 
                         proyectos=proyectos, 
                         usuarios=usuarios, 
                         current_user=current_user)

@app.route('/tareas/eliminar/<int:tarea_id>', methods=['GET', 'POST'])
@rol_requerido(['Administrador'])
def eliminar_tarea(current_user, tarea_id):
    """Solo Administradores pueden eliminar tareas"""
    tarea = Tarea.query.get_or_404(tarea_id)
    
    db.session.delete(tarea)
    db.session.commit()
    
    flash('Tarea eliminada exitosamente', 'success')
    return redirect(url_for('dashboard'))

# PASO 7: INICIALIZACIÓN DE LA BASE DE DATOS

def crear_datos_ejemplo():
    """Crea usuarios de ejemplo para probar el sistema"""
    
    # Crear usuarios de ejemplo
    admin = Usuario(username='admin', rol='Administrador')
    admin.set_password('admin123')
    
    editor = Usuario(username='editor', rol='Editor')
    editor.set_password('editor123')
    
    usuario = Usuario(username='usuario', rol='Usuario Común')
    usuario.set_password('usuario123')
    
    db.session.add_all([admin, editor, usuario])
    db.session.commit()
    
    # Crear proyectos de ejemplo
    proyecto1 = Proyecto(
        nombre='Sistema de Ventas',
        descripcion='Desarrollo de sistema de ventas online',
        creador_id=admin.id,
        asignado_a=editor.id
    )
    
    proyecto2 = Proyecto(
        nombre='App Mobile',
        descripcion='Aplicación móvil para clientes',
        creador_id=editor.id,
        asignado_a=usuario.id
    )
    
    db.session.add_all([proyecto1, proyecto2])
    db.session.commit()
    
    # Crear tareas de ejemplo
    tarea1 = Tarea(
        titulo='Diseñar base de datos',
        descripcion='Crear el esquema de la base de datos',
        proyecto_id=proyecto1.id,
        asignado_a=editor.id
    )
    
    tarea2 = Tarea(
        titulo='Crear mockups',
        descripcion='Diseñar las pantallas de la app',
        proyecto_id=proyecto2.id,
        asignado_a=usuario.id
    )
    
    db.session.add_all([tarea1, tarea2])
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            
            # Solo crear datos de ejemplo si no existen usuarios
            if Usuario.query.count() == 0:
                crear_datos_ejemplo()
                print("✅ Datos de ejemplo creados:")
                print("   Admin: admin/admin123")
                print("   Editor: editor/editor123") 
                print("   Usuario: usuario/usuario123")
            else:
                print("✅ Base de datos ya inicializada")
                
          
            
        except Exception as e:
            print(f"❌ Error al inicializar la aplicación: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=9000)
