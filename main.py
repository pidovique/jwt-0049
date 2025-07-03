from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

# Configuracion de app

app = Flask(__name__)

app.config['SECRET_KEY'] = 'tu-clave-secreta-super-segura-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dbsegura.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)


# Filtros

@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime(timestamp):
    try:
        return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    except:
        return 'N/A'
    

# STEP 1 : MODELO BDD


    class Usuario(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password_hash = db.Column(db.String(120),  nullable=False)
        rol = db.Column(db.String(20), nullable=False, default='Usuario Comun')

        def set_password(self, password):
            """  PROTEGER PASSW HASH   """
            self.password_hash = generate_password_hash(password)
        
        def check_password(self, password):
            """ Verificar la passwd"""
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





# STEP 2 : JWT

    def generar_jwt(usuario_id, username, rol):
        """preparar JWT usuario"""

        payload = {
        'user_id': usuario_id,
        'username' : username,
        'rol' : rol,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24), # expira 24 hrs
        'iat': datetime.datetime.utcnow()  
    }


     # asegurarme string 

        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

        if isinstance(token, bytes):
            token = token.decode('utf-8')

        print(f"tu Token: {token[:50]}...")
        return token
    

def verificar_jwt(token):

    try:
        
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        payload = jwt.decode(token. app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("Error token expirado")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Error: Token invalido - {e}")
        return None
    except Exception as e:
        print(f"Error al verificar JWT: {e}")
        return None
    


## MW AUTH
  

def token_requerido(f):

    """ DECORADOR  """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('jwt_token')


        if not token:   
            return redirect(url_for('login'))

        try:
            data = verificar_jwt(token)
            if data is None:
                print("[token_requerido] Token inválido, redirigiendo a login")
                flash('Token null o expirado')
                session.clear()
                return redirect(url_for('login')) 
            print(f"[token_requerido] Token válido para usuario: {data.get('username')}") 

            return f(current_user=data, *args, **kwargs)
        except Exception as e:
            print(f"[token_requerido] Error inesperado: {e}")  # Debug
            flash('Error de autenticación', 'error')
            session.clear()
            return redirect(url_for('login'))
        
    return decorated



def rol_requerido(roles_permitidos):
    def decorador(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = session.get('jwt_token')

    
            if not token:
                flash('Acceso denegado - No autenticado', 'error')
                return redirect(url_for('login'))
            
            data = verificar_jwt(token)
            if data is None:
                print("Token inválido en rol_requerido")  # Debug
                flash('Token inválido o expirado', 'error')
                return redirect(url_for('login'))
            
            print(f"Rol del usuario: {data.get('rol')}, Roles permitidos: {roles_permitidos}") 

            if data['rol'] not in roles_permitidos:
                flash(f'Acceso denegado - Rol requerido: {", ".join(roles_permitidos)}', 'error')
                return redirect(url_for('dashboard'))
            
            return f(current_user=data, *args, **kwargs)

        return decorated
    return decorador

## RUTAS 

@app.route('/')
def index():

    # logeado

    if session.get('jwt_token'):
        token = session.get('jwt_token')
        data = verificar_jwt(token)
        if data is not None:
            return redirect(url_for('dashboard'))
        
    return redirect(url_for('login'))





