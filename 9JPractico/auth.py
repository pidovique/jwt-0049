
from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models import User, db


def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Token invalido o expirado'}), 401
    return decorated


def admin_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)

            if not user or not user.is_admin():
                return jsonify({'error':'Acceso denegado. Se requiere ser Rol Admin'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error' : 'Error de Autentificacion'}), 401
    return decorated
    

def get_current_user():

    try:
         verify_jwt_in_request()
         current_user_id = get_jwt_identity()
         return User.query.get(current_user_id)
    except:
         return None
        
    



       

