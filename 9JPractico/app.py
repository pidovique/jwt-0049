from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity
from config import Config
from models import db, User
from auth import  token_required, admin_required, get_current_user
import re



app = Flask(__name__)
app.config.from_object(Config)

# INIt... EXTEND

db.init_app(app)
jwt = JWTManager(app)


# crear Tablas

with app.app_context():
    db.create_all()


def validate_input(data, required_fields):

    errors= []

    for field in required_fields:
        if field not in data or not data[field]:
            errors.append(f'El campo {field} es requerido')

    return errors


def validate_email(email):

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


@app.route('/api/register', methods=['POST'])
def register():

    try:
        data = request.json()

        # validar DATOS

        errors = validate_input(data, ['username', 'email', 'password' ])
        if errors:
            return jsonify({'errors': errors}), 400
        

        # validar Email

        if not validate_email(data['email']):
            return jsonify({'error': 'Formato de email invalido'}), 400
        

        # Verificar user existente

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'el usuario ya existe'}), 409
        

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email ya existe'}), 409
        

        #Crear USER
        user = User(

            username=data['username'],
            email=data['email'],
            role=data.get('roel', 'user') 
        )


        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()


        return jsonify({'message': ' Usuario creado Exitosamente'}), 201
    
    except Exception as e:
        return jsonify({'error': 'Error interno'}), 500
    



@app.route('/api/login', methods=['POST'])
def login():

    try:
        data = request.get_json()

        errors = validate_input(data, ['username' , 'password'])
        
        if errors:
           return jsonify({'errors': errors}), 400
        

        # buscar user


        user = User.query.filter_by(username=data['username']).first()

        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Credenciales invalidas'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'usuario inactivo'}), 401


        # buscar JWT


        access_token = create_access_token(identity=user.id)

        return jsonify({
            'access_token' : access_token,
            'user': user.to_dict()
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Error interno'}), 500
    

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():

    try:
        users = User.query.all()
        return jsonify([user.to_dict() for user in users ]), 200
    except Exception as e:
        return jsonify({'error': 'Error interno'}), 500



@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required

def delete_user(user_id):

    """
    VERSIÓN SEGURA: Eliminar usuario
    - Requiere autenticación JWT
    - Requiere rol de administrador
    - Usa parámetros seguros
    - Validación de entrada
    """
    try:

        #validar id 
        if not isinstance(user_id, int) or user_id <=0:
            return jsonify({'error' : 'ID de user invalido'}), 400
        

        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User no encontrado'}), 400
        

        # consultar previamente a user a delete
        user_to_delete = User.query.get(user_id)
        if not user_to_delete:
            return jsonify({'error' : 'no puedes eliminar la cuenta'}), 400    


        # prevenir auto-eliminacion

        if user_to_delete.id == current_user.id:
            return jsonify({'error': 'No puedes eliminar el user'}), 400
        
        db.session.delete(user_to_delete)
        db.session.commit()

        return jsonify({
            'message': 'usuario eliminado correctamente',
            'deleted_user': user_to_delete.to_dict()
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error interno'}) , 500
    
@app.route('/api/profile' , methods=['GET'] )
@token_required

def get_profile():

    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        return jsonify(current_user.to_dict()), 200
    except Exception as e:
        return jsonify({'error': 'Error interno'}), 500
    

# Manejo de errores
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint no encontrado'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Método no permitido'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Error interno del servidor'}), 500

if __name__=='__main__':
    app.run(debug=True)












