from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Message, Transfer
import os

app = Flask(__name__)

# Configuración INSEGURA (solo para demostración)
app.config['SECRET_KEY'] = 'vulnerable-secret-key-123'  # VULNERABLE: clave predecible
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# VULNERABLE: Sin protección CSRF por defecto
app.config['WTF_CSRF_ENABLED'] = False

# VULNERABLE: Desactivar autoescape en Jinja2 para demostrar XSS
app.jinja_env.autoescape = False

# Inicializar extensiones
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Crear tablas y usuarios de prueba
def init_database():
    with app.app_context():
        db.create_all()
        
        # Verificar si ya existen usuarios
        if User.query.count() == 0:
            # Crear usuarios de prueba
            users = [
                User(username='alice', password='password123', email='alice@example.com'),
                User(username='bob', password='password456', email='bob@example.com'),
                User(username='charlie', password='password789', email='charlie@example.com')
            ]
            
            for user in users:
                db.session.add(user)
            
            db.session.commit()
            print("Base de datos inicializada con usuarios de prueba")

# RUTAS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABLE: Sin hash de contraseña
        user = User.query.filter_by(username=username, password=password).first()
        
        if user:
            login_user(user)
            # VULNERABLE: Sin validación de 'next' parameter
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Credenciales inválidas')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('dashboard.html', users=users)

@app.route('/profile')
@login_required
def profile():
    transfers_sent = Transfer.query.filter_by(from_user_id=current_user.id).all()
    transfers_received = Transfer.query.filter_by(to_user_id=current_user.id).all()
    return render_template('profile.html', 
                         transfers_sent=transfers_sent,
                         transfers_received=transfers_received)

# RUTAS VULNERABLES A CSRF

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    """Transferir dinero - VULNERABLE a CSRF"""
    to_username = request.form.get('to_username')
    amount = int(request.form.get('amount', 0))
    
    # Validaciones básicas
    if amount <= 0:
        return jsonify({'error': 'Cantidad inválida'}), 400
    
    if current_user.balance < amount:
        return jsonify({'error': 'Balance insuficiente'}), 400
    
    # Buscar usuario destino
    to_user = User.query.filter_by(username=to_username).first()
    if not to_user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if to_user.id == current_user.id:
        return jsonify({'error': 'No puedes transferirte a ti mismo'}), 400
    
    # Realizar transferencia
    current_user.balance -= amount
    to_user.balance += amount
    
    # Registrar transferencia
    transfer = Transfer(
        from_user_id=current_user.id,
        to_user_id=to_user.id,
        amount=amount
    )
    db.session.add(transfer)
    db.session.commit()
    
    return jsonify({'success': True, 'new_balance': current_user.balance})

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    """Actualizar email - VULNERABLE a CSRF"""
    new_email = request.form.get('email')
    
    if new_email:
        current_user.email = new_email
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Email requerido'}), 400

# RUTAS VULNERABLES A XSS

@app.route('/messages')
def messages():
    """Mostrar mensajes - VULNERABLE a XSS almacenado"""
    all_messages = Message.query.order_by(Message.created_at.desc()).all()
    return render_template('messages.html', messages=all_messages)

@app.route('/post_message', methods=['POST'])
@login_required
def post_message():
    """Publicar mensaje - VULNERABLE: sin sanitización"""
    content = request.form.get('content')
    
    if content:
        # VULNERABLE: Almacena contenido sin sanitizar
        message = Message(content=content, user_id=current_user.id)
        db.session.add(message)
        db.session.commit()
        
    return redirect(url_for('messages'))

@app.route('/search')
def search():
    """Búsqueda - VULNERABLE a XSS reflejado"""
    query = request.args.get('q', '')
    
    # VULNERABLE: Refleja la entrada del usuario sin sanitizar
    results = []
    error = None
    
    if query:
        # Búsqueda simple en mensajes
        results = Message.query.filter(Message.content.contains(query)).all()
        if not results:
            error = f'No se encontraron resultados para: {query}'
    
    return render_template('search.html', query=query, results=results, error=error)

# API endpoints para demostración

@app.route('/api/user_info')
@login_required
def api_user_info():
    """API endpoint - VULNERABLE: expone información sensible"""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'balance': current_user.balance,
        'session_id': request.cookies.get('session')  # VULNERABLE: expone session ID
    })

@app.route('/api/transfer', methods=['POST'])
@login_required
def api_transfer():
    """API para transferencia - VULNERABLE a CSRF"""
    data = request.get_json()
    
    to_username = data.get('to_username')
    amount = data.get('amount', 0)
    
    to_user = User.query.filter_by(username=to_username).first()
    if not to_user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if current_user.balance >= amount > 0:
        current_user.balance -= amount
        to_user.balance += amount
        
        transfer = Transfer(
            from_user_id=current_user.id,
            to_user_id=to_user.id,
            amount=amount
        )
        db.session.add(transfer)
        db.session.commit()
        
        return jsonify({'success': True, 'new_balance': current_user.balance})
    
    return jsonify({'error': 'Transferencia inválida'}), 400

# Ruta para servir archivos de ataque CSRF (solo para demostración)
@app.route('/evil/<path:filename>')
def serve_evil(filename):
    """Servir archivos de ataque para demostración"""
    return app.send_static_file(f'evil/{filename}')

if __name__ == '__main__':
    init_database()
    # VULNERABLE: Debug mode activado
    app.run(debug=True, port=5010)
