# app.py - Aplicación web Flask para el Sistema de Estudiantes
from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
from datetime import datetime

# Importar las clases del sistema (asume que están en el mismo archivo o módulo)
from estudiante import SistemaRegistroEstudiantes, Estudiante

app = Flask(__name__)

# Crear una instancia global del sistema
sistema = SistemaRegistroEstudiantes()

# Datos de ejemplo
def cargar_datos_ejemplo():
    estudiantes_ejemplo = [
        ("María", "González", "Algoritmos con Python", "L4"),
        ("Carlos", "Rodríguez", "Algoritmos con Python", "L4"),
        ("Ana", "López", "Detección de Superficies Web", "L5"),
        ("Luis", "Martínez", "Algoritmos con Python", "L4"),
        ("Sofia", "Hernández", "Detección de Superficies Web", "L5"),
    ]
    
    for nombre, apellido, curso, nivel in estudiantes_ejemplo:
        sistema.registrar_estudiante(nombre, apellido, curso, nivel)

# Cargar datos al iniciar
cargar_datos_ejemplo()

@app.route('/')
def index():
    """Página principal con estadísticas"""
    stats = sistema.obtener_estadisticas()
    return render_template('index.html', stats=stats)

@app.route('/registro')
def registro():
    """Página de registro de estudiantes"""
    return render_template('registro.html')

@app.route('/consulta')
def consulta():
    """Página de consulta de estudiantes"""
    return render_template('consulta.html')

@app.route('/listar')
def listar():
    """Página que lista todos los estudiantes"""
    estudiantes = sistema.listar_todos()
    return render_template('listar.html', estudiantes=estudiantes)

# API endpoints
@app.route('/api/registrar', methods=['POST'])
def api_registrar():
    """API para registrar un nuevo estudiante"""
    try:
        data = request.json
        estudiante = sistema.registrar_estudiante(
            data['nombre'],
            data['apellido'],
            data['curso'],
            data['nivel']
        )
        return jsonify({
            'success': True,
            'estudiante': estudiante.to_dict(),
            'message': 'Estudiante registrado exitosamente'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al registrar estudiante: {str(e)}'
        }), 400

@app.route('/api/consultar/<tipo>/<valor>')
def api_consultar(tipo, valor):
    """API para consultar estudiantes"""
    try:
        if tipo == 'id':
            estudiante = sistema.consultar_por_id(int(valor))
            if estudiante:
                return jsonify({
                    'success': True,
                    'estudiantes': [estudiante.to_dict()]
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Estudiante no encontrado'
                })
        
        elif tipo == 'nombre':
            estudiantes = sistema.consultar_por_nombre(valor)
            return jsonify({
                'success': True,
                'estudiantes': [e.to_dict() for e in estudiantes]
            })
        
        elif tipo == 'curso':
            estudiantes = sistema.consultar_por_curso(valor)
            return jsonify({
                'success': True,
                'estudiantes': [e.to_dict() for e in estudiantes]
            })
        
        elif tipo == 'nivel':
            estudiantes = sistema.consultar_por_nivel(valor)
            return jsonify({
                'success': True,
                'estudiantes': [e.to_dict() for e in estudiantes]
            })
        
        else:
            return jsonify({
                'success': False,
                'message': 'Tipo de consulta no válido'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error en la consulta: {str(e)}'
        }), 400

@app.route('/api/eliminar/<int:id_estudiante>', methods=['DELETE'])
def api_eliminar(id_estudiante):
    """API para eliminar un estudiante"""
    try:
        if sistema.eliminar_estudiante(id_estudiante):
            return jsonify({
                'success': True,
                'message': 'Estudiante eliminado exitosamente'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Estudiante no encontrado'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al eliminar estudiante: {str(e)}'
        }), 400

@app.route('/api/estadisticas')
def api_estadisticas():
    """API para obtener estadísticas del sistema"""
    stats = sistema.obtener_estadisticas()
    return jsonify(stats)

@app.route('/api/todos')
def api_todos():
    """API para obtener todos los estudiantes"""
    estudiantes = sistema.listar_todos()
    return jsonify({
        'success': True,
        'estudiantes': [e.to_dict() for e in estudiantes]
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)


# ===== TEMPLATES HTML =====
# Crear carpeta 'templates' y estos archivos:

# templates/base.html
BASE_HTML = '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Estudiantes</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .navbar {
            background: #333;
            padding: 15px 0;
            margin: -20px -20px 20px -20px;
            border-radius: 8px 8px 0 0;
        }
        .navbar a {
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            margin: 0 5px;
            border-radius: 4px;
            transition: background 0.3s;
        }
        .navbar a:hover {
            background: #555;
        }
        .card {
            background: white;
            padding: 20px;
            margin: 10px 0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-group {
            margin: 15px 0;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .btn {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover {
            background: #0056b3;
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .table th {
            background: #f8f9fa;
            font-weight: bold;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="navbar">
            <a href="/">Inicio</a>
            <a href="/registro">Registrar</a>
            <a href="/consulta">Consultar</a>
            <a href="/listar">Listar Todos</a>
        </nav>
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>'''

# templates/index.html
INDEX_HTML = '''{% extends "base.html" %}

{% block content %}
<h1>Sistema de Registro y Consulta de Estudiantes</h1>

<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-number">{{ stats.total_estudiantes }}</div>
        <div>Total Estudiantes</div>
    </div>
    
    <div class="stat-card">
        <div class="stat-number">{{ stats.por_curso|length }}</div>
        <div>Cursos Diferentes</div>
    </div>
    
    <div class="stat-card">
        <div class="stat-number">{{ stats.por_nivel|length }}</div>
        <div>Niveles Diferentes</div>
    </div>
</div>

<div class="card">
    <h3>Distribución por Cursos</h3>
    {% for curso, cantidad in stats.por_curso.items() %}
    <div style="margin: 10px 0;">
        <strong>{{ curso }}:</strong> {{ cantidad }} estudiantes
    </div>
    {% endfor %}
</div>

<div class="card">
    <h3>Distribución por Niveles</h3>
    {% for nivel, cantidad in stats.por_nivel.items() %}
    <div style="margin: 10px 0;">
        <strong>{{ nivel }}:</strong> {{ cantidad }} estudiantes
    </div>
    {% endfor %}
</div>
{% endblock %}'''
