# Sistema de Registro y Consulta de Estudiantes
from datetime import datetime
from typing import List, Dict, Optional

class Estudiante:
    """Clase para representar un estudiante"""
    
    def __init__(self, id_estudiante: int, nombre: str, apellido: str, 
                 curso: str, nivel: str, fecha_registro: str = None):
        self.id_estudiante = id_estudiante
        self.nombre = nombre
        self.apellido = apellido
        self.curso = curso
        self.nivel = nivel
        self.fecha_registro = fecha_registro or datetime.now().strftime("%d-%b")
        
    def __str__(self):
        return f"ID: {self.id_estudiante} | {self.nombre} {self.apellido} | {self.curso} ({self.nivel})"
    
    def to_dict(self):
        """Convierte el estudiante a diccionario para facilitar el manejo"""
        return {
            'id': self.id_estudiante,
            'nombre': self.nombre,
            'apellido': self.apellido,
            'curso': self.curso,
            'nivel': self.nivel,
            'fecha_registro': self.fecha_registro
        }

class SistemaRegistroEstudiantes:
    """Sistema para gestionar el registro y consulta de estudiantes"""
    
    def __init__(self):
        self.estudiantes: List[Estudiante] = []
        self.contador_id = 1
        
    def registrar_estudiante(self, nombre: str, apellido: str, 
                           curso: str, nivel: str) -> Estudiante:
        """Registra un nuevo estudiante en el sistema"""
        nuevo_estudiante = Estudiante(
            id_estudiante=self.contador_id,
            nombre=nombre,
            apellido=apellido,
            curso=curso,
            nivel=nivel
        )
        self.estudiantes.append(nuevo_estudiante)
        self.contador_id += 1
        return nuevo_estudiante
    
    def consultar_por_id(self, id_estudiante: int) -> Optional[Estudiante]:
        """Consulta un estudiante por su ID"""
        for estudiante in self.estudiantes:
            if estudiante.id_estudiante == id_estudiante:
                return estudiante
        return None
    
    def consultar_por_nombre(self, nombre: str) -> List[Estudiante]:
        """Consulta estudiantes por nombre (búsqueda parcial)"""
        resultados = []
        for estudiante in self.estudiantes:
            if nombre.lower() in estudiante.nombre.lower():
                resultados.append(estudiante)
        return resultados
    
    def consultar_por_curso(self, curso: str) -> List[Estudiante]:
        """Consulta estudiantes por curso"""
        resultados = []
        for estudiante in self.estudiantes:
            if curso.lower() in estudiante.curso.lower():
                resultados.append(estudiante)
        return resultados
    
    def consultar_por_nivel(self, nivel: str) -> List[Estudiante]:
        """Consulta estudiantes por nivel"""
        resultados = []
        for estudiante in self.estudiantes:
            if nivel.lower() == estudiante.nivel.lower():
                resultados.append(estudiante)
        return resultados
    
    def listar_todos(self) -> List[Estudiante]:
        """Retorna todos los estudiantes registrados"""
        return self.estudiantes.copy()
    
    def eliminar_estudiante(self, id_estudiante: int) -> bool:
        """Elimina un estudiante por su ID"""
        for i, estudiante in enumerate(self.estudiantes):
            if estudiante.id_estudiante == id_estudiante:
                del self.estudiantes[i]
                return True
        return False
    
    def actualizar_estudiante(self, id_estudiante: int, **kwargs) -> bool:
        """Actualiza los datos de un estudiante"""
        estudiante = self.consultar_por_id(id_estudiante)
        if estudiante:
            for key, value in kwargs.items():
                if hasattr(estudiante, key):
                    setattr(estudiante, key, value)
            return True
        return False
    
    def obtener_estadisticas(self) -> Dict:
        """Obtiene estadísticas del sistema"""
        total_estudiantes = len(self.estudiantes)
        cursos = {}
        niveles = {}
        
        for estudiante in self.estudiantes:
            # Contar por curso
            if estudiante.curso in cursos:
                cursos[estudiante.curso] += 1
            else:
                cursos[estudiante.curso] = 1
                
            # Contar por nivel
            if estudiante.nivel in niveles:
                niveles[estudiante.nivel] += 1
            else:
                niveles[estudiante.nivel] = 1
        
        return {
            'total_estudiantes': total_estudiantes,
            'por_curso': cursos,
            'por_nivel': niveles
        }

# Ejemplo de uso y datos de prueba
def ejemplo_uso():
    # Crear el sistema
    sistema = SistemaRegistroEstudiantes()
    
    # Registrar estudiantes de ejemplo
    estudiantes_ejemplo = [
        ("María", "González", "Algoritmos con Python", "L4"),
        ("Carlos", "Rodríguez", "Algoritmos con Python", "L4"),
        ("Ana", "López", "Detección de Superficies Web", "L5"),
        ("Luis", "Martínez", "Algoritmos con Python", "L4"),
        ("Sofia", "Hernández", "Detección de Superficies Web", "L5"),
    ]
    
    print("=== REGISTRANDO ESTUDIANTES ===")
    for nombre, apellido, curso, nivel in estudiantes_ejemplo:
        estudiante = sistema.registrar_estudiante(nombre, apellido, curso, nivel)
        print(f"Registrado: {estudiante}")
    
    print(f"\n=== CONSULTAS ===")
    
    # Consultar por ID
    print("\n1. Consulta por ID (ID=2):")
    estudiante = sistema.consultar_por_id(2)
    if estudiante:
        print(f"   Encontrado: {estudiante}")
    else:
        print("   No encontrado")
    
    # Consultar por nombre
    print("\n2. Consulta por nombre ('María'):")
    resultados = sistema.consultar_por_nombre("María")
    for estudiante in resultados:
        print(f"   {estudiante}")
    
    # Consultar por curso
    print("\n3. Consulta por curso ('Algoritmos'):")
    resultados = sistema.consultar_por_curso("Algoritmos")
    for estudiante in resultados:
        print(f"   {estudiante}")
    
    # Consultar por nivel
    print("\n4. Consulta por nivel ('L5'):")
    resultados = sistema.consultar_por_nivel("L5")
    for estudiante in resultados:
        print(f"   {estudiante}")
    
    # Listar todos
    print("\n5. Todos los estudiantes:")
    todos = sistema.listar_todos()
    for estudiante in todos:
        print(f"   {estudiante}")
    
    # Estadísticas
    print("\n=== ESTADÍSTICAS ===")
    stats = sistema.obtener_estadisticas()
    print(f"Total de estudiantes: {stats['total_estudiantes']}")
    print("Por curso:")
    for curso, cantidad in stats['por_curso'].items():
        print(f"   {curso}: {cantidad} estudiantes")
    print("Por nivel:")
    for nivel, cantidad in stats['por_nivel'].items():
        print(f"   {nivel}: {cantidad} estudiantes")
    
    return sistema

# Ejecutar el ejemplo
if __name__ == "__main__":
    sistema = ejemplo_uso()
