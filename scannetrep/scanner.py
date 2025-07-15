#!/usr/bin/env python3
import socket
import threading
import subprocess
import time
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ipaddress


class NetworkScanner:
    def __init__(self, target, timeout=3, max_threads=50):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.services = {}
        self.active_hosts = []

        self.common_ports = [
             21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080 
             ]
        
        self.known_services = { 
              21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt" }


    def parse_port_range(self, port_string):

        ports = []

        if not port_string:
            return self.common_ports

        try:
            port_parts = port_string.split(',')

            for part in port_parts:
                part = part.strip()

                if '-' in part:
                    start, end =  part.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())

                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        print(f"Invalid port range: {part}")
                        continue

                    ports.extend(range(start_port, end_port + 1))
                else:
                    port = int(part.strip())
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        print(f"Invalid port: {part}")
            return sorted(list(set(ports)))  # Remove duplicates  y ordenar       


        except ValueError as e:
            print(f"Error parsing port range: {e}")
            return self.common_ports   
    

    def is_valid_ip(self, ip):
        """ Validadar IP address format """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def resolve_hostname(self, hostname):
        """ Resolve hostname to IP address """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"Could not resolve hostname: {hostname}")
            return None
       
    
    def ping_host(self, host):
        """ Ping a host to check if it's active """
        try:
            param = "-n" if subprocess.os.name == "nt" else "-c"
            command = ["ping", param, "1", "W", "1000", host] 

            result = subprocess.run(command, capture_output=True,text=True, timeout=5)
            return result.returncode == 0
        except:        
            return False
        

    def scan_port(self, host, port):

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                service = self.known_services.get(port, "Unknown")
                return {

                    "host": host,
                    "port": port,
                    "service": service,
                    'status': 'open'
                }
            
        except:
            pass
        return None

    
    def grab_banner(self, host, port):
        """ Attempt to grab a service banner """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            if port in [80, 8080]:
                sock.send(b"GET / HTTP/1.1\r\nHost:" + host.encode() + b"\r\n\r\n")


            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return None
        
    
    def discover_hosts(self, network):

        print(f"\n[*] Escanning network: {network} ...")

        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts_to_check = list(net.hosts())

            if len(hosts_to_check) > 254:
                print("Red muy grande")
                hosts_to_check = hosts_to_check[:254]  # Limitar a 254 hosts

            with ThreadPoolExecutor(max_workers=min(50, len(hosts_to_check))) as executor:   
                futures = {executor.submit(self.ping_host, str(host)): str(host) for host in hosts_to_check}
                for future in futures:
                    try: 
                        if future.result():
                            host = futures[future]
                            self.active_hosts.append(host)
                            print(f"Host activo encontrados: {host}")
                    except Exception as e:
                        continue
        except Exception as e:
            print(f"Error discovering hosts: {e}")


    
    def scan_ports(self, host, ports=None):

        ports = ports or self.common_ports
        print(f"\n[*] Escanning ports on {host} ...")

        max_workers = min(self.max_threads, len(ports))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        self.open_ports.append(result)
                        print(f"Puerto abierto encontrado: {result['port']} ({result['service']}) en {host}")
                except Exception as e:
                    continue

    
    def enumerate_services(self, host):
        """ Enumerate services on open ports """
        print(f"\n[*] Enumerating services on {host} ...")
        
        for port_info in self.open_ports:
            port = port_info['port']
            banner = self.grab_banner(host, port)
            
            self.services[port] = {

                'service': port_info['service'],
                'banner' : banner,
                'port' : port
            }

            
            
            if banner:
                self.services[port] = banner
                print(f"Banner encontrado en {host}:{port} - {banner}")
            else:
                print(f"No se pudo obtener banner de {host}:{port}")

    def generate_report(self):
        """Genera un reporte completo del escaneo"""
        print("\n" + "="*60)
        print("REPORTE DE ESCANEO")
        print("="*60)
        print(f"Objetivo: {self.target}")
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Hosts activos: {len(self.active_hosts)}")
        print(f"Puertos abiertos: {len(self.open_ports)}")
        
        if self.active_hosts:
            print("\n[*] HOSTS ACTIVOS:")
            for host in self.active_hosts:
                print(f"  - {host}")
        
        if self.open_ports:
            print("\n[*] PUERTOS ABIERTOS:")
            for port_info in self.open_ports:
                print(f"  - {port_info['host']}:{port_info['port']} ({port_info['service']})")
        
        if self.services:
            print("\n[*] SERVICIOS DETECTADOS:")
            for port, service_info in self.services.items():
                print(f"  Puerto {port}: {service_info['service']}")
                if service_info['banner']:
                    print(f"    Banner: {service_info['banner'][:80]}...")
        
        print("\n" + "="*60)
    
    def run_full_scan(self, port_range=None):
        """
        Ejecuta un escaneo completo.
        
        Args:
            port_range (str): Rango de puertos (ej: "1-1000", "22,80,443", "1-100,443,8080")
        """
        print("[*] Iniciando escaneo completo...")
        print(f"[*] Objetivo: {self.target}")
        print(f"[*] Timeout: {self.timeout}s")
        print(f"[*] Hilos máximos: {self.max_threads}")
        
        # Parsear puertos
        if port_range:
            ports_to_scan = self.parse_port_range(port_range)
        else:
            ports_to_scan = self.common_ports
            
        print(f"[*] Puertos a escanear: {len(ports_to_scan)}")
        
        if len(ports_to_scan) > 1000:
            print("[!] Advertencia: Escaneando más de 1000 puertos puede ser lento")
        
        start_time = time.time()
        
        # Resolver hostname si es necesario
        target_ip = self.target
        if not self.is_valid_ip(self.target) and "/" not in self.target:
            print(f"[*] Resolviendo hostname: {self.target}")
            target_ip = self.resolve_hostname(self.target)
            if not target_ip:
                print(f"[!] No se pudo resolver el hostname: {self.target}")
                return
            print(f"[*] Resuelto a: {target_ip}")
        
        # Si es una red, descubrir hosts primero
        if "/" in self.target:
            self.discover_hosts(self.target)
            targets = self.active_hosts
        else:
            # Si es una IP individual, verificar si está activa
            if self.ping_host(target_ip):
                targets = [target_ip]
                print(f"[+] Host {target_ip} está activo")
            else:
                print(f"[!] Host {target_ip} no responde al ping, continuando con escaneo...")
                targets = [target_ip]  # Continuar aunque no responda al ping
        
        # Escanear puertos en cada host activo
        for host in targets:
            self.scan_ports(host, ports_to_scan)
            self.enumerate_services(host)
        
        end_time = time.time()
        print(f"\n[*] Escaneo completado en {end_time - start_time:.2f} segundos")
        
        # Generar reporte
        self.generate_report()


def main():
    """Función principal con interfaz de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="NetworkScanner - Herramienta de escaneo de redes",
        epilog="ADVERTENCIA: Use solo en redes autorizadas"
    )
    
    parser.add_argument("target", help="IP, hostname o rango de red (ej: 192.168.1.1, google.com, 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout en segundos (default: 3)")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Número máximo de hilos (default: 50)")
    parser.add_argument("-p", "--ports", help="Puertos específicos: '22,80,443' o rango: '1-1000' o mixto: '22,80,1000-2000'")
    parser.add_argument("--full", action="store_true", help="Escanear todos los puertos (1-65535)")
    parser.add_argument("--top1000", action="store_true", help="Escanear los 1000 puertos más comunes")
    
    args = parser.parse_args()
    
    # Determinar puertos a escanear
    port_range = None
    if args.full:
        port_range = "1-65535"
        print("[!] Escaneo completo de puertos habilitado. Esto puede tomar mucho tiempo.")
    elif args.top1000:
        port_range = "1-1000"
    elif args.ports:
        port_range = args.ports
    
    # Crear y ejecutar escáner
    scanner = NetworkScanner(args.target, timeout=args.timeout, max_threads=args.threads)
    
    try:
        scanner.run_full_scan(port_range)
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario")
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")


# Ejemplo de uso programático
if __name__ == "__main__":
    import sys
    
    # Si hay argumentos de línea de comandos, usar main()
    if len(sys.argv) > 1:
        main()
    else:
        # Si no hay argumentos, mostrar ejemplos
        print("=== EJEMPLOS DE USO ===")
        print("\n1. Desde línea de comandos:")
        print("python scanner.py 192.168.1.1")
        print("python scanner.py 192.168.1.1 -p 1-1000")
        print("python scanner.py 192.168.1.1 -p 22,80,443,3389")
        print("python scanner.py 192.168.1.0/24")
        print("python scanner.py google.com -p 80,443")
        
        print("\n2. Desde código:")
        print("=== EJEMPLO: Escaneo básico ===")
        scanner = NetworkScanner("127.0.0.1", timeout=2)
        scanner.run_full_scan()
        
        print("\n=== EJEMPLO: Escaneo con rango de puertos ===")
        scanner2 = NetworkScanner("127.0.0.1", timeout=2)
        scanner2.run_full_scan("80-90")
    


         


