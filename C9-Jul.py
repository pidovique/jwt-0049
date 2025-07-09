#!/usr/bin/env python3

"""
Analizador Cabeceras HTTP - SEGURIDAD
"""


import requests 
import sys
from urllib.parse import urlparse
from colorama import Fore,Style, init
import json 

# colores terminal ==> colorama
init()

class AnalizadorSeguridad:
    def __init__(self):
        self.cabeceras_seguridad = {
            'X-Frame-Options' : 'Proteccion contra clickjacking',
            'X-XSS-Protection': 'Proteccion contra XSS',
            'X-Content-Type-Options' : 'Previene sniffing',
            'Strict-Transport-Security': 'No http solo https',
            'Content-Security-Policy' :  'XSS , injection',
            'X-Permitted-Cross-Domain-Policies': 'Control Politicas Eje FLash',
            'Referrer-Policy' : 'Control de Info Referencia'
        }

        self.cabeceras_informacion = {

            'Server': 'Info Server',
            'X-Powered-By' : 'Tech backend',
            'X-Generator' : 'CMS o Framework',
            'X-AspNet-Version' : 'Version ASP'    
        }



    def analizar_url(self,url):
        """ Analizar URL """
        try:
            print(f"{Fore.CYAN}🌐 Analizando: {url}{Style.RESET_ALL}")
            print("=" * 70)

            # inventando HEADER NAVEGADOR
            headers = {
                'User-Agent': 'Mozilla/5.0.  (Windows NT 10.0; Win64; x64 ) AppleWebKit/537.36'
            }

            response = requests.get(url, headers=headers, timeout=10)


            #Info BASICA
            self._mostrar_info_basica(response)

            # info Segura
            self._analizar_seguridad(response.headers)

            #Info exp...
            self._analizar_informacion_expuesta(response.headers)

            # Recomendaciones

            self._generar_recomendaciones(response.headers)


        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED} ❌ Error de conexión: {e}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED} ❌ Error Inesperado : {e}{Style.RESET_ALL}")




    def _mostrar_info_basica(self, response):

        print(f"{Fore.GREEN}📊 Información Básica: {Style.RESET_ALL}")
        print(f"   Status Code : {response.status_code}")
        print(f"   Tiempo: {response.elapsed.total_seconds():2f}s")
        print(f".  Tamaño {len(response.content)} bytes\n")


    def _analizar_seguridad(self, headers):  
       """analizar cabecera""" 

       print(f"{Fore.YELLOW} Analisis de Seguridad: {Style.RESET_ALL}")

       presentes = 0 
       total = len(self.cabeceras_seguridad)

       for cabecera, descripcion in self.cabeceras_seguridad.items():
           if cabecera in headers:
               print (f" ✅{cabecera}: {headers[cabecera]}")
               presentes +=1
           else:
               print(f"  ❌ {cabecera}: NO PRESENTE ")


        # Puntuacion seguridad

       puntuacion = (presentes / total) * 100 
       color = Fore.GREEN if puntuacion >= 70 else Fore.YELLOW if puntuacion >= 40 else Fore.RED
       print(f"\n {color} 🎯 Puntuación de Seguridad: {puntuacion:1f}%{Style.RESET_ALL}\n")
    
    
    
    
    def _analizar_informacion_expuesta(self, headers):
        print(f"\n {Fore.MAGENTA} Informacion Expuesta:{Style.RESET_ALL}")

        info_encontrada = False
        for cabecera, descripcion in self.cabeceras_informacion.items():
            if cabecera in headers:
                print(f" ⚠️  {cabecera}: {headers[cabecera]} ({descripcion})") 
                info_encontrada = True


            if not info_encontrada:
                print(f". No se detecto informacion Sencible expuesta")
            print()


    def _generar_recomendaciones(self, headers):
        """ Reporte Recomendaciones """
        print(f"{Fore.BLUE}💡 Recomendaciones:{Style.RESET_ALL}")

        recomendaciones = []


        # Verificar Cabeceras Faltantes

        for cabecera in self.cabeceras_seguridad:
            if cabecera not in headers:
                recomendaciones.append(f"Implemtar {cabecera}")

        
        # Verificar info Expuesta

        for cabecera in self.cabeceras_informacion:
            if cabecera in headers:
                recomendaciones.append("Ocultar cabecera {cabecera}")

        
        if recomendaciones: 
            for i, rec in enumerate(recomendaciones, 1):
                print(f" {i}. {rec}")
        else:
            print(" Cabeceras parecen Adecuadas ")

#Funcion principal

def main():
    if len(sys.argv) != 2:
        print("Ejemplo https://example.com")
        sys.exit(1)


    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url


    
    analizador = AnalizadorSeguridad()
    analizador.analizar_url(url)

if __name__ == "__main__":

    # ADD URL
    analizador = AnalizadorSeguridad()
    analizador.analizar_url("https://homer.sii.cl/")

