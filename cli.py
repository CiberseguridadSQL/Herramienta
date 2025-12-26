"""
Interfaz de Línea de Comandos (CLI) Profesional
"""

import argparse
import sys
import json
from typing import List, Optional
from urllib.parse import urlparse

def parse_arguments():
    """Parsea argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Herramienta profesional de detección de vulnerabilidades SQLi',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python detector.py --url http://localhost:5000 --attack all
  python detector.py --url http://192.168.1.10 --endpoint /login --ml
  python detector.py --url http://target.com --report reporte.html --aggressive
  python detector.py --url http://app.com --method POST --cookies '{"session":"abc123"}'
        """
    )
    
    # Argumentos obligatorios
    parser.add_argument(
        '--url',
        type=str,
        required=True,
        help='URL base objetivo (ej: http://localhost:5000)'
    )
    
    # Argumentos opcionales
    parser.add_argument(
        '--endpoint',
        type=str,
        action='append',
        dest='endpoints',
        help='Endpoint específico a analizar (puede usarse múltiples veces)'
    )
    
    parser.add_argument(
        '--method',
        type=str,
        choices=['GET', 'POST', 'BOTH'],
        default='GET',
        help='Método HTTP a usar (default: GET)'
    )
    
    parser.add_argument(
        '--attack',
        type=str,
        choices=['basic', 'aggressive', 'ml', 'all', 'recon'],
        default='all',
        help='Modo de ataque: basic, aggressive, ml, all, recon (default: all)'
    )
    
    parser.add_argument(
        '--payload-set',
        type=str,
        choices=['basic', 'union', 'boolean_blind', 'time_based', 'error_based', 'all'],
        default='all',
        help='Conjunto de payloads a usar (default: all)'
    )
    
    parser.add_argument(
        '--ml',
        action='store_true',
        help='Usar clasificador de Machine Learning'
    )
    
    parser.add_argument(
        '--ml-model',
        type=str,
        help='Ruta al modelo ML pre-entrenado'
    )
    
    parser.add_argument(
        '--train-ml',
        action='store_true',
        help='Entrenar modelo ML con los resultados del escaneo'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout para requests en segundos (default: 10)'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Modo agresivo: aumenta timeouts y número de intentos'
    )
    
    parser.add_argument(
        '--cookies',
        type=str,
        help='Cookies en formato JSON (ej: \'{"session":"abc123"}\')'
    )
    
    parser.add_argument(
        '--headers',
        type=str,
        help='Headers personalizados en formato JSON'
    )
    
    parser.add_argument(
        '--report',
        type=str,
        help='Ruta para guardar el reporte (HTML o JSON según extensión)'
    )
    
    parser.add_argument(
        '--json',
        type=str,
        help='Ruta para guardar reporte JSON'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Modo verbose: muestra información detallada'
    )
    
    parser.add_argument(
        '--params',
        type=str,
        help='Parámetros específicos a probar (separados por coma)'
    )
    
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verificar certificados SSL (default: False)'
    )

    parser.add_argument(
        '--forced-params',
        type=str,
        help='Define un parámetro con un valor fijo. Separe cada valor por comas (,)'
    )

    parser.add_argument(
        '--forced-values',
        type=str,
        help='Define valores para los parámetros fijos. Separe cada valor por comas (,)'
    )
    
    return parser.parse_args()

def validate_url(url: str) -> bool:
    """Valida que la URL sea válida"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def parse_json_input(json_str: str) -> dict:
    """Parsea string JSON a diccionario"""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing JSON: {e}")
        sys.exit(1)

def get_payloads_by_mode(mode: str, payload_set: str):
    """Obtiene payloads según el modo de ataque"""
    from payloads import get_all_payloads, get_payloads_by_type, PAYLOADS
    
    if payload_set == 'all':
        if mode == 'basic':
            # Solo payloads básicos
            return get_payloads_by_type('basic')
        elif mode == 'aggressive':
            # Todos los payloads
            return get_all_payloads()
        elif mode == 'ml':
            # Payloads balanceados para ML
            all_payloads = []
            for ptype in PAYLOADS.keys():
                all_payloads.extend(get_payloads_by_type(ptype))
            return all_payloads
        elif mode == 'recon':
            # Payloads de reconocimiento (básicos + algunos avanzados)
            recon_payloads = []
            recon_payloads.extend(get_payloads_by_type('basic'))
            recon_payloads.extend(get_payloads_by_type('error_based')[:5])
            return recon_payloads
        else:  # all
            return get_all_payloads()
    else:
        return get_payloads_by_type(payload_set)

def print_banner():
    """Imprime banner de la herramienta"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║         SQL INJECTION SCANNER - Security Tool v1.0           ║
    ║         Detección Profesional de Vulnerabilidades SQLi       ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_summary(args):
    """Imprime resumen de configuración"""
    print("\n[*] Configuration:")
    print(f"    URL: {args.url}")
    print(f"    Method: {args.method}")
    print(f"    Attack Mode: {args.attack}")
    print(f"    Payload Set: {args.payload_set}")
    print(f"    ML Enabled: {args.ml}")
    print(f"    Timeout: {args.timeout}s")
    print(f"    Aggressive: {args.aggressive}")
    if args.endpoints:
        print(f"    Endpoints: {', '.join(args.endpoints)}")
    print()

