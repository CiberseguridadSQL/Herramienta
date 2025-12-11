"""
Motor de Ataque Automatizado (Scanner)
Envía payloads y analiza respuestas del servidor
"""

import requests
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
import json

class SQLInjectionScanner:
    """Scanner automatizado para detectar vulnerabilidades SQL Injection"""
    
    def __init__(self, timeout: int = 10, cookies: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, verify_ssl: bool = False):
        self.timeout = timeout
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Headers por defecto
        default_headers = {
            'User-Agent': 'SQLi-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        default_headers.update(self.headers)
        self.session.headers.update(default_headers)
        
        if self.cookies:
            self.session.cookies.update(self.cookies)
    
    def get_base_response(self, url: str, method: str = 'GET', 
                          params: Optional[Dict] = None, 
                          data: Optional[Dict] = None) -> Dict:
        """
        Obtiene la respuesta base (sin payload) para comparación
        """
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, json=None, timeout=self.timeout)
            
            elapsed_time = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'time': elapsed_time,
                'length': len(response.text),
                'url': response.url
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'error': str(e),
                'connection_error': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'error': str(e)
            }
        except Exception as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def check_connectivity(self, url: str) -> bool:
        """
        Verifica si el servidor está accesible antes de empezar el escaneo
        """
        try:
            response = self.session.get(url, timeout=5)
            return response.status_code > 0
        except:
            return False
    
    def inject_payload_get(self, url: str, param_name: str, payload: str) -> Dict:
        """
        Inyecta payload en parámetro GET
        """
        try:
            parsed_url = urlparse(url)
            # URL encode el payload pero mantener caracteres importantes para SQLi
            encoded_payload = quote(payload, safe="'\"-")
            # Construir URL directamente
            target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param_name}={encoded_payload}"
            
            start_time = time.time()
            response = self.session.get(target_url, timeout=self.timeout)
            elapsed_time = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'time': elapsed_time,
                'length': len(response.text),
                'url': response.url,
                'payload': payload,
                'param': param_name
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Error de conexión o timeout - retornar error pero no fallar
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e),
                'connection_error': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e)
            }
        except Exception as e:
            # Capturar cualquier otra excepción
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def inject_payload_post(self, url: str, data: Dict, param_name: str, 
                           payload: str) -> Dict:
        """
        Inyecta payload en parámetro POST
        """
        try:
            # Crear copia de datos y agregar payload
            test_data = data.copy()
            test_data[param_name] = payload
            
            start_time = time.time()
            response = self.session.post(url, data=test_data, timeout=self.timeout)
            elapsed_time = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'time': elapsed_time,
                'length': len(response.text),
                'url': response.url,
                'payload': payload,
                'param': param_name
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Error de conexión o timeout
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e),
                'connection_error': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e)
            }
        except Exception as e:
            # Capturar cualquier otra excepción
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def discover_parameters(self, url: str, method: str = 'GET') -> List[str]:
        """
        Descubre parámetros de la URL o formulario
        """
        params = []
        
        if method.upper() == 'GET':
            # Extraer parámetros de la URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            params = list(query_params.keys())
        else:
            # Intentar descubrir parámetros del formulario HTML
            try:
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Buscar inputs en formularios
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for inp in inputs:
                        name = inp.get('name')
                        if name and name not in params:
                            params.append(name)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                # Si no puede conectar, retornar lista vacía
                pass
            except Exception:
                # Cualquier otro error, continuar sin parámetros descubiertos
                pass
        
        return params
    
    def scan_endpoint(self, url: str, method: str = 'GET', 
                     params: Optional[List[str]] = None,
                     payloads: List[Dict] = None) -> List[Dict]:
        """
        Escanea un endpoint completo con todos los payloads
        """
        if payloads is None:
            from payloads import get_all_payloads
            payloads = get_all_payloads()
        
        results = []
        
        # Descubrir parámetros si no se proporcionan
        if params is None:
            params = self.discover_parameters(url, method)
        
        if not params:
            # Si no hay parámetros, intentar con parámetros comunes
            params = ['id', 'user', 'username', 'email', 'password', 'search', 
                     'q', 'query', 'name', 'value', 'buscar', 'empleado', 'nombre']
        
        # Obtener respuesta base
        base_data = {}
        if method.upper() == 'POST':
            # Para POST, necesitamos datos base
            for param in params:
                base_data[param] = 'test'
        
        # Para GET, usar un valor neutral que no cause errores
        base_params = {}
        if method.upper() == 'GET':
            for param in params:
                # Usar valores que probablemente no existan pero no causen errores SQL
                base_params[param] = '999999'  # ID que probablemente no existe
        
        base_response = self.get_base_response(url, method, 
                                               params=base_params if method == 'GET' else None,
                                               data=base_data if method == 'POST' else None)
        
        # Verificar si hay errores de conexión en la respuesta base
        if base_response.get('connection_error'):
            print(f"  [!] Connection error: {base_response.get('error', 'Unknown error')}")
            print(f"  [!] Skipping scan for this endpoint due to connection issues")
            return []
        
        # Debug: mostrar información de respuesta base
        base_status = base_response.get('status_code', 0)
        base_length = base_response.get('length', 0)
        print(f"  [*] Base response: status={base_status}, length={base_length}")
        if base_length == 0:
            print(f"  [!] WARNING: Base response is empty! This may affect detection accuracy.")
        
        # Probar cada payload en cada parámetro
        connection_errors = 0
        max_connection_errors = 5  # Máximo de errores de conexión antes de detener
        
        print(f"  [*] Testing {len(params)} parameters with {len(payloads)} payloads each...")
        
        # Para boolean-blind, necesitamos probar condiciones TRUE y FALSE explícitamente
        boolean_true_payloads = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
        boolean_false_payloads = ["' OR '1'='2", "' OR 1=2--", "' OR 'a'='b"]
        
        for param_idx, param in enumerate(params):
            print(f"  [+] Testing parameter {param_idx+1}/{len(params)}: {param} ({len(payloads)} payloads)")
            
            # Para boolean-blind, primero probar TRUE y FALSE explícitamente
            if any(p.get('type') == 'boolean_blind' for p in payloads):
                true_responses = []
                false_responses = []
                
                # Probar payloads TRUE
                for true_payload in boolean_true_payloads:
                    try:
                        if method.upper() == 'GET':
                            true_resp = self.inject_payload_get(url, param, true_payload)
                        else:
                            true_resp = self.inject_payload_post(url, base_data, param, true_payload)
                        if not true_resp.get('connection_error'):
                            true_responses.append(true_resp)
                    except:
                        pass
                
                # Probar payloads FALSE
                for false_payload in boolean_false_payloads:
                    try:
                        if method.upper() == 'GET':
                            false_resp = self.inject_payload_get(url, param, false_payload)
                        else:
                            false_resp = self.inject_payload_post(url, base_data, param, false_payload)
                        if not false_resp.get('connection_error'):
                            false_responses.append(false_resp)
                    except:
                        pass
                
                # Guardar respuestas TRUE y FALSE para análisis posterior
                if true_responses and false_responses:
                    for true_resp in true_responses:
                        true_resp['payload_info'] = {'payload': true_resp.get('payload', ''), 'type': 'boolean_blind'}
                        true_resp['base_response'] = base_response
                        true_resp['is_boolean_test'] = True
                        true_resp['boolean_type'] = 'true'
                        results.append(true_resp)
                    
                    for false_resp in false_responses:
                        false_resp['payload_info'] = {'payload': false_resp.get('payload', ''), 'type': 'boolean_blind'}
                        false_resp['base_response'] = base_response
                        false_resp['is_boolean_test'] = True
                        false_resp['boolean_type'] = 'false'
                        results.append(false_resp)
            
            for idx, payload_info in enumerate(payloads):
                payload = payload_info['payload']
                
                try:
                    if method.upper() == 'GET':
                        test_response = self.inject_payload_get(url, param, payload)
                    else:
                        test_response = self.inject_payload_post(url, base_data, param, payload)
                    
                    # Si hay error de conexión, incrementar contador
                    if test_response.get('connection_error'):
                        connection_errors += 1
                        if connection_errors >= max_connection_errors:
                            print(f"  [!] Too many connection errors. Stopping scan for this endpoint.")
                            return results
                    
                    # Agregar información del payload
                    test_response['payload_info'] = payload_info
                    test_response['base_response'] = base_response
                    
                    results.append(test_response)
                    
                    # Mostrar progreso cada 10 payloads
                    if (idx + 1) % 10 == 0:
                        print(f"      Progress: {idx + 1}/{len(payloads)} payloads tested")
                    
                    # Pequeña pausa para no sobrecargar el servidor
                    time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    print("\n  [!] Scan interrupted by user")
                    raise
                except Exception as e:
                    print(f"  [!] Error testing payload: {e}")
                    continue
        
        return results
    
    def scan_multiple_endpoints(self, base_url: str, endpoints: List[str],
                               method: str = 'GET', payloads: List[Dict] = None) -> Dict:
        """
        Escanea múltiples endpoints
        """
        all_results = {}
        
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            print(f"\n[*] Scanning endpoint: {full_url}")
            
            results = self.scan_endpoint(full_url, method, payloads=payloads)
            all_results[endpoint] = {
                'url': full_url,
                'results': results
            }
        
        return all_results

