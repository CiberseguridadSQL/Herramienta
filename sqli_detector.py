"""
Módulo de Detección de Vulnerabilidades SQL Injection
Implementa criterios formales OWASP para detección SQLi
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
import difflib

class SQLInjectionDetector:
    """Detector de vulnerabilidades SQL Injection basado en criterios OWASP"""
    
    # Patrones de error SQL según OWASP
    SQL_ERROR_PATTERNS = [
        r"syntax error",
        r"SQLSTATE",
        r'near "',
        r"unclosed quotation mark",
        r"You have an error in your SQL syntax",
        r"OperationalError",
        r"SQLiteException",
        r"MySQLSyntaxErrorException",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wmysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL query failed",
        r"Warning.*\Wpg_",
        r"Warning.*\Woci_",
        r"Warning.*\Wodbc_",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wdb2_",
        r"SQLite.*error",
        r"SQLite.*Exception",
        r"Microsoft.*ODBC.*SQL Server",
        r"ODBC.*SQL Server Driver",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wsqlsrv_",
        r"Warning.*\Wfbsql_",
        r"Warning.*\Wibase_",
        r"Warning.*\Wifx_",
        r"Exception.*\Worg\.hibernate",
        r"Exception.*\Worg\.springframework",
        r"java\.sql\.SQLException",
        r"java\.sql\.SQLSyntaxErrorException",
        r"com\.mysql\.jdbc\.exceptions",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"org\.postgresql\.util\.PSQLException",
        r"org\.h2\.jdbc\.JdbcSQLException",
        r"SQLException",
        r"SQLSyntaxErrorException",
        r"ORA-\d{5}",
        r"PLS-\d{5}",
        r"SQL error",
        r"SQL.*error",
        r"SQL.*Exception",
        r"Query failed",
        r"SQL command not properly ended",
        r"quoted string not properly terminated",
        r"invalid character",
        r"invalid number",
        r"column.*does not exist",
        r"table.*does not exist",
        r"unknown column",
        r"unknown table",
        r"table.*already exists",
        r"column.*already exists"
    ]
    
    # Tiempo mínimo para considerar time-based SQLi (segundos)
    TIME_BASED_THRESHOLD = 5.0
    
    def __init__(self):
        self.error_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_ERROR_PATTERNS]
    
    def detect_sql_errors(self, response_text: str) -> List[str]:
        """
        Detecta mensajes de error SQL en la respuesta
        Retorna lista de patrones encontrados
        """
        found_errors = []
        for pattern in self.error_patterns:
            if pattern.search(response_text):
                found_errors.append(pattern.pattern)
        return found_errors
    
    def detect_time_based_sqli(self, response_time: float, payload_type: str) -> bool:
        """
        Detecta SQLi time-based si el tiempo de respuesta excede el umbral
        y el payload es de tipo time-based
        """
        if payload_type != 'time_based':
            return False
        return response_time >= self.TIME_BASED_THRESHOLD
    
    def analyze_html_changes(self, base_response: str, test_response: str) -> Dict:
        """
        Analiza cambios en el HTML entre respuesta base y respuesta con payload
        Retorna métricas de similitud y diferencias
        """
        if not base_response or not test_response:
            return {
                'similarity': 0.0,
                'length_diff': abs(len(test_response) - len(base_response)),
                'significant_change': False,
                'dom_changes': []
            }
        
        # Calcular similitud usando SequenceMatcher
        similarity = difflib.SequenceMatcher(None, base_response, test_response).ratio()
        
        # Analizar cambios en el DOM usando BeautifulSoup
        try:
            base_soup = BeautifulSoup(base_response, 'html.parser')
            test_soup = BeautifulSoup(test_response, 'html.parser')
            
            base_elements = set([str(tag) for tag in base_soup.find_all()])
            test_elements = set([str(tag) for tag in test_soup.find_all()])
            
            added_elements = test_elements - base_elements
            removed_elements = base_elements - test_elements
            
            dom_changes = {
                'added': len(added_elements),
                'removed': len(removed_elements),
                'total_base': len(base_elements),
                'total_test': len(test_elements)
            }
            
            # Cambio significativo si la similitud es < 0.95 o hay cambios en DOM (MUY sensible)
            significant_change = similarity < 0.95 or len(added_elements) > 0 or len(removed_elements) > 0
            
        except Exception:
            dom_changes = {'error': 'Could not parse HTML'}
            significant_change = similarity < 0.7
        
        return {
            'similarity': similarity,
            'length_diff': abs(len(test_response) - len(base_response)),
            'significant_change': significant_change,
            'dom_changes': dom_changes
        }
    
    def detect_boolean_blind_sqli(self, base_response: str, true_response: str, 
                                   false_response: str) -> bool:
        """
        Detecta SQLi boolean-blind comparando respuestas con condiciones TRUE y FALSE
        """
        if not base_response or not true_response or not false_response:
            return False
        
        # Analizar cambios entre respuestas
        true_analysis = self.analyze_html_changes(base_response, true_response)
        false_analysis = self.analyze_html_changes(base_response, false_response)
        
        # Si hay diferencias significativas entre TRUE y FALSE, posible boolean-blind
        if true_analysis['significant_change'] and false_analysis['significant_change']:
            # Verificar que las respuestas TRUE y FALSE sean diferentes
            true_false_similarity = difflib.SequenceMatcher(
                None, true_response, false_response
            ).ratio()
            
            # Si son muy diferentes (< 0.8 similitud), posible boolean-blind
            if true_false_similarity < 0.8:
                return True
        
        return False
    
    def detect_length_based_sqli(self, base_length: int, test_length: int, 
                                  threshold: float = 0.05) -> bool:
        """
        Detecta SQLi basado en diferencias significativas en la longitud de respuesta
        threshold: porcentaje de diferencia considerado significativo (reducido a 5%)
        """
        if base_length == 0:
            return False
        
        diff_ratio = abs(test_length - base_length) / base_length
        # También considerar diferencias absolutas
        return diff_ratio >= threshold or abs(test_length - base_length) > 30
    
    def evaluate_payload(self, payload_info: Dict, base_response: Dict, 
                        test_response: Dict) -> Dict:
        """
        Evalúa un payload completo usando múltiples criterios OWASP
        Retorna un dict con el análisis completo
        """
        payload = payload_info['payload']
        payload_type = payload_info['type']
        
        # Extraer información de las respuestas
        test_text = test_response.get('text', '')
        test_time = test_response.get('time', 0.0)
        test_status = test_response.get('status_code', 0)
        test_length = len(test_text)
        
        base_text = base_response.get('text', '')
        base_length = len(base_text)
        
        # Inicializar resultado
        result = {
            'payload': payload,
            'payload_type': payload_type,
            'status_code': test_status,
            'response_time': test_time,
            'response_length': test_length,
            'base_length': base_length,
            'vulnerable': False,
            'vulnerability_type': None,
            'confidence': 'low',
            'evidence': [],
            'indicators': {}
        }
        
        # 1. Detección de errores SQL
        sql_errors = self.detect_sql_errors(test_text)
        if sql_errors:
            result['vulnerable'] = True
            result['vulnerability_type'] = 'error_based'
            result['confidence'] = 'high'
            result['evidence'].append(f"SQL errors detected: {', '.join(sql_errors[:3])}")
            result['indicators']['sql_errors'] = sql_errors
        
        # 2. Detección time-based
        if self.detect_time_based_sqli(test_time, payload_type):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'time_based'
            result['confidence'] = 'high'
            result['evidence'].append(f"Time-based delay detected: {test_time:.2f}s")
            result['indicators']['time_delay'] = test_time
        
        # 3. Análisis de cambios HTML
        html_analysis = self.analyze_html_changes(base_text, test_text)
        result['indicators']['html_analysis'] = html_analysis
        
        # Detección especial para boolean-blind (comparar TRUE vs FALSE)
        if payload_type == 'boolean_blind' or test_response.get('is_boolean_test'):
            # Si tenemos información de tipo boolean (TRUE/FALSE), usarla
            boolean_type = test_response.get('boolean_type')
            if boolean_type:
                # Guardar para comparación posterior
                result['boolean_type'] = boolean_type
                result['indicators']['boolean_test'] = True
        
        # Detección de cambios significativos (MUY sensible)
        if html_analysis['significant_change']:
            # Para boolean-blind o básicos con cambios significativos
            if payload_type in ['boolean_blind', 'basic']:
                # MUY sensible - cualquier cambio significativo
                if html_analysis['similarity'] < 0.95:  # Muy sensible
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'boolean_blind' if payload_type == 'boolean_blind' else 'basic'
                    result['confidence'] = 'high' if html_analysis['similarity'] < 0.80 else 'medium'
                    result['evidence'].append(f"Significant HTML structure changes detected (similarity: {html_analysis['similarity']:.2f})")
        
        # 4. Detección basada en longitud (MUY sensible)
        length_diff = abs(test_length - base_length)
        if base_length > 0:
            length_diff_ratio = length_diff / base_length
            # Cualquier cambio de más del 5% es sospechoso
            if length_diff_ratio > 0.05 or length_diff > 50:
                result['indicators']['length_based'] = True
                if not result['vulnerable']:
                    # Si la diferencia es significativa, considerar vulnerable
                    if length_diff > 100 or length_diff_ratio > 0.10:
                        result['vulnerable'] = True
                        result['vulnerability_type'] = 'basic' if payload_type == 'basic' else 'boolean_blind'
                        result['confidence'] = 'high' if length_diff > 200 else 'medium'
                        result['evidence'].append(f"Significant length difference: {length_diff} bytes ({length_diff_ratio:.1%} change)")
                    else:
                        result['confidence'] = 'medium'
                        result['evidence'].append(f"Length difference detected: {length_diff} bytes ({length_diff_ratio:.1%} change)")
        
        # 5. Detección UNION-based (MUY sensible)
        if payload_type == 'union':
            # Cualquier cambio con payload UNION es sospechoso
            if html_analysis['length_diff'] > 20:  # Muy sensible - cualquier cambio
                result['indicators']['union_possible'] = True
                # Verificar si el payload UNION está en la respuesta (indicador fuerte)
                test_lower = test_text.lower()
                if 'union' in test_lower or 'select' in test_lower or 'from' in test_lower:
                    # Si aparece UNION, SELECT o FROM en la respuesta, es muy probable
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'union'
                    result['confidence'] = 'high'
                    result['evidence'].append("UNION/SELECT/FROM keywords found in response")
                elif html_analysis['length_diff'] > 50 or html_analysis['similarity'] < 0.90:
                    # Cambio significativo = probable UNION exitoso
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'union'
                    result['confidence'] = 'high' if html_analysis['length_diff'] > 100 else 'medium'
                    result['evidence'].append(f"UNION-based injection detected (length diff: {html_analysis['length_diff']} bytes, similarity: {html_analysis['similarity']:.2f})")
                elif html_analysis['length_diff'] > 20:
                    # Cualquier cambio con UNION es sospechoso
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'union'
                    result['confidence'] = 'medium'
                    result['evidence'].append(f"Possible UNION-based injection (length diff: {html_analysis['length_diff']} bytes)")
        
        # 6. Detección de payloads básicos que alteran la lógica (MUY sensible)
        if payload_type == 'basic' and not result['vulnerable']:
            # Verificar si el payload básico causó cambios en el comportamiento
            # Por ejemplo, si cambió el status code o la respuesta es muy diferente
            if test_status != base_response.get('status_code', 200):
                result['vulnerable'] = True
                result['vulnerability_type'] = 'basic'
                result['confidence'] = 'high' if test_status in [200, 302, 301] else 'medium'
                result['evidence'].append(f"Status code changed: {base_response.get('status_code', 200)} -> {test_status}")
            elif html_analysis['similarity'] < 0.90 or html_analysis['length_diff'] > 30:
                # Cualquier cambio significativo con payload básico
                result['vulnerable'] = True
                result['vulnerability_type'] = 'basic'
                result['confidence'] = 'high' if html_analysis['similarity'] < 0.80 else 'medium'
                result['evidence'].append(f"Basic SQL injection detected (similarity: {html_analysis['similarity']:.2f}, length diff: {html_analysis['length_diff']} bytes)")
        
        # 6b. Detección adicional: palabras clave de éxito en respuestas
        success_keywords = ['login exitoso', 'bienvenido', 'welcome', 'dashboard', 'admin', 'empleado', 'usuario', 'password', 'email']
        test_lower = test_text.lower()
        base_lower = base_text.lower()
        for keyword in success_keywords:
            if keyword in test_lower and keyword not in base_lower:
                # Nueva palabra clave apareció = posible inyección exitosa
                if not result['vulnerable']:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'basic'
                    result['confidence'] = 'high'
                result['evidence'].append(f"Success keyword '{keyword}' appeared in response")
                break
        
        # 7. Extraer query filtrada si está en la respuesta
        filtered_query = self._extract_filtered_query(test_text)
        if filtered_query:
            result['indicators']['filtered_query'] = filtered_query
            if not result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'error_based'
                result['confidence'] = 'high'
            result['evidence'].append(f"SQL query detected in response")
        
        # 8. Detección adicional: cambios en códigos de estado
        base_status = base_response.get('status_code', 200)
        if test_status != base_status:
            # Cualquier cambio en status code es sospechoso
            if test_status in [200, 302, 301, 403]:
                # Cambio a éxito o redirección = posible bypass
                if not result['vulnerable']:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'basic'
                    result['confidence'] = 'high'
                result['evidence'].append(f"Status code changed to success/redirect: {base_status} -> {test_status}")
            elif test_status == 500:
                # Error 500 puede indicar SQLi
                if not result['vulnerable']:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'error_based'
                    result['confidence'] = 'medium'
                result['evidence'].append("Server error (500) indicates possible SQL injection")
        
        # 9. Detección por contenido: buscar datos sensibles en respuesta
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\']?([^"\']+)',
            r'admin["\']?\s*[:=]\s*["\']?([^"\']+)',
            r'email["\']?\s*[:=]\s*["\']?([^"\']+)',
        ]
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, test_text, re.IGNORECASE)
            if matches and not re.search(pattern, base_text, re.IGNORECASE):
                # Datos sensibles aparecieron = posible extracción exitosa
                if not result['vulnerable']:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'union' if payload_type == 'union' else 'error_based'
                    result['confidence'] = 'high'
                result['evidence'].append(f"Sensitive data pattern detected in response")
                break
        
        # 10. Detección final: si hay CUALQUIER cambio significativo con payload SQL, marcar como sospechoso
        if not result['vulnerable'] and payload_type in ['basic', 'boolean_blind', 'union']:
            if html_analysis['length_diff'] > 10 or html_analysis['similarity'] < 0.98:
                # Cualquier cambio con payload SQL es sospechoso - MARCADO COMO VULNERABLE
                result['vulnerable'] = True
                result['vulnerability_type'] = payload_type
                result['confidence'] = 'medium'
                result['evidence'].append(f"Response changed with SQL payload (diff: {html_analysis['length_diff']} bytes, similarity: {html_analysis['similarity']:.2f})")
        
        # 11. Detección ultra-agresiva: cualquier diferencia con payload SQL
        if not result['vulnerable']:
            # Si hay CUALQUIER diferencia en longitud o contenido con un payload SQL, es sospechoso
            if test_length != base_length or test_status != base_status:
                # Marcar como vulnerable si hay cualquier cambio
                if payload_type in ['union', 'basic', 'boolean_blind', 'error_based']:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = payload_type
                    result['confidence'] = 'high' if abs(test_length - base_length) > 50 else 'medium'
                    result['evidence'].append(f"Response differs from base (length: {test_length} vs {base_length}, status: {test_status} vs {base_status})")
        
        # 12. Detección final: si el payload contiene SQL y hay CUALQUIER cambio, marcar
        if not result['vulnerable']:
            sql_keywords = ['union', 'select', 'or', 'and', '--', '/*', "'", '"']
            payload_lower = payload.lower()
            has_sql_keyword = any(keyword in payload_lower for keyword in sql_keywords)
            
            if has_sql_keyword and (test_length != base_length or test_status != base_status or html_analysis['similarity'] < 0.99):
                # Cualquier cambio con payload que contiene SQL = vulnerable
                result['vulnerable'] = True
                result['vulnerability_type'] = payload_type if payload_type != 'unknown' else 'basic'
                result['confidence'] = 'medium'
                result['evidence'].append(f"SQL payload caused response change (length diff: {abs(test_length - base_length)}, similarity: {html_analysis['similarity']:.2%})")
        
        return result
    
    def _extract_filtered_query(self, response_text: str) -> Optional[str]:
        """
        Intenta extraer la query SQL filtrada del servidor si aparece en la respuesta
        """
        # Patrones comunes donde las apps muestran queries filtradas
        patterns = [
            r"SELECT.*FROM.*WHERE",
            r"INSERT.*INTO.*VALUES",
            r"UPDATE.*SET.*WHERE",
            r"DELETE.*FROM.*WHERE"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:200]  # Limitar longitud
        
        return None
    
    def get_vulnerability_description(self, vuln_type: str) -> str:
        """Retorna descripción del tipo de vulnerabilidad"""
        descriptions = {
            'error_based': 'Error-based SQL Injection: El servidor revela información de error SQL',
            'time_based': 'Time-based Blind SQL Injection: El servidor responde con retrasos controlados',
            'boolean_blind': 'Boolean-based Blind SQL Injection: El servidor responde diferente según condiciones booleanas',
            'union': 'UNION-based SQL Injection: Permite extraer datos mediante UNION SELECT',
            'basic': 'Basic SQL Injection: Inyección SQL básica que altera la lógica de la consulta'
        }
        return descriptions.get(vuln_type, 'Unknown SQL Injection type')

