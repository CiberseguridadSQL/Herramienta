"""
Módulo de Detección de Vulnerabilidades SQL Injection
Implementa criterios formales OWASP para detección SQLi
"""

import re
import time
from typing import Dict, List, Optional, Tuple
import difflib

class SQLInjectionDetector:
    """Detector de vulnerabilidades SQL Injection basado en criterios OWASP"""
    
    # Patrones de error SQL según OWASP (Lista completa)
    SQL_ERROR_PATTERNS = [
        r"syntax error", r"SQLSTATE", r'near "', r"unclosed quotation mark",
        r"You have an error in your SQL syntax", r"OperationalError", r"SQLiteException",
        r"MySQLSyntaxErrorException", r"PostgreSQL.*ERROR", r"Warning.*\Wmysql_",
        r"valid MySQL result", r"MySqlClient\.", r"PostgreSQL query failed",
        r"Warning.*\Wpg_", r"Warning.*\Woci_", r"Warning.*\Wodbc_",
        r"Warning.*\Wmssql_", r"Warning.*\Wsqlsrv_", r"Warning.*\Wfbsql_",
        r"Warning.*\Wibase_", r"Warning.*\Wifx_", r"Exception.*\Worg\.hibernate",
        r"Exception.*\Worg\.springframework", r"java\.sql\.SQLException",
        r"java\.sql\.SQLSyntaxErrorException", r"com\.mysql\.jdbc\.exceptions",
        r"com\.microsoft\.sqlserver\.jdbc", r"org\.postgresql\.util\.PSQLException",
        r"org\.h2\.jdbc\.JdbcSQLException", r"SQLException", r"SQLSyntaxErrorException",
        r"ORA-\d{5}", r"PLS-\d{5}", r"SQL error", r"SQL.*error", r"SQL.*Exception",
        r"Query failed", r"SQL command not properly ended", r"quoted string not properly terminated",
        r"invalid character", r"invalid number", r"column.*does not exist",
        r"table.*does not exist", r"unknown column", r"unknown table",
        r"table.*already exists", r"column.*already exists"
    ]
    
    TIME_BASED_THRESHOLD = 5.0
    
    def __init__(self):
        self.error_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_ERROR_PATTERNS]
    
    def detect_sql_errors(self, response_text: str) -> List[Dict]:
        """Detecta errores SQL y extrae el contexto (snippet) para el reporte."""
        found_errors = []
        for pattern in self.error_patterns:
            match = pattern.search(response_text)
            if match:
                # Extraer contexto: 100 caracteres antes y después 
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 100)
                snippet = response_text[start:end]
                snippet = " ".join(snippet.split()) # Limpieza básica
                
                found_errors.append({
                    'pattern': pattern.pattern,
                    'snippet': snippet
                })
        return found_errors
    
    def detect_time_based_sqli(self, response_time: float, payload_type: str) -> bool:
        if payload_type != 'time_based':
            return False
        return response_time >= self.TIME_BASED_THRESHOLD
    
    def analyze_html_changes(self, base_response: str, test_response: str) -> Dict:
        """Analiza cambios en el HTML con umbrales anti-ruido."""
        if not base_response or not test_response:
            return {
                'similarity': 0.0, 'length_diff': abs(len(test_response) - len(base_response)),
                'significant_change': False, 'dom_changes': []
            }
        
        similarity = difflib.SequenceMatcher(None, base_response, test_response).ratio()
        length_diff = abs(len(test_response) - len(base_response))
        
        # Solo consideramos cambio significativo si:
        # 1. La similitud cae por debajo del 95%
        # 2. Y ADEMÁS la diferencia en bytes es mayor a 50 (ignora cambios de hora/tokens pequeños)
        significant_change = similarity < 0.95 and length_diff > 50
        
        return {
            'similarity': similarity,
            'length_diff': length_diff,
            'significant_change': significant_change
        }
    
    def detect_boolean_blind_sqli(self, base_response: str, true_response: str, false_response: str) -> bool:
        """Detecta SQLi boolean-blind."""
        if not base_response or not true_response or not false_response:
            return False
            
        true_false_similarity = difflib.SequenceMatcher(None, true_response, false_response).ratio()
        
        # Si TRUE y FALSE son muy diferentes (< 0.9), es vulnerable.
        if true_false_similarity < 0.9:
            return True
        return False
    
    def detect_length_based_sqli(self, base_length: int, test_length: int, threshold: float = 0.15) -> bool:
        """Detecta diferencias de longitud significativas."""
        if base_length == 0: return False
        
        diff = abs(test_length - base_length)
        diff_ratio = diff / base_length
        
        # Debe cumplir el ratio Y ser una diferencia de al menos 50 bytes
        if diff_ratio >= threshold and diff > 50:
            return True
        return False

    def evaluate_payload(self, payload_info: Dict, base_response: Dict, test_response: Dict) -> Dict:
        """Evalúa un payload completo."""
        payload = payload_info['payload']
        payload_type = payload_info['type']
        
        test_text = test_response.get('text', '')
        test_time = test_response.get('time', 0.0)
        test_status = test_response.get('status_code', 0)
        test_length = len(test_text)
        
        base_text = base_response.get('text', '')
        base_length = len(base_text)
        base_status = base_response.get('status_code', 200)
        
        result = {
            'payload': payload, 'payload_type': payload_type,
            'status_code': test_status, 'response_time': test_time,
            'response_length': test_length, 'base_length': base_length,
            'vulnerable': False, 'vulnerability_type': None,
            'confidence': 'low', 'evidence': [], 'indicators': {}
        }
        
        # 1. ERRORES SQL (Prioridad Máxima)
        sql_errors = self.detect_sql_errors(test_text)
        if sql_errors:
            result['vulnerable'] = True
            result['vulnerability_type'] = 'error_based'
            result['confidence'] = 'high'
            patterns_found = [e['pattern'] for e in sql_errors]
            result['evidence'].append(f"SQL errors detected: {', '.join(patterns_found[:3])}")
            
            # Guardamos el snippet del error como preview principal
            result['indicators']['error_snippet'] = sql_errors[0]['snippet']
            # Esto asegura que el reporte muestre el error, no el header
            result['indicators']['response_preview'] = sql_errors[0]['snippet'] 
        
        # 2. TIME BASED
        if self.detect_time_based_sqli(test_time, payload_type):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'time_based'
            result['confidence'] = 'high'
            result['evidence'].append(f"Time-based delay detected: {test_time:.2f}s")
        
        # 3. ANÁLISIS HTML
        html_analysis = self.analyze_html_changes(base_text, test_text)
        result['indicators']['html_analysis'] = html_analysis
        
        # 4. BOOLEAN BLIND (Diferencias significativas)
        if not result['vulnerable'] and (payload_type == 'boolean_blind' or test_response.get('is_boolean_test')):
             # Filtro anti-ruido: Exigimos al menos 10% de diferencia estructural
             if html_analysis['similarity'] < 0.90: 
                result['vulnerable'] = True
                result['vulnerability_type'] = 'boolean_blind'
                result['confidence'] = 'medium'
                result['evidence'].append(f"Significant structure change (similarity: {html_analysis['similarity']:.2f})")

        # 5. LENGTH BASED (Con filtro anti-ruido)
        if self.detect_length_based_sqli(base_length, test_length, threshold=0.15):
             if not result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'basic'
                result['confidence'] = 'medium'
                result['evidence'].append(f"Significant length difference ({abs(test_length - base_length)} bytes)")

        # 6. STATUS CODE CHANGE (Ignoramos 500 aquí, suelen ser error_based)
        if test_status != base_status and test_status < 500: 
             if not result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'basic'
                result['confidence'] = 'medium'
                result['evidence'].append(f"Status code changed: {base_status} -> {test_status}")

        # 7. EXTRACCIÓN DE QUERY
        filtered_query = self._extract_filtered_query(test_text)
        if filtered_query:
            result['indicators']['filtered_query'] = filtered_query
            if not result['vulnerable']: # Si no se había detectado antes
                result['vulnerable'] = True
                result['vulnerability_type'] = 'error_based'
                result['confidence'] = 'high'
            result['evidence'].append("SQL query leaked in response")
            result['indicators']['response_preview'] = filtered_query

        # 8. PREVIEW INTELIGENTE FINAL
        # Si es vulnerable y aún no hemos definido qué mostrar (no es error explícito ni query filtrada)
        if result['vulnerable'] and 'response_preview' not in result['indicators']:
            preview = self._get_smart_preview(base_text, test_text)
            # Limpiamos para HTML
            preview = preview.replace('<', '&lt;').replace('>', '&gt;')
            result['indicators']['response_preview'] = preview

        return result
    
    def _extract_filtered_query(self, response_text: str) -> Optional[str]:
        # Capturamos más contexto alrededor de las consultas (hasta 800 caracteres)
        patterns = [
            r"(SELECT[\s\S]{0,800}FROM[\s\S]{0,800}WHERE[\s\S]{0,800})",
            r"(INSERT[\s\S]{0,800}INTO[\s\S]{0,800}VALUES[\s\S]{0,800})",
            r"(UPDATE[\s\S]{0,800}SET[\s\S]{0,800}WHERE[\s\S]{0,800})",
        ]

        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                # Limitar la longitud retornada para no inundar el reporte
                return match.group(0)[:800]

        return None

    def get_vulnerability_description(self, vuln_type: str) -> str:
        descriptions = {
            'error_based': 'Error-based SQL Injection: El servidor revela información de error SQL',
            'time_based': 'Time-based Blind SQL Injection: El servidor responde con retrasos controlados',
            'boolean_blind': 'Boolean-based Blind SQL Injection: El servidor responde diferente según condiciones booleanas',
            'union': 'UNION-based SQL Injection: Permite extraer datos mediante UNION SELECT',
            'basic': 'Basic SQL Injection: Inyección SQL básica que altera la lógica de la consulta'
        }
        return descriptions.get(vuln_type, 'Unknown SQL Injection type')

    def _get_smart_preview(self, base_text: str, test_text: str, window: int = 200) -> str:
        """
        Encuentra EXACTAMENTE dónde cambia el HTML y devuelve esa zona.
        """
        if not base_text or not test_text:
            return test_text[:300]

        # Encontrar el índice del primer carácter diferente
        limit = min(len(base_text), len(test_text))
        diff_index = -1
        
        for i in range(limit):
            if base_text[i] != test_text[i]:
                diff_index = i
                break
        
        if diff_index == -1:
            if len(test_text) != len(base_text):
                diff_index = limit
            else:
                return test_text[:300] # Son idénticas

        # Calcular recorte alrededor de la diferencia
        start = max(0, diff_index - window)
        end = min(len(test_text), diff_index + window)
        
        preview = test_text[start:end]
        
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(test_text) else ""
        
        return f"{prefix}{preview}{suffix}"