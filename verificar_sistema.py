"""
TELEMEDICINA - Script de Verificación Completa
Verifica todas las fases implementadas
"""
import sqlite3
import os
import sys

# Cargar variables de entorno
from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("VERIFICACION COMPLETA DEL SISTEMA TELEMEDICINA")
print("=" * 60)

errores = []
advertencias = []

# ==========================================
# FASE 1: Seguridad Básica
# ==========================================
print("\n[FASE 1] Seguridad Basica")
print("-" * 40)

# Verificar módulo de seguridad
try:
    from utils.seguridad import (
        hashear_password, verificar_password,
        validar_rut_chileno, normalizar_rut,
        obtener_fecha_hora_chile, obtener_timestamp_chile,
        generar_checksum_registro
    )
    print("  [OK] Modulo de seguridad importado")
    
    # Test hash
    test_hash = hashear_password("test123")
    if verificar_password("test123", test_hash):
        print("  [OK] Hashing de passwords funciona")
    else:
        errores.append("Hashing de passwords falla")
        
    # Test RUT
    valido, _, _, _ = validar_rut_chileno("12.345.678-5")
    if valido:
        print("  [OK] Validacion RUT funciona")
    else:
        errores.append("Validacion RUT falla")
        
    # Test timestamp Chile
    ts = obtener_timestamp_chile()
    if ts and "2026" in ts:
        print("  [OK] Zona horaria Chile funciona")
    else:
        advertencias.append("Zona horaria puede tener problemas")
        
except Exception as e:
    errores.append(f"Error en modulo seguridad: {e}")

# Verificar base de datos
conn = sqlite3.connect('telemedicina.db')
conn.row_factory = sqlite3.Row

# Verificar tabla auditoria
cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='auditoria'")
if cursor.fetchone():
    print("  [OK] Tabla 'auditoria' existe")
else:
    errores.append("Tabla 'auditoria' no existe")

# Verificar columna password_hash en usuarios
cursor = conn.execute("PRAGMA table_info(usuarios)")
columnas = [row[1] for row in cursor.fetchall()]
if 'password_hash' in columnas:
    print("  [OK] Columna 'password_hash' existe")
else:
    errores.append("Columna 'password_hash' no existe")

if 'rut' in columnas:
    print("  [OK] Columna 'rut' existe en usuarios")
else:
    advertencias.append("Columna 'rut' no existe en usuarios")

# ==========================================
# FASE 2: Jerarquía de Roles
# ==========================================
print("\n[FASE 2] Jerarquia de Roles")
print("-" * 40)

try:
    from utils.aprobaciones import (
        es_admin_maestro, requiere_aprobacion,
        obtener_solicitudes_pendientes
    )
    print("  [OK] Modulo de aprobaciones importado")
    
    if es_admin_maestro('admin_maestro'):
        print("  [OK] Funcion es_admin_maestro funciona")
    else:
        errores.append("Funcion es_admin_maestro falla")
        
except Exception as e:
    errores.append(f"Error en modulo aprobaciones: {e}")

# Verificar tabla solicitudes_aprobacion
cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='solicitudes_aprobacion'")
if cursor.fetchone():
    print("  [OK] Tabla 'solicitudes_aprobacion' existe")
else:
    errores.append("Tabla 'solicitudes_aprobacion' no existe")

# Verificar admin_maestro
cursor = conn.execute("SELECT COUNT(*) FROM usuarios WHERE rol='admin_maestro'")
count = cursor.fetchone()[0]
if count > 0:
    print(f"  [OK] Existe {count} admin_maestro")
else:
    advertencias.append("No hay admin_maestro creado")

# ==========================================
# FASE 3: Protección CSRF
# ==========================================
print("\n[FASE 3] Proteccion CSRF")
print("-" * 40)

try:
    from flask_wtf.csrf import CSRFProtect
    print("  [OK] Flask-WTF CSRFProtect disponible")
except ImportError:
    errores.append("Flask-WTF no instalado")

# Verificar tokens en templates
templates_dir = 'templates'
templates_con_csrf = 0
templates_totales = 0

for filename in os.listdir(templates_dir):
    if filename.endswith('.html'):
        templates_totales += 1
        filepath = os.path.join(templates_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if 'csrf_token' in content or 'csrf-token' in content:
                    templates_con_csrf += 1
        except:
            pass

print(f"  [INFO] {templates_con_csrf}/{templates_totales} templates con CSRF")
if templates_con_csrf < templates_totales:
    advertencias.append(f"Solo {templates_con_csrf} de {templates_totales} templates tienen CSRF")

# ==========================================
# FASE 4: Variables de Entorno
# ==========================================
print("\n[FASE 4] Variables de Entorno")
print("-" * 40)

# Verificar .env existe
if os.path.exists('.env'):
    print("  [OK] Archivo .env existe")
else:
    errores.append("Archivo .env no existe")

# Verificar .env.example existe
if os.path.exists('.env.example'):
    print("  [OK] Archivo .env.example existe")
else:
    advertencias.append("Archivo .env.example no existe")

# Verificar .gitignore
if os.path.exists('.gitignore'):
    try:
        with open('.gitignore', 'r', encoding='utf-8', errors='ignore') as f:
            if '.env' in f.read():
                print("  [OK] .env esta en .gitignore")
            else:
                advertencias.append(".env NO esta en .gitignore")
    except:
        advertencias.append("No se pudo leer .gitignore")
else:
    advertencias.append("Archivo .gitignore no existe")

# Verificar variables cargadas
secret_key = os.environ.get('SECRET_KEY')
if secret_key and len(secret_key) >= 32:
    print("  [OK] SECRET_KEY configurada correctamente")
else:
    errores.append("SECRET_KEY no configurada o muy corta")

jitsi_secret = os.environ.get('JITSI_APP_SECRET')
if jitsi_secret:
    print("  [OK] JITSI_APP_SECRET configurada")
else:
    advertencias.append("JITSI_APP_SECRET no configurada")

flask_env = os.environ.get('FLASK_ENV', 'development')
print(f"  [INFO] FLASK_ENV = {flask_env}")

conn.close()

# ==========================================
# RESUMEN
# ==========================================
print("\n" + "=" * 60)
print("RESUMEN DE VERIFICACION")
print("=" * 60)

if errores:
    print(f"\n[ERRORES] ({len(errores)})")
    for e in errores:
        print(f"  X {e}")
else:
    print("\n[OK] No se encontraron errores criticos")

if advertencias:
    print(f"\n[ADVERTENCIAS] ({len(advertencias)})")
    for a in advertencias:
        print(f"  ! {a}")
else:
    print("\n[OK] No hay advertencias")

print("\n" + "=" * 60)
if len(errores) == 0:
    print("SISTEMA VERIFICADO CORRECTAMENTE")
    sys.exit(0)
else:
    print("VERIFICACION COMPLETADA CON ERRORES")
    sys.exit(1)
