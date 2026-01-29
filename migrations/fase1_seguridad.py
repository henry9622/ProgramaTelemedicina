# ==========================================
# SCRIPT DE MIGRACIÓN - FASE 1
# ==========================================
# Ejecutar UNA SOLA VEZ para:
# 1. Agregar tabla de auditoría
# 2. Migrar contraseñas a hash
# 3. Agregar columnas de seguridad
# ==========================================

import sqlite3
import os
import sys
import shutil
from datetime import datetime

# Agregar el directorio padre al path para importar utils
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.seguridad import (
    hashear_password, 
    obtener_timestamp_chile,
    TIMEZONE_CHILE
)

# Configuración
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'telemedicina.db')
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')


def crear_backup_pre_migracion():
    """Crea backup de seguridad antes de la migración"""
    if not os.path.exists(DB_PATH):
        print("❌ No se encontró la base de datos")
        return False
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_name = f"backup_pre_migracion_fase1_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    shutil.copy2(DB_PATH, backup_path)
    print(f"✅ Backup creado: {backup_name}")
    return True


def ejecutar_migracion():
    """Ejecuta la migración de Fase 1"""
    
    print("\n" + "="*60)
    print("   MIGRACIÓN FASE 1 - FUNDAMENTOS DE SEGURIDAD")
    print("="*60 + "\n")
    
    # 1. Crear backup
    print("📦 Paso 1: Creando backup de seguridad...")
    if not crear_backup_pre_migracion():
        return False
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # 2. Crear tabla de auditoría
        print("\n📋 Paso 2: Creando tabla de auditoría...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                usuario_nombre TEXT NOT NULL,
                usuario_rol TEXT NOT NULL,
                accion TEXT NOT NULL,
                categoria TEXT NOT NULL CHECK (categoria IN (
                    'autenticacion',
                    'usuarios',
                    'lugares',
                    'consultas',
                    'historial',
                    'respaldos',
                    'sistema',
                    'seguridad'
                )),
                entidad_tipo TEXT,
                entidad_id TEXT,
                datos_antes TEXT,
                datos_despues TEXT,
                ip_origen TEXT,
                user_agent TEXT,
                resultado TEXT NOT NULL CHECK (resultado IN ('exito', 'error', 'denegado', 'pendiente')),
                mensaje TEXT,
                fecha TEXT NOT NULL,
                checksum TEXT NOT NULL
            )
        ''')
        print("   ✅ Tabla 'auditoria' creada")
        
        # 3. Verificar y agregar columna password_hash si no existe
        print("\n🔐 Paso 3: Verificando estructura de usuarios...")
        
        # Obtener columnas actuales
        cursor.execute("PRAGMA table_info(usuarios)")
        columnas = [col['name'] for col in cursor.fetchall()]
        
        if 'password_hash' not in columnas:
            # Agregar columna password_hash
            cursor.execute('ALTER TABLE usuarios ADD COLUMN password_hash TEXT')
            print("   ✅ Columna 'password_hash' agregada")
        else:
            print("   ℹ️  Columna 'password_hash' ya existe")
        
        # 4. Migrar contraseñas existentes
        print("\n🔑 Paso 4: Migrando contraseñas a hash...")
        
        # Obtener usuarios con contraseñas en texto plano
        usuarios = cursor.execute('''
            SELECT id, nombre, correo, password, password_hash 
            FROM usuarios 
            WHERE password IS NOT NULL AND password != ''
        ''').fetchall()
        
        migradas = 0
        for usuario in usuarios:
            # Si ya tiene hash, saltar
            if usuario['password_hash'] and usuario['password_hash'].startswith('pbkdf2:'):
                print(f"   ⏭️  {usuario['correo']} - ya tiene hash")
                continue
            
            # Hashear la contraseña actual
            password_actual = usuario['password']
            password_hash = hashear_password(password_actual)
            
            # Actualizar en BD
            cursor.execute('''
                UPDATE usuarios 
                SET password_hash = ? 
                WHERE id = ?
            ''', (password_hash, usuario['id']))
            
            print(f"   ✅ {usuario['correo']} - contraseña migrada")
            migradas += 1
        
        print(f"\n   📊 Total migradas: {migradas} de {len(usuarios)}")
        
        # 5. Agregar columnas adicionales de seguridad si no existen
        print("\n🛡️  Paso 5: Agregando campos de seguridad...")
        
        campos_nuevos = [
            ('es_plantilla', 'INTEGER DEFAULT 0'),
            ('activo', 'INTEGER DEFAULT 1'),
            ('ultimo_acceso', 'TEXT'),
            ('intentos_fallidos', 'INTEGER DEFAULT 0'),
            ('bloqueado_hasta', 'TEXT'),
            ('fecha_creacion', 'TEXT'),
        ]
        
        for campo, tipo in campos_nuevos:
            if campo not in columnas:
                try:
                    cursor.execute(f'ALTER TABLE usuarios ADD COLUMN {campo} {tipo}')
                    print(f"   ✅ Campo '{campo}' agregado")
                except sqlite3.OperationalError:
                    print(f"   ⏭️  Campo '{campo}' ya existe")
            else:
                print(f"   ⏭️  Campo '{campo}' ya existe")
        
        # 6. Marcar admin maestro inicial
        print("\n👑 Paso 6: Configurando Admin Maestro...")
        cursor.execute('''
            UPDATE usuarios 
            SET es_plantilla = 1 
            WHERE correo = 'admin@clinica.cl'
        ''')
        if cursor.rowcount > 0:
            print("   ✅ Admin maestro marcado como plantilla protegida")
        
        # 7. Agregar campos a tabla lugares si no existen
        print("\n📍 Paso 7: Actualizando tabla lugares...")
        cursor.execute("PRAGMA table_info(lugares)")
        columnas_lugares = [col['name'] for col in cursor.fetchall()]
        
        campos_lugares = [
            ('es_plantilla', 'INTEGER DEFAULT 0'),
            ('activo', 'INTEGER DEFAULT 1'),
            ('codigo_deis', 'TEXT'),
            ('fecha_creacion', 'TEXT'),
        ]
        
        for campo, tipo in campos_lugares:
            if campo not in columnas_lugares:
                try:
                    cursor.execute(f'ALTER TABLE lugares ADD COLUMN {campo} {tipo}')
                    print(f"   ✅ Campo '{campo}' agregado a lugares")
                except sqlite3.OperationalError:
                    print(f"   ⏭️  Campo '{campo}' ya existe en lugares")
        
        # 8. Crear tabla respaldos_metadata
        print("\n💾 Paso 8: Creando tabla de metadatos de respaldos...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS respaldos_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre_archivo TEXT UNIQUE NOT NULL,
                tipo TEXT NOT NULL CHECK (tipo IN ('auto', 'manual', 'inicial', 'pre_migracion')),
                tamaño_bytes INTEGER NOT NULL,
                checksum_sha256 TEXT,
                creado_por INTEGER,
                fecha_creacion TEXT NOT NULL,
                eliminado INTEGER DEFAULT 0,
                eliminado_por INTEGER,
                fecha_eliminacion TEXT,
                FOREIGN KEY (creado_por) REFERENCES usuarios(id),
                FOREIGN KEY (eliminado_por) REFERENCES usuarios(id)
            )
        ''')
        print("   ✅ Tabla 'respaldos_metadata' creada")
        
        # Commit de todos los cambios
        conn.commit()
        
        print("\n" + "="*60)
        print("   ✅ MIGRACIÓN FASE 1 COMPLETADA EXITOSAMENTE")
        print("="*60)
        print("\n⚠️  IMPORTANTE:")
        print("   1. Reinicia el servidor Flask para aplicar cambios")
        print("   2. Las contraseñas antiguas siguen funcionando")
        print("   3. El sistema ahora usa password_hash para login")
        print("\n")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ ERROR en migración: {e}")
        print("   Los cambios han sido revertidos.")
        return False
        
    finally:
        conn.close()


if __name__ == '__main__':
    print("\n" + "🏥 TELEMEDICINA - Script de Migración" + "\n")
    
    respuesta = input("¿Desea ejecutar la migración Fase 1? (s/n): ").strip().lower()
    
    if respuesta == 's':
        ejecutar_migracion()
    else:
        print("Migración cancelada.")
