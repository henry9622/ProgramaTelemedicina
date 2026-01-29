# ==========================================
# SCRIPT DE MIGRACIÓN - FASE 2
# ==========================================
# Implementa:
# 1. Rol admin_maestro
# 2. Tabla de solicitudes de aprobación
# 3. Actualización de permisos
# ==========================================

import sqlite3
import os
import sys
import shutil
from datetime import datetime

# Agregar el directorio padre al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.seguridad import obtener_timestamp_chile, hashear_password

# Configuración
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'telemedicina.db')
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')


def crear_backup_pre_migracion():
    """Crea backup de seguridad antes de la migración"""
    if not os.path.exists(DB_PATH):
        print("[ERROR] No se encontro la base de datos")
        return False
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_name = f"backup_pre_migracion_fase2_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    shutil.copy2(DB_PATH, backup_path)
    print(f"[OK] Backup creado: {backup_name}")
    return True


def ejecutar_migracion():
    """Ejecuta la migración de Fase 2"""
    
    print("")
    print("=" * 60)
    print("   MIGRACION FASE 2 - JERARQUIA DE ROLES")
    print("=" * 60)
    print("")
    
    # 1. Crear backup
    print("[1] Creando backup de seguridad...")
    if not crear_backup_pre_migracion():
        return False
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # 2. Crear tabla de solicitudes de aprobación
        print("")
        print("[2] Creando tabla de solicitudes de aprobacion...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS solicitudes_aprobacion (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo_accion TEXT NOT NULL,
                entidad_tipo TEXT NOT NULL,
                entidad_id TEXT NOT NULL,
                datos_originales TEXT,
                datos_nuevos TEXT,
                solicitante_id INTEGER NOT NULL,
                solicitante_nombre TEXT NOT NULL,
                solicitante_rol TEXT NOT NULL,
                justificacion TEXT,
                estado TEXT DEFAULT 'pendiente',
                aprobador_id INTEGER,
                aprobador_nombre TEXT,
                fecha_solicitud TEXT NOT NULL,
                fecha_resolucion TEXT,
                motivo_resolucion TEXT,
                FOREIGN KEY (solicitante_id) REFERENCES usuarios(id),
                FOREIGN KEY (aprobador_id) REFERENCES usuarios(id)
            )
        ''')
        print("   [OK] Tabla 'solicitudes_aprobacion' creada")
        
        # 3. Promover admin principal a admin_maestro
        print("")
        print("[3] Configurando Admin Maestro...")
        
        # Buscar el admin con correo admin@clinica.cl
        admin = cursor.execute(
            "SELECT id, nombre, rol FROM usuarios WHERE correo = 'admin@clinica.cl'"
        ).fetchone()
        
        if admin:
            cursor.execute('''
                UPDATE usuarios 
                SET rol = 'admin_maestro', es_plantilla = 1 
                WHERE correo = 'admin@clinica.cl'
            ''')
            print(f"   [OK] '{admin['nombre']}' promovido a admin_maestro")
        else:
            # Si no existe, verificar si hay algún admin_maestro
            maestro = cursor.execute(
                "SELECT id FROM usuarios WHERE rol = 'admin_maestro'"
            ).fetchone()
            
            if not maestro:
                # Crear admin maestro por defecto
                password_hash = hashear_password('AdminMaestro2026!')
                cursor.execute('''
                    INSERT INTO usuarios 
                    (nombre, rut, correo, rol, password, password_hash, es_plantilla, activo, fecha_creacion)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)
                ''', (
                    'Administrador Maestro',
                    '1-9',
                    'admin.maestro@clinica.cl',
                    'admin_maestro',
                    'AdminMaestro2026!',
                    password_hash,
                    obtener_timestamp_chile()
                ))
                print("   [OK] Admin Maestro creado (admin.maestro@clinica.cl / AdminMaestro2026!)")
        
        # 4. Verificar que hay al menos un admin_maestro
        print("")
        print("[4] Verificando jerarquia de roles...")
        
        maestros = cursor.execute(
            "SELECT COUNT(*) as total FROM usuarios WHERE rol = 'admin_maestro'"
        ).fetchone()['total']
        
        admins = cursor.execute(
            "SELECT COUNT(*) as total FROM usuarios WHERE rol = 'admin'"
        ).fetchone()['total']
        
        print(f"   - Admin Maestro: {maestros}")
        print(f"   - Admin Regular: {admins}")
        
        if maestros == 0:
            print("   [ALERTA] No hay Admin Maestro. Promoviendo primer admin...")
            primer_admin = cursor.execute(
                "SELECT id, nombre FROM usuarios WHERE rol = 'admin' ORDER BY id LIMIT 1"
            ).fetchone()
            
            if primer_admin:
                cursor.execute(
                    "UPDATE usuarios SET rol = 'admin_maestro' WHERE id = ?",
                    (primer_admin['id'],)
                )
                print(f"   [OK] '{primer_admin['nombre']}' promovido a admin_maestro")
        
        # 5. Agregar índices para rendimiento
        print("")
        print("[5] Creando indices de rendimiento...")
        
        indices = [
            ("idx_solicitudes_estado", "solicitudes_aprobacion", "estado"),
            ("idx_solicitudes_solicitante", "solicitudes_aprobacion", "solicitante_id"),
            ("idx_auditoria_fecha", "auditoria", "fecha"),
            ("idx_auditoria_usuario", "auditoria", "usuario_id"),
        ]
        
        for nombre, tabla, columna in indices:
            try:
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {nombre} ON {tabla}({columna})")
                print(f"   [OK] Indice '{nombre}' creado")
            except Exception as e:
                print(f"   [--] Indice '{nombre}': {e}")
        
        # Commit de todos los cambios
        conn.commit()
        
        print("")
        print("=" * 60)
        print("   [OK] MIGRACION FASE 2 COMPLETADA EXITOSAMENTE")
        print("=" * 60)
        print("")
        print("IMPORTANTE:")
        print("  1. Reinicia el servidor Flask")
        print("  2. El usuario admin@clinica.cl ahora es Admin Maestro")
        print("  3. Las acciones sensibles de admins regulares")
        print("     requeriran aprobacion del Admin Maestro")
        print("")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"[ERROR] Error en migracion: {e}")
        print("   Los cambios han sido revertidos.")
        return False
        
    finally:
        conn.close()


if __name__ == '__main__':
    print("")
    print("TELEMEDICINA - Script de Migracion Fase 2")
    print("")
    
    respuesta = input("Desea ejecutar la migracion Fase 2? (s/n): ").strip().lower()
    
    if respuesta == 's':
        ejecutar_migracion()
    else:
        print("Migracion cancelada.")
