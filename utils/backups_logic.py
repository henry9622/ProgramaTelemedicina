import os
import shutil
import glob
import time
import threading
from datetime import datetime
from .database import DB_PATH

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
BACKUP_HOUR = int(os.environ.get('BACKUP_HOUR', 16))
BACKUP_MINUTE = int(os.environ.get('BACKUP_MINUTE', 59))
MAX_BACKUPS = int(os.environ.get('MAX_BACKUPS', 30))

# Asegurar que la carpeta de respaldos existe
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

def crear_respaldo(manual=False):
    """Crea un respaldo de la base de datos"""
    if not os.path.exists(DB_PATH):
        return None
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    tipo = 'manual' if manual else 'auto'
    backup_name = f"backup_{tipo}_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    try:
        shutil.copy2(DB_PATH, backup_path)
        limpiar_respaldos_antiguos()
        return backup_name
    except Exception as e:
        print(f"Error creando respaldo: {e}")
        return None

def limpiar_respaldos_antiguos():
    """Mantiene solo los últimos MAX_BACKUPS respaldos MANUALES"""
    backups_manuales = glob.glob(os.path.join(BACKUP_DIR, 'backup_manual_*.db'))
    backups_manuales.sort(key=os.path.getmtime, reverse=True)
    
    for backup in backups_manuales[MAX_BACKUPS:]:
        try:
            os.remove(backup)
        except Exception as e:
            print(f"Error eliminando respaldo antiguo: {e}")

def listar_respaldos():
    """Lista todos los respaldos disponibles"""
    backups = glob.glob(os.path.join(BACKUP_DIR, 'backup_*.db'))
    backups.sort(key=os.path.getmtime, reverse=True)
    
    result = []
    for backup in backups:
        name = os.path.basename(backup)
        size = os.path.getsize(backup)
        mtime = datetime.fromtimestamp(os.path.getmtime(backup))
        
        es_automatico = 'backup_auto_' in name
        
        result.append({
            'nombre': name,
            'tamaño': f"{size / 1024:.1f} KB",
            'fecha': mtime.strftime('%Y-%m-%d %H:%M:%S'),
            'tipo': 'auto' if es_automatico else 'manual',
            'protegido': es_automatico
        })
    return result

def respaldo_programado():
    """Hilo para respaldo automático"""
    while True:
        ahora = datetime.now()
        siguiente = ahora.replace(hour=BACKUP_HOUR, minute=BACKUP_MINUTE, second=0, microsecond=0)
        
        if ahora >= siguiente:
            siguiente = siguiente.replace(day=siguiente.day + 1)
        
        segundos_espera = (siguiente - ahora).total_seconds()
        print(f"[BACKUP] Próximo respaldo programado: {siguiente.strftime('%Y-%m-%d %H:%M')}")
        
        time.sleep(segundos_espera)
        
        nombre = crear_respaldo(manual=False)
        if nombre:
            print(f"[BACKUP] Respaldo automático creado: {nombre}")

def iniciar_hilo_respaldos():
    if not os.environ.get('WERKZEUG_RUN_MAIN'):
        backup_thread = threading.Thread(target=respaldo_programado, daemon=True)
        backup_thread.start()
        print(f"[BACKUP] Respaldo programado diario a las {BACKUP_HOUR}:{BACKUP_MINUTE:02d}")
