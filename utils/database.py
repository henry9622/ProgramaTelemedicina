import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), os.environ.get('DB_PATH', 'telemedicina.db'))

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Tabla de Lugares (Postas/Centros)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lugares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_posta TEXT NOT NULL,
            direccion TEXT NOT NULL,
            fecha_creacion TIMESTAMP,
            activo INTEGER DEFAULT 1,
            es_plantilla INTEGER DEFAULT 0
        )
    ''')

    # 2. Tabla de Usuarios (Admin, Medico, TENS)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            rut TEXT UNIQUE NOT NULL,
            correo TEXT UNIQUE NOT NULL,
            rol TEXT NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT,
            fecha_creacion TIMESTAMP,
            ultimo_acceso TIMESTAMP,
            intentos_fallidos INTEGER DEFAULT 0,
            bloqueado_hasta TIMESTAMP,
            activo INTEGER DEFAULT 1,
            es_plantilla INTEGER DEFAULT 0
        )
    ''')

    # 3. Tabla de Consultas (Lista de espera)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS consultas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cip TEXT NOT NULL,
            rut_paciente_hash TEXT NOT NULL,
            nombre_medico TEXT DEFAULT 'Pendiente',
            lugar_id INTEGER NOT NULL,
            tens_nombre TEXT NOT NULL,
            estado TEXT DEFAULT 'esperando',
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (lugar_id) REFERENCES lugares (id)
        )
    ''')
    
    # 4. Tabla de Historial de Consultas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historial_consultas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_consulta TEXT NOT NULL UNIQUE,
            token_seguridad TEXT NOT NULL,
            cip TEXT NOT NULL,
            rut_paciente_cifrado TEXT NOT NULL,
            rut_paciente_hash TEXT NOT NULL,
            nombre_medico TEXT NOT NULL,
            tens_nombre TEXT NOT NULL,
            nombre_posta TEXT NOT NULL,
            fecha_inicio TIMESTAMP,
            fecha_fin TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 5. Tabla de Mapeo de Pacientes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mapeo_pacientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cip TEXT UNIQUE NOT NULL,
            rut_cifrado TEXT NOT NULL,
            rut_hash TEXT NOT NULL,
            rut_enmascarado TEXT NOT NULL,
            fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            creado_por_id INTEGER,
            FOREIGN KEY (creado_por_id) REFERENCES usuarios (id)
        )
    ''')

    # 6. Tabla de Auditoría
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            usuario_nombre TEXT,
            usuario_rol TEXT,
            accion TEXT NOT NULL,
            categoria TEXT NOT NULL,
            entidad_tipo TEXT,
            entidad_id TEXT,
            datos_antes TEXT,
            datos_despues TEXT,
            ip_origen TEXT,
            user_agent TEXT,
            resultado TEXT,
            mensaje TEXT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            checksum TEXT
        )
    ''')

    # 7. Tabla de Solicitudes de Aprobación
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solicitudes_aprobacion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo_accion TEXT NOT NULL,
            entidad_tipo TEXT NOT NULL,
            entidad_id TEXT NOT NULL,
            solicitante_id INTEGER NOT NULL,
            solicitante_nombre TEXT NOT NULL,
            solicitante_rol TEXT NOT NULL,
            datos_originales TEXT,
            datos_nuevos TEXT,
            justificacion TEXT,
            estado TEXT DEFAULT 'pendiente',
            aprobador_id INTEGER,
            aprobador_nombre TEXT,
            motivo_rechazo TEXT,
            fecha_solicitud TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            fecha_resolucion TIMESTAMP,
            FOREIGN KEY (solicitante_id) REFERENCES usuarios (id)
        )
    ''')

    # Admin maestro inicial
    cursor.execute("SELECT * FROM usuarios WHERE correo='admin@clinica.cl'")
    if not cursor.fetchone():
        cursor.execute('''
            INSERT INTO usuarios (nombre, rut, correo, rol, password) 
            VALUES (?, ?, ?, ?, ?)
        ''', ('Administrador Maestro', '1-1', 'admin@clinica.cl', 'admin_maestro', 'admin123'))
    
    conn.commit()
    conn.close()
