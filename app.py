import time
import jwt
import sqlite3
import os
import hashlib
import shutil
from datetime import datetime
import threading
import glob
import io
import csv
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file

# ==========================================
# CARGA DE VARIABLES DE ENTORNO (Fase 4)
# ==========================================
from dotenv import load_dotenv
load_dotenv()  # Carga variables desde .env

# ==========================================
# MÓDULO DE SEGURIDAD (Fase 1)
# ==========================================
from utils.seguridad import (
    TIMEZONE_CHILE, obtener_fecha_hora_chile, obtener_timestamp_chile,
    formatear_fecha_display, hashear_password, verificar_password,
    validar_politica_password, validar_rut_chileno, normalizar_rut,
    enmascarar_rut, hashear_rut, cifrar_rut, descifrar_rut,
    generar_cip, validar_cip
)

# ==========================================
# MÓDULO DE APROBACIONES (Fase 2)
# ==========================================
from utils.aprobaciones import (
    requiere_aprobacion, es_admin_maestro, puede_aprobar,
    crear_solicitud, obtener_solicitudes_pendientes,
    obtener_solicitudes_usuario, contar_solicitudes_pendientes,
    aprobar_solicitud, rechazar_solicitud
)

# ==========================================
# MÓDULOS DE DATOS Y RESPALDOS (Refactorizado)
# ==========================================
from utils.database import get_db_connection, init_db, DB_PATH
from utils.backups_logic import (
    crear_respaldo, listar_respaldos, iniciar_hilo_respaldos, BACKUP_DIR
)
from utils.auditoria import registrar_auditoria, obtener_auditoria

# ==========================================
# CONFIGURACIÓN DE LA APLICACIÓN
# ==========================================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'clave_por_defecto_solo_desarrollo')

# Verificar seguridad en producción
if os.environ.get('FLASK_ENV') == 'production' and app.secret_key == 'clave_por_defecto_solo_desarrollo':
    raise ValueError("ERROR: SECRET_KEY no configurada para produccion.")

# Inicializar base de datos
init_db()

# ==========================================
# PROTECCIÓN CSRF (Fase 3)
# ==========================================
from flask_wtf.csrf import CSRFProtect, CSRFError
csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Error de seguridad: Token CSRF invalido. Por favor, recarga la pagina.')
    return redirect(url_for('index'))

# ==========================================
# CONFIGURACIÓN DEL SERVIDOR DE TELEMEDICINA
# ==========================================
JITSI_HOST = os.environ.get('JITSI_HOST', '100.102.175.23:8443')
JITSI_APP_ID = os.environ.get('JITSI_APP_ID', 'telemedicina_utalca')
JITSI_APP_SECRET = os.environ.get('JITSI_APP_SECRET', 'ClaveSecretaHenry2026')


# ==========================================
# SEGURIDAD JITSI (JWT)
# ==========================================

def generar_token_jitsi(nombre_usuario, sala):
    ahora = int(time.time())
    payload = {
        "iss": JITSI_APP_ID, 
        "aud": JITSI_APP_ID, 
        "sub": JITSI_HOST, 
        "room": sala,
        "iat": ahora, 
        "exp": ahora + 3600,
        "context": {"user": {"name": nombre_usuario}}
    }
    return jwt.encode(payload, JITSI_APP_SECRET, algorithm="HS256")

# ==========================================
# RUTAS DE LOGIN Y DASHBOARDS
# ==========================================

@app.route('/')
def index():
    if 'rol' in session:
        rol = session['rol']
        # admin_maestro usa el mismo dashboard que admin
        if rol == 'admin_maestro':
            return redirect(url_for('dashboard_admin'))
        return redirect(url_for(f"dashboard_{rol}"))
    return render_template('login_unico.html')

@app.route('/login', methods=['POST'])
def login():
    correo = request.form.get('correo', '').strip().lower()
    password = request.form.get('password', '')
    ip_origen = request.remote_addr
    
    conn = get_db_connection()
    
    # Buscar usuario por correo
    user = conn.execute('SELECT * FROM usuarios WHERE LOWER(correo) = ?', (correo,)).fetchone()
    
    if not user:
        # Registrar intento fallido (usuario no existe)
        registrar_auditoria(
            conn=conn,
            usuario_id=None,
            usuario_nombre=correo,
            usuario_rol='desconocido',
            accion='login_fallido',
            categoria='autenticacion',
            resultado='error',
            mensaje='Usuario no encontrado',
            ip_origen=ip_origen
        )
        conn.close()
        flash('Credenciales incorrectas')
        return redirect(url_for('index'))
    
    # Verificar si está bloqueado
    if user['bloqueado_hasta']:
        try:
            bloqueado_hasta = datetime.fromisoformat(user['bloqueado_hasta'])
            if obtener_fecha_hora_chile().replace(tzinfo=None) < bloqueado_hasta:
                conn.close()
                flash('Cuenta bloqueada temporalmente. Intente más tarde.')
                return redirect(url_for('index'))
        except:
            pass
    
    # Verificar contraseña (primero hash, luego texto plano para migración)
    password_valida = False
    
    # Intentar con password_hash (nuevo sistema)
    if user['password_hash']:
        password_valida = verificar_password(password, user['password_hash'])
    
    # Si no hay hash o falló, intentar con password en texto plano (migración)
    if not password_valida and user['password'] == password:
        password_valida = True
        # Migrar contraseña a hash automáticamente
        nuevo_hash = hashear_password(password)
        conn.execute('UPDATE usuarios SET password_hash = ? WHERE id = ?', 
                    (nuevo_hash, user['id']))
        conn.commit()
    
    if password_valida:
        # Login exitoso
        session.update({
            'user_id': user['id'], 
            'nombre': user['nombre'], 
            'rol': user['rol'],
            'login_time': obtener_timestamp_chile()
        })
        
        # Actualizar último acceso y resetear intentos fallidos
        conn.execute('''
            UPDATE usuarios 
            SET ultimo_acceso = ?, intentos_fallidos = 0, bloqueado_hasta = NULL 
            WHERE id = ?
        ''', (obtener_timestamp_chile(), user['id']))
        
        # Registrar login exitoso
        registrar_auditoria(
            conn=conn,
            usuario_id=user['id'],
            usuario_nombre=user['nombre'],
            usuario_rol=user['rol'],
            accion='login_exitoso',
            categoria='autenticacion',
            resultado='exito',
            mensaje=f"Inicio de sesión desde {ip_origen}",
            ip_origen=ip_origen
        )
        
        conn.commit()
        conn.close()
        # Redirigir al dashboard correcto (admin_maestro usa dashboard_admin)
        if user['rol'] == 'admin_maestro':
            return redirect(url_for('dashboard_admin'))
        return redirect(url_for(f"dashboard_{user['rol']}"))
    else:
        # Login fallido - incrementar intentos
        intentos = (user['intentos_fallidos'] or 0) + 1
        bloqueado_hasta = None
        
        # Bloquear después de 5 intentos fallidos (30 minutos)
        if intentos >= 5:
            from datetime import timedelta
            bloqueado_hasta = (obtener_fecha_hora_chile() + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute('''
            UPDATE usuarios 
            SET intentos_fallidos = ?, bloqueado_hasta = ? 
            WHERE id = ?
        ''', (intentos, bloqueado_hasta, user['id']))
        
        # Registrar intento fallido
        registrar_auditoria(
            conn=conn,
            usuario_id=user['id'],
            usuario_nombre=user['nombre'],
            usuario_rol=user['rol'],
            accion='login_fallido',
            categoria='autenticacion',
            resultado='error',
            mensaje=f"Contraseña incorrecta. Intento {intentos}/5",
            ip_origen=ip_origen
        )
        
        conn.commit()
        conn.close()
        
        if intentos >= 5:
            flash('Cuenta bloqueada por 30 minutos debido a múltiples intentos fallidos.')
        else:
            flash('Credenciales incorrectas')
        return redirect(url_for('index'))

@app.route('/dashboard_admin_maestro')
def dashboard_admin_maestro():
    """Alias para el dashboard de admin maestro - usa el mismo template"""
    return redirect(url_for('dashboard_admin'))

@app.route('/dashboard_admin')
def dashboard_admin():
    rol = session.get('rol')
    # Permitir acceso a admin y admin_maestro
    if rol not in ['admin', 'admin_maestro']: 
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    usuarios = conn.execute('SELECT * FROM usuarios').fetchall()
    lugares = conn.execute('SELECT * FROM lugares').fetchall()
    historial = conn.execute('SELECT * FROM historial_consultas ORDER BY fecha_fin DESC').fetchall()
    
    # Obtener solicitudes pendientes (solo para admin_maestro)
    solicitudes_pendientes = []
    total_pendientes = 0
    if es_admin_maestro(rol):
        solicitudes_pendientes = obtener_solicitudes_pendientes(conn)
        total_pendientes = len(solicitudes_pendientes)
    
    # Obtener mis solicitudes (para admin regular)
    mis_solicitudes = []
    if rol == 'admin':
        mis_solicitudes = obtener_solicitudes_usuario(conn, session.get('user_id'))
    
    conn.close()
    respaldos = listar_respaldos()
    
    return render_template('dashboard_admin.html', 
                          saludo="Admin Maestro" if es_admin_maestro(rol) else "Admin",
                          usuarios=usuarios, 
                          lugares=lugares, 
                          historial=historial, 
                          respaldos=respaldos,
                          es_admin_maestro=es_admin_maestro(rol),
                          solicitudes_pendientes=solicitudes_pendientes,
                          total_pendientes=total_pendientes,
                          mis_solicitudes=mis_solicitudes)

@app.route('/dashboard_medico')
def dashboard_medico():
    if session.get('rol') != 'medico': return redirect(url_for('index'))
    conn = get_db_connection()
    nombre_medico = session.get('nombre', '')
    
    # El médico ve TODAS las consultas en espera
    consultas = conn.execute('''
        SELECT c.*, l.nombre_posta FROM consultas c 
        JOIN lugares l ON c.lugar_id = l.id WHERE c.estado = 'esperando'
    ''').fetchall()
    
    # Consultas finalizadas hoy por este médico
    consultas_finalizadas = conn.execute('''
        SELECT COUNT(*) as total FROM historial_consultas 
        WHERE nombre_medico = ? AND DATE(fecha_fin) = DATE('now', 'localtime')
    ''', (nombre_medico,)).fetchone()['total']
    
    # Historial de consultas finalizadas hoy (para el desplegable)
    historial_hoy = conn.execute('''
        SELECT codigo_consulta, cip, tens_nombre, nombre_posta, fecha_inicio, fecha_fin 
        FROM historial_consultas 
        WHERE nombre_medico = ? AND DATE(fecha_fin) = DATE('now', 'localtime')
        ORDER BY fecha_fin DESC
        LIMIT 20
    ''', (nombre_medico,)).fetchall()
    
    # Consultas pendientes (atendiendo pero no finalizadas - desconexión)
    consultas_pendientes = conn.execute('''
        SELECT c.*, l.nombre_posta FROM consultas c 
        JOIN lugares l ON c.lugar_id = l.id 
        WHERE c.estado = 'atendiendo' AND c.nombre_medico = ?
    ''', (nombre_medico,)).fetchall()
    
    conn.close()
    return render_template('dashboard_medico.html', 
                           saludo=f"Doctor {session['nombre']}", 
                           pacientes=consultas,
                           consultas_finalizadas=consultas_finalizadas,
                           historial_hoy=historial_hoy,
                           consultas_pendientes=consultas_pendientes)

@app.route('/api/pacientes-espera')
def api_pacientes_espera():
    """API para obtener pacientes en espera (AJAX) sin recargar toda la página"""
    if session.get('rol') != 'medico':
        return jsonify({'error': 'No autorizado'}), 403
    
    conn = get_db_connection()
    consultas = conn.execute('''
        SELECT c.id, c.cip, c.fecha, l.nombre_posta, c.tens_nombre 
        FROM consultas c 
        JOIN lugares l ON c.lugar_id = l.id 
        WHERE c.estado = 'esperando'
        ORDER BY c.fecha ASC
    ''').fetchall()
    conn.close()
    
    # Convertir a lista de diccionarios
    pacientes = []
    for c in consultas:
        pacientes.append({
            'id': c['id'],
            'cip': c['cip'],
            'nombre_posta': c['nombre_posta'],
            'tens_nombre': c['tens_nombre'],
            'tens_inicial': c['tens_nombre'][0] if c['tens_nombre'] else '?'
        })
    
    return jsonify({'pacientes': pacientes, 'total': len(pacientes)})


@app.route('/dashboard_tens')
def dashboard_tens():
    if session.get('rol') != 'tens': return redirect(url_for('index'))
    conn = get_db_connection()
    lugares = conn.execute('SELECT * FROM lugares').fetchall()
    conn.close()
    return render_template('dashboard_tens.html', saludo=f"TENS {session['nombre']}", lugares=lugares)

# ==========================================
# ACCIONES DE ADMINISTRACIÓN
# ==========================================

@app.route('/admin/registrar-usuario', methods=['POST'])
def registrar_usuario():
    rol_sesion = session.get('rol')
    if rol_sesion not in ['admin', 'admin_maestro']: 
        return redirect(url_for('index'))
    
    nombre = request.form.get('nombre', '').strip()
    rut = request.form.get('rut', '').strip()
    correo = request.form.get('correo', '').strip().lower()
    rol = request.form.get('rol', '').lower().strip()
    password = request.form.get('password', '')
    
    # Validar RUT chileno
    rut_valido, rut_numero, rut_dv, rut_mensaje = validar_rut_chileno(rut)
    if not rut_valido:
        flash(f'❌ RUT inválido: {rut_mensaje}')
        return redirect(url_for('dashboard_admin'))
    
    # Normalizar RUT (formato: 12345678-9)
    rut_normalizado = normalizar_rut(rut)
    
    # Validar política de contraseña
    password_valida, password_mensaje = validar_politica_password(password)
    if not password_valida:
        flash(f'❌ Contraseña inválida: {password_mensaje}')
        return redirect(url_for('dashboard_admin'))
    
    # Hashear contraseña
    password_hash = hashear_password(password)
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO usuarios (nombre, rut, correo, rol, password, password_hash, fecha_creacion, activo) 
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (nombre, rut_normalizado, correo, rol, password, password_hash, obtener_timestamp_chile()))
        
        # Registrar auditoría
        registrar_auditoria(
            conn=conn,
            usuario_id=session.get('user_id'),
            usuario_nombre=session.get('nombre'),
            usuario_rol=session.get('rol'),
            accion='usuario_creado',
            categoria='usuarios',
            entidad_tipo='usuario',
            entidad_id=str(conn.execute('SELECT last_insert_rowid()').fetchone()[0]),
            datos_despues=json.dumps({'nombre': nombre, 'rut_masked': enmascarar_rut(rut_normalizado), 'rol': rol}),
            resultado='exito',
            mensaje=f'Usuario {nombre} ({rol}) creado',
            ip_origen=request.remote_addr
        )
        
        conn.commit()
        flash(f'✅ Usuario {nombre} registrado exitosamente.')
    except sqlite3.IntegrityError as e:
        if 'rut' in str(e).lower():
            flash('❌ Error: El RUT ya está registrado.')
        elif 'correo' in str(e).lower():
            flash('❌ Error: El correo ya está registrado.')
        else:
            flash('❌ Error: Datos duplicados.')
    except Exception as e:
        flash(f'❌ Error al registrar usuario: {str(e)}')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/eliminar-usuarios', methods=['POST'])
def eliminar_usuarios():
    rol = session.get('rol')
    if rol not in ['admin', 'admin_maestro']: 
        return redirect(url_for('index'))
    
    ids = request.form.getlist('usuarios_seleccionados')
    if not ids:
        flash('No se seleccionaron usuarios.')
        return redirect(url_for('dashboard_admin'))
    
    conn = get_db_connection()
    
    for uid in ids:
        usuario = conn.execute(
            "SELECT id, nombre, rol, es_plantilla, rut FROM usuarios WHERE id = ?", 
            (uid,)
        ).fetchone()
        
        if not usuario:
            continue
        
        # No se puede eliminar plantillas
        if usuario['es_plantilla']:
            flash(f"El usuario '{usuario['nombre']}' es una plantilla protegida.")
            continue
        
        # No se puede eliminar admin_maestro
        if usuario['rol'] == 'admin_maestro':
            flash("No se puede eliminar al Admin Maestro.")
            continue
        
        # Verificar que no sea el único admin
        if usuario['rol'] in ['admin', 'admin_maestro']:
            total_admins = conn.execute(
                "SELECT COUNT(*) FROM usuarios WHERE rol IN ('admin', 'admin_maestro')"
            ).fetchone()[0]
            if total_admins <= 1:
                flash("No puedes eliminar al unico Administrador.")
                continue
        
        # Si es admin_maestro, ejecutar directamente
        if es_admin_maestro(rol):
            conn.execute('DELETE FROM usuarios WHERE id = ?', (uid,))
            registrar_auditoria(
                conn=conn,
                usuario_id=session.get('user_id'),
                usuario_nombre=session.get('nombre'),
                usuario_rol=rol,
                accion='usuario_eliminado',
                categoria='usuarios',
                entidad_tipo='usuario',
                entidad_id=str(uid),
                datos_antes=json.dumps({'nombre': usuario['nombre'], 'rol': usuario['rol']}),
                resultado='exito',
                mensaje=f"Usuario {usuario['nombre']} eliminado por Admin Maestro",
                ip_origen=request.remote_addr
            )
            flash(f"Usuario '{usuario['nombre']}' eliminado.")
        else:
            # Admin regular: crear solicitud de aprobacion
            solicitud_id = crear_solicitud(
                conn=conn,
                tipo_accion='eliminar_usuario',
                entidad_tipo='usuario',
                entidad_id=str(uid),
                solicitante_id=session.get('user_id'),
                solicitante_nombre=session.get('nombre'),
                solicitante_rol=rol,
                datos_originales={'nombre': usuario['nombre'], 'rol': usuario['rol'], 'rut_masked': enmascarar_rut(usuario['rut'])},
                justificacion=request.form.get('justificacion', '')
            )
            
            if solicitud_id:
                registrar_auditoria(
                    conn=conn,
                    usuario_id=session.get('user_id'),
                    usuario_nombre=session.get('nombre'),
                    usuario_rol=rol,
                    accion='solicitud_eliminacion_usuario',
                    categoria='usuarios',
                    entidad_tipo='solicitud',
                    entidad_id=str(solicitud_id),
                    resultado='pendiente',
                    mensaje=f"Solicitud para eliminar usuario {usuario['nombre']}",
                    ip_origen=request.remote_addr
                )
                flash(f"Solicitud de eliminacion de '{usuario['nombre']}' enviada al Admin Maestro.")
            else:
                flash(f"Error al crear solicitud para {usuario['nombre']}.")
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/registrar-lugar', methods=['POST'])
def registrar_lugar():
    rol = session.get('rol')
    if rol not in ['admin', 'admin_maestro']: 
        return redirect(url_for('index'))
    
    nombre = request.form.get('nombre_posta', '').strip()
    direccion = request.form.get('direccion', '').strip()
    
    if not nombre or not direccion:
        flash('Nombre y direccion son requeridos.')
        return redirect(url_for('dashboard_admin'))
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO lugares (nombre_posta, direccion, fecha_creacion, activo) 
            VALUES (?, ?, ?, 1)
        ''', (nombre, direccion, obtener_timestamp_chile()))
        
        registrar_auditoria(
            conn=conn,
            usuario_id=session.get('user_id'),
            usuario_nombre=session.get('nombre'),
            usuario_rol=rol,
            accion='lugar_creado',
            categoria='lugares',
            entidad_tipo='lugar',
            entidad_id=str(conn.execute('SELECT last_insert_rowid()').fetchone()[0]),
            datos_despues=json.dumps({'nombre': nombre, 'direccion': direccion}),
            resultado='exito',
            mensaje=f'Lugar {nombre} creado',
            ip_origen=request.remote_addr
        )
        
        conn.commit()
        flash(f'Lugar "{nombre}" registrado exitosamente.')
    except Exception as e:
        flash(f'Error al registrar lugar: {str(e)}')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/eliminar-lugares', methods=['POST'])
def eliminar_lugares():
    rol = session.get('rol')
    if rol not in ['admin', 'admin_maestro']: 
        return redirect(url_for('index'))
    
    ids = request.form.getlist('lugares_seleccionados')
    if not ids:
        flash('No se seleccionaron lugares.')
        return redirect(url_for('dashboard_admin'))
    
    conn = get_db_connection()
    
    for lid in ids:
        lugar = conn.execute(
            "SELECT id, nombre_posta, direccion, es_plantilla FROM lugares WHERE id = ?", 
            (lid,)
        ).fetchone()
        
        if not lugar:
            continue
        
        # No se puede eliminar plantillas
        if lugar['es_plantilla']:
            flash(f"La posta '{lugar['nombre_posta']}' es una plantilla protegida.")
            continue
        
        # Si es admin_maestro, ejecutar directamente
        if es_admin_maestro(rol):
            conn.execute('DELETE FROM lugares WHERE id = ?', (lid,))
            registrar_auditoria(
                conn=conn,
                usuario_id=session.get('user_id'),
                usuario_nombre=session.get('nombre'),
                usuario_rol=rol,
                accion='lugar_eliminado',
                categoria='lugares',
                entidad_tipo='lugar',
                entidad_id=str(lid),
                datos_antes=json.dumps({'nombre': lugar['nombre_posta']}),
                resultado='exito',
                mensaje=f"Lugar {lugar['nombre_posta']} eliminado por Admin Maestro",
                ip_origen=request.remote_addr
            )
            flash(f"Lugar '{lugar['nombre_posta']}' eliminado.")
        else:
            # Admin regular: crear solicitud de aprobacion
            solicitud_id = crear_solicitud(
                conn=conn,
                tipo_accion='eliminar_lugar',
                entidad_tipo='lugar',
                entidad_id=str(lid),
                solicitante_id=session.get('user_id'),
                solicitante_nombre=session.get('nombre'),
                solicitante_rol=rol,
                datos_originales={'nombre': lugar['nombre_posta'], 'direccion': lugar['direccion']},
                justificacion=request.form.get('justificacion', '')
            )
            
            if solicitud_id:
                flash(f"Solicitud de eliminacion de '{lugar['nombre_posta']}' enviada al Admin Maestro.")
            else:
                flash(f"Error al crear solicitud para {lugar['nombre_posta']}.")
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard_admin'))

# ==========================================
# GESTIÓN DE APROBACIONES (Solo Admin Maestro)
# ==========================================

@app.route('/admin/aprobar-solicitud/<int:solicitud_id>', methods=['POST'])
def aprobar_solicitud_route(solicitud_id):
    """Aprueba una solicitud pendiente"""
    rol = session.get('rol')
    if not es_admin_maestro(rol):
        flash('Solo el Admin Maestro puede aprobar solicitudes.')
        return redirect(url_for('dashboard_admin'))
    
    motivo = request.form.get('motivo', 'Aprobada')
    
    conn = get_db_connection()
    exito, mensaje = aprobar_solicitud(
        conn=conn,
        solicitud_id=solicitud_id,
        aprobador_id=session.get('user_id'),
        aprobador_nombre=session.get('nombre'),
        motivo=motivo
    )
    
    if exito:
        registrar_auditoria(
            conn=conn,
            usuario_id=session.get('user_id'),
            usuario_nombre=session.get('nombre'),
            usuario_rol=rol,
            accion='solicitud_aprobada',
            categoria='sistema',
            entidad_tipo='solicitud',
            entidad_id=str(solicitud_id),
            resultado='exito',
            mensaje=mensaje,
            ip_origen=request.remote_addr
        )
        flash(f'Solicitud aprobada: {mensaje}')
    else:
        flash(f'Error al aprobar: {mensaje}')
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/rechazar-solicitud/<int:solicitud_id>', methods=['POST'])
def rechazar_solicitud_route(solicitud_id):
    """Rechaza una solicitud pendiente"""
    rol = session.get('rol')
    if not es_admin_maestro(rol):
        flash('Solo el Admin Maestro puede rechazar solicitudes.')
        return redirect(url_for('dashboard_admin'))
    
    motivo = request.form.get('motivo', '')
    if not motivo:
        flash('Debe proporcionar un motivo para rechazar.')
        return redirect(url_for('dashboard_admin'))
    
    conn = get_db_connection()
    exito, mensaje = rechazar_solicitud(
        conn=conn,
        solicitud_id=solicitud_id,
        aprobador_id=session.get('user_id'),
        aprobador_nombre=session.get('nombre'),
        motivo=motivo
    )
    
    if exito:
        registrar_auditoria(
            conn=conn,
            usuario_id=session.get('user_id'),
            usuario_nombre=session.get('nombre'),
            usuario_rol=rol,
            accion='solicitud_rechazada',
            categoria='sistema',
            entidad_tipo='solicitud',
            entidad_id=str(solicitud_id),
            resultado='exito',
            mensaje=f"Rechazada: {motivo}",
            ip_origen=request.remote_addr
        )
        flash(f'Solicitud rechazada.')
    else:
        flash(f'Error al rechazar: {mensaje}')
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard_admin'))

# ==========================================
# ACCIONES DE CONSULTA
# ==========================================

@app.route('/tens/crear-consulta', methods=['POST'])
def crear_consulta():
    if session.get('rol') != 'tens': return redirect(url_for('index'))
    if request.form.get('consentimiento') != 'aceptado':
        flash('Atencion: El paciente debe aceptar el consentimiento.')
        return redirect(url_for('dashboard_tens'))

    rut_paciente = request.form.get('rut_paciente', '').strip()
    lugar_id = request.form.get('lugar_id')
    
    # Validar RUT del paciente
    rut_valido, rut_numero, rut_dv, rut_mensaje = validar_rut_chileno(rut_paciente)
    if not rut_valido:
        flash(f'RUT invalido: {rut_mensaje}')
        return redirect(url_for('dashboard_tens'))
    
    # Normalizar RUT (formato: 12345678-9)
    rut_normalizado = normalizar_rut(rut_paciente)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Obtener nombre de la posta para generar CIP
    lugar = cursor.execute('SELECT nombre_posta FROM lugares WHERE id = ?', (lugar_id,)).fetchone()
    nombre_posta = lugar['nombre_posta'] if lugar else 'GEN'
    
    # ==========================================
    # PRIVACY BY DESIGN: Generar identificadores pseudoanónimos
    # ==========================================
    
    # 1. Generar CIP único (Código de Identificación de Paciente)
    cip = generar_cip(nombre_posta)
    
    # Verificar que el CIP sea único (regenerar si ya existe)
    while cursor.execute('SELECT id FROM mapeo_pacientes WHERE cip = ?', (cip,)).fetchone():
        cip = generar_cip(nombre_posta)
    
    # 2. Cifrar RUT con AES-256-GCM (Ley 19.628 / Marco Ciberseguridad)
    rut_cifrado = cifrar_rut(rut_normalizado)
    if not rut_cifrado:
        flash('Error de seguridad al procesar datos del paciente.')
        conn.close()
        return redirect(url_for('dashboard_tens'))
    
    # 3. Hash del RUT para búsquedas (sin exponer el RUT)
    rut_hash = hashear_rut(rut_normalizado)
    
    # 4. RUT enmascarado para display mínimo si es necesario
    rut_masked = enmascarar_rut(rut_normalizado)
    
    # ==========================================
    # ALMACENAMIENTO SEGURO
    # ==========================================
    
    # Guardar mapeo CIP ↔ RUT cifrado (solo para trazabilidad interna)
    cursor.execute('''
        INSERT INTO mapeo_pacientes (cip, rut_cifrado, rut_hash, rut_enmascarado, creado_por_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (cip, rut_cifrado, rut_hash, rut_masked, session.get('user_id')))
    
    # Crear consulta con CIP (SIN RUT visible)
    cursor.execute('''
        INSERT INTO consultas (cip, rut_paciente_hash, lugar_id, tens_nombre, nombre_medico) 
        VALUES (?, ?, ?, ?, 'Pendiente')
    ''', (cip, rut_hash, lugar_id, session['nombre']))
    
    conn.commit()
    consulta_id = cursor.lastrowid
    conn.close()
    
    # Usar CIP como identificador de sala (NO el RUT)
    token = generar_token_jitsi(session['nombre'], cip)
    return render_template('consulta.html', jitsi_token=token, sala=cip, 
                           nombre_usuario=f"TENS: {session['nombre']}", 
                           consulta_id=consulta_id, es_medico=False)

@app.route('/iniciar-consulta', methods=['POST'])
def iniciar_consulta():
    if not session.get('user_id'): return redirect(url_for('index'))
    # Ahora recibimos CIP en lugar de RUT
    cip = request.form.get('cip') or request.form.get('nombre_paciente')  # Compatibilidad
    consulta_id = request.form.get('consulta_id')
    
    # Actualizar estado de la consulta cuando el médico entra
    if consulta_id and session.get('rol') == 'medico':
        conn = get_db_connection()
        conn.execute('''
            UPDATE consultas SET estado = 'atendiendo', nombre_medico = ? 
            WHERE id = ?
        ''', (session['nombre'], consulta_id))
        conn.commit()
        conn.close()
    
    # Usar CIP como identificador de sala (Privacy by Design)
    token = generar_token_jitsi(session['nombre'], cip)
    return render_template('consulta.html', jitsi_token=token, sala=cip, 
                           nombre_usuario=f"Doctor: {session['nombre']}", 
                           consulta_id=consulta_id, es_medico=True)

# ==========================================
# CONTROL DE CONSULTA (MÉDICO CONTROLA)
# ==========================================

@app.route('/finalizar-consulta', methods=['POST'])
def finalizar_consulta():
    """Solo el médico puede finalizar la consulta y se guarda en historial"""
    
    # Verificar si es cierre automático (sendBeacon cuando médico navega hacia atrás)
    es_auto_close = request.form.get('auto_close') == 'true'
    
    # Para cierre manual, verificar que sea médico
    if not es_auto_close and session.get('rol') != 'medico':
        return jsonify({'error': 'No autorizado'}), 403
    
    consulta_id = request.form.get('consulta_id')
    if not consulta_id:
        return jsonify({'error': 'ID de consulta no proporcionado'}), 400
        
    conn = get_db_connection()
    
    # Verificar que la consulta existe y está activa o atendiendo
    consulta = conn.execute('''
        SELECT c.*, l.nombre_posta 
        FROM consultas c 
        JOIN lugares l ON c.lugar_id = l.id 
        WHERE c.id = ? AND c.estado IN ('activa', 'atendiendo')
    ''', (consulta_id,)).fetchone()
    
    if not consulta:
        conn.close()
        # Si ya está finalizada, retornar éxito silencioso
        return jsonify({'success': True, 'message': 'Consulta ya finalizada'})
    
    # Usar CIP existente como código de consulta (Privacy by Design)
    cip = consulta['cip']
    
    # Generar código único para el historial (basado en CIP + timestamp)
    codigo_consulta = f"{cip}-{int(time.time()) % 10000}"
    
    # Generar token de seguridad hasheado (SHA256) - sin usar RUT
    # Para auto_close, usar el nombre del médico de la consulta
    nombre_medico = session.get('nombre', consulta['nombre_medico'] if consulta['nombre_medico'] else 'Médico')
    data_to_hash = f"{codigo_consulta}{cip}{nombre_medico}{time.time()}"
    token_seguridad = hashlib.sha256(data_to_hash.encode()).hexdigest()[:16]
    
    # Obtener RUT cifrado desde tabla de mapeo (para trazabilidad)
    mapeo = conn.execute('''
        SELECT rut_cifrado, rut_hash FROM mapeo_pacientes WHERE cip = ?
    ''', (cip,)).fetchone()
    
    if mapeo:
        rut_cifrado = mapeo['rut_cifrado']
        rut_hash = mapeo['rut_hash']
    else:
        # Fallback si no hay mapeo (datos antiguos)
        rut_cifrado = ''
        try:
            rut_hash = consulta['rut_paciente_hash'] if consulta['rut_paciente_hash'] else ''
        except (KeyError, IndexError):
            rut_hash = ''
    
    # Guardar en historial con datos cifrados (SIN RUT en texto plano)
    try:
        conn.execute('''
            INSERT INTO historial_consultas 
            (codigo_consulta, token_seguridad, cip, rut_paciente_cifrado, rut_paciente_hash, 
             nombre_medico, tens_nombre, nombre_posta, fecha_inicio)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (codigo_consulta, token_seguridad, cip, rut_cifrado, rut_hash,
              nombre_medico, consulta['tens_nombre'], consulta['nombre_posta'], consulta['fecha']))
    except sqlite3.IntegrityError:
        # Si el código ya existe, agregar timestamp adicional
        codigo_consulta = f"{cip}-{int(time.time())}"
        conn.execute('''
            INSERT INTO historial_consultas 
            (codigo_consulta, token_seguridad, cip, rut_paciente_cifrado, rut_paciente_hash,
             nombre_medico, tens_nombre, nombre_posta, fecha_inicio)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (codigo_consulta, token_seguridad, cip, rut_cifrado, rut_hash,
              nombre_medico, consulta['tens_nombre'], consulta['nombre_posta'], consulta['fecha']))
    
    # Actualizar estado de la consulta
    conn.execute('UPDATE consultas SET estado = ? WHERE id = ?', ('finalizada', consulta_id))
    conn.commit()
    conn.close()
    
    # Log para depuración
    if es_auto_close:
        print(f"[AUTO-CLOSE] Consulta {consulta_id} finalizada automáticamente (navegación hacia atrás)")
    
    return jsonify({'success': True, 'message': 'Consulta finalizada', 'codigo': codigo_consulta})

@app.route('/verificar-estado-consulta/<int:consulta_id>')
def verificar_estado_consulta(consulta_id):
    """El TENS verifica si la consulta fue finalizada por el médico"""
    conn = get_db_connection()
    consulta = conn.execute('SELECT estado FROM consultas WHERE id = ?', (consulta_id,)).fetchone()
    conn.close()
    
    if consulta:
        return jsonify({'estado': consulta['estado']})
    return jsonify({'error': 'Consulta no encontrada'}), 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ==========================================
# RUTAS DE RESPALDOS (Solo Admin)
# ==========================================

@app.route('/admin/crear-respaldo', methods=['POST'])
def admin_crear_respaldo():
    """Crear respaldo manual de la base de datos"""
    if session.get('rol') not in ['admin', 'admin_maestro']:
        return redirect(url_for('index'))
    
    nombre = crear_respaldo(manual=True)
    if nombre:
        flash(f'✅ Respaldo creado exitosamente: {nombre}')
    else:
        flash('❌ Error al crear respaldo')
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/descargar-respaldo/<nombre>')
def admin_descargar_respaldo(nombre):
    """Descargar un archivo de respaldo"""
    if session.get('rol') not in ['admin', 'admin_maestro']:
        return redirect(url_for('index'))
    
    # Validar que el nombre sea seguro (solo backup_*.db)
    if not nombre.startswith('backup_') or not nombre.endswith('.db'):
        flash('❌ Archivo no válido')
        return redirect(url_for('dashboard_admin'))
    
    backup_path = os.path.join(BACKUP_DIR, nombre)
    if os.path.exists(backup_path):
        return send_file(backup_path, as_attachment=True, download_name=nombre)
    
    flash('❌ Respaldo no encontrado')
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/eliminar-respaldos', methods=['POST'])
def admin_eliminar_respaldos():
    """Eliminar respaldos seleccionados (requiere verificación de contraseña)"""
    if session.get('rol') not in ['admin', 'admin_maestro']:
        return redirect(url_for('index'))
    
    # Verificar contraseña del admin
    password = request.form.get('password_confirmacion')
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    admin = conn.execute('SELECT password FROM usuarios WHERE id = ?', (user_id,)).fetchone()
    
    if not admin or admin['password'] != password:
        conn.close()
        flash('❌ Contraseña incorrecta. No se eliminaron los respaldos.')
        return redirect(url_for('dashboard_admin'))
    
    # Obtener respaldos seleccionados
    respaldos_seleccionados = request.form.getlist('respaldos_seleccionados')
    
    if not respaldos_seleccionados:
        conn.close()
        flash('⚠️ No se seleccionaron respaldos para eliminar.')
        return redirect(url_for('dashboard_admin'))
    
    eliminados = 0
    errores = 0
    protegidos = 0
    
    for nombre in respaldos_seleccionados:
        # Validar que el nombre sea seguro
        if not nombre.startswith('backup_') or not nombre.endswith('.db'):
            errores += 1
            continue
        
        # PROTEGER respaldos automáticos (no se pueden eliminar)
        if 'backup_auto_' in nombre:
            protegidos += 1
            continue
        
        backup_path = os.path.join(BACKUP_DIR, nombre)
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
                eliminados += 1
            except Exception as e:
                print(f"Error eliminando respaldo {nombre}: {e}")
                errores += 1
        else:
            errores += 1
    
    conn.close()
    
    if eliminados > 0:
        flash(f'✅ Se eliminaron {eliminados} respaldo(s) correctamente.')
    if protegidos > 0:
        flash(f'🔒 {protegidos} respaldo(s) automático(s) NO se eliminaron (están protegidos).')
    if errores > 0:
        flash(f'⚠️ Hubo {errores} error(es) al eliminar algunos respaldos.')
    
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/exportar-historial')
def admin_exportar_historial():
    """Exportar historial de consultas a CSV (sin datos sensibles) con filtro por fechas"""
    rol = session.get('rol')
    if rol not in ['admin', 'admin_maestro']:
        return redirect(url_for('index'))
    
    # Obtener filtros de fecha (opcional)
    fecha_desde = request.args.get('fecha_desde', '')
    fecha_hasta = request.args.get('fecha_hasta', '')
    
    conn = get_db_connection()
    
    # Construir query con filtros opcionales
    query = 'SELECT * FROM historial_consultas WHERE 1=1'
    params = []
    
    if fecha_desde:
        query += ' AND DATE(fecha_fin) >= ?'
        params.append(fecha_desde)
    
    if fecha_hasta:
        query += ' AND DATE(fecha_fin) <= ?'
        params.append(fecha_hasta)
    
    query += ' ORDER BY fecha_fin DESC'
    
    historial = conn.execute(query, params).fetchall()
    conn.close()
    
    # Crear CSV en memoria
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Encabezados (SIN RUT - Privacy by Design)
    writer.writerow(['Código', 'Token Seguridad', 'CIP (Código Atención)', 'Médico', 'TENS', 'Posta', 'Fecha Inicio', 'Fecha Fin'])
    
    # Datos
    for h in historial:
        # Manejar CIP que podría no existir en registros antiguos
        try:
            cip = h['cip'] if h['cip'] else '(migración)'
        except (KeyError, IndexError):
            cip = '(migración)'
        
        writer.writerow([
            h['codigo_consulta'],
            h['token_seguridad'],
            cip,  # CIP en lugar de RUT
            h['nombre_medico'],
            h['tens_nombre'],
            h['nombre_posta'],
            h['fecha_inicio'],
            h['fecha_fin']
        ])
    
    # Preparar respuesta con nombre descriptivo
    output.seek(0)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
    
    # Nombre del archivo incluye rango de fechas si se filtró
    if fecha_desde or fecha_hasta:
        rango = f"_{fecha_desde or 'inicio'}_a_{fecha_hasta or 'hoy'}"
    else:
        rango = "_completo"
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'historial_consultas{rango}_{timestamp}.csv'
    )

if __name__ == '__main__':
    iniciar_hilo_respaldos()
    app.run(host='0.0.0.0', port=5000, debug=True)
