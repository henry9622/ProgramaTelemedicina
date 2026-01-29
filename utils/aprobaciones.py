# ==========================================
# MÓDULO DE APROBACIONES - TELEMEDICINA
# ==========================================
# Sistema de solicitudes y aprobaciones
# para acciones sensibles
# ==========================================

import json
from .seguridad import obtener_timestamp_chile, enmascarar_rut

# Tipos de acciones que requieren aprobación
ACCIONES_REQUIEREN_APROBACION = {
    'eliminar_usuario': {
        'descripcion': 'Eliminar usuario',
        'categoria': 'usuarios',
        'nivel_riesgo': 'alto'
    },
    'eliminar_lugar': {
        'descripcion': 'Eliminar posta/lugar',
        'categoria': 'lugares',
        'nivel_riesgo': 'alto'
    },
    'eliminar_respaldo': {
        'descripcion': 'Eliminar respaldo',
        'categoria': 'respaldos',
        'nivel_riesgo': 'alto'
    },
    'modificar_usuario': {
        'descripcion': 'Modificar datos de usuario',
        'categoria': 'usuarios',
        'nivel_riesgo': 'medio'
    },
    'modificar_lugar': {
        'descripcion': 'Modificar datos de posta',
        'categoria': 'lugares',
        'nivel_riesgo': 'medio'
    },
    'exportar_historial': {
        'descripcion': 'Exportar historial clinico',
        'categoria': 'historial',
        'nivel_riesgo': 'alto'
    },
}


def requiere_aprobacion(rol_usuario, tipo_accion):
    """
    Determina si una acción requiere aprobación según el rol.
    
    Args:
        rol_usuario: Rol del usuario que ejecuta la acción
        tipo_accion: Tipo de acción a ejecutar
        
    Returns:
        bool: True si requiere aprobación
    """
    # Admin Maestro no requiere aprobación
    if rol_usuario == 'admin_maestro':
        return False
    
    # Admin regular requiere aprobación para acciones sensibles
    if rol_usuario == 'admin':
        return tipo_accion in ACCIONES_REQUIEREN_APROBACION
    
    # Otros roles no pueden realizar estas acciones
    return True


def crear_solicitud(conn, tipo_accion, entidad_tipo, entidad_id, 
                    solicitante_id, solicitante_nombre, solicitante_rol,
                    datos_originales=None, datos_nuevos=None, justificacion=None):
    """
    Crea una nueva solicitud de aprobación.
    
    Returns:
        int: ID de la solicitud creada, o None si hay error
    """
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO solicitudes_aprobacion (
                tipo_accion, entidad_tipo, entidad_id,
                datos_originales, datos_nuevos,
                solicitante_id, solicitante_nombre, solicitante_rol,
                justificacion, estado, fecha_solicitud
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pendiente', ?)
        ''', (
            tipo_accion, entidad_tipo, entidad_id,
            json.dumps(datos_originales, default=str) if datos_originales else None,
            json.dumps(datos_nuevos, default=str) if datos_nuevos else None,
            solicitante_id, solicitante_nombre, solicitante_rol,
            justificacion,
            obtener_timestamp_chile()
        ))
        
        return cursor.lastrowid
        
    except Exception as e:
        print(f"[APROBACIONES] Error al crear solicitud: {e}")
        return None


def obtener_solicitudes_pendientes(conn, limite=50):
    """
    Obtiene todas las solicitudes pendientes de aprobación.
    
    Returns:
        List: Lista de solicitudes pendientes
    """
    solicitudes = conn.execute('''
        SELECT * FROM solicitudes_aprobacion 
        WHERE estado = 'pendiente'
        ORDER BY fecha_solicitud DESC
        LIMIT ?
    ''', (limite,)).fetchall()
    
    return solicitudes


def obtener_solicitudes_usuario(conn, usuario_id, limite=20):
    """
    Obtiene las solicitudes creadas por un usuario específico.
    """
    solicitudes = conn.execute('''
        SELECT * FROM solicitudes_aprobacion 
        WHERE solicitante_id = ?
        ORDER BY fecha_solicitud DESC
        LIMIT ?
    ''', (usuario_id, limite)).fetchall()
    
    return solicitudes


def contar_solicitudes_pendientes(conn):
    """
    Cuenta el número de solicitudes pendientes.
    
    Returns:
        int: Número de solicitudes pendientes
    """
    resultado = conn.execute(
        "SELECT COUNT(*) as total FROM solicitudes_aprobacion WHERE estado = 'pendiente'"
    ).fetchone()
    
    return resultado['total'] if resultado else 0


def aprobar_solicitud(conn, solicitud_id, aprobador_id, aprobador_nombre, motivo=None):
    """
    Aprueba una solicitud y ejecuta la acción correspondiente.
    
    Returns:
        tuple: (exito, mensaje)
    """
    # Obtener la solicitud
    solicitud = conn.execute(
        "SELECT * FROM solicitudes_aprobacion WHERE id = ?",
        (solicitud_id,)
    ).fetchone()
    
    if not solicitud:
        return False, "Solicitud no encontrada"
    
    if solicitud['estado'] != 'pendiente':
        return False, f"La solicitud ya fue {solicitud['estado']}"
    
    try:
        # Ejecutar la acción según el tipo
        exito, mensaje = ejecutar_accion_aprobada(conn, solicitud)
        
        if exito:
            # Marcar como aprobada
            conn.execute('''
                UPDATE solicitudes_aprobacion 
                SET estado = 'aprobada',
                    aprobador_id = ?,
                    aprobador_nombre = ?,
                    fecha_resolucion = ?,
                    motivo_resolucion = ?
                WHERE id = ?
            ''', (
                aprobador_id, aprobador_nombre,
                obtener_timestamp_chile(),
                motivo or 'Aprobada',
                solicitud_id
            ))
            
            return True, mensaje
        else:
            return False, mensaje
            
    except Exception as e:
        return False, f"Error al aprobar: {str(e)}"


def rechazar_solicitud(conn, solicitud_id, aprobador_id, aprobador_nombre, motivo):
    """
    Rechaza una solicitud.
    
    Returns:
        tuple: (exito, mensaje)
    """
    solicitud = conn.execute(
        "SELECT * FROM solicitudes_aprobacion WHERE id = ?",
        (solicitud_id,)
    ).fetchone()
    
    if not solicitud:
        return False, "Solicitud no encontrada"
    
    if solicitud['estado'] != 'pendiente':
        return False, f"La solicitud ya fue {solicitud['estado']}"
    
    try:
        conn.execute('''
            UPDATE solicitudes_aprobacion 
            SET estado = 'rechazada',
                aprobador_id = ?,
                aprobador_nombre = ?,
                fecha_resolucion = ?,
                motivo_resolucion = ?
            WHERE id = ?
        ''', (
            aprobador_id, aprobador_nombre,
            obtener_timestamp_chile(),
            motivo or 'Rechazada sin motivo especificado',
            solicitud_id
        ))
        
        return True, "Solicitud rechazada"
        
    except Exception as e:
        return False, f"Error al rechazar: {str(e)}"


def ejecutar_accion_aprobada(conn, solicitud):
    """
    Ejecuta la acción de una solicitud aprobada.
    
    Returns:
        tuple: (exito, mensaje)
    """
    tipo_accion = solicitud['tipo_accion']
    entidad_tipo = solicitud['entidad_tipo']
    entidad_id = solicitud['entidad_id']
    
    try:
        if tipo_accion == 'eliminar_usuario':
            # Verificar que no sea el único admin_maestro
            if entidad_tipo == 'usuario':
                usuario = conn.execute(
                    "SELECT rol FROM usuarios WHERE id = ?", (entidad_id,)
                ).fetchone()
                
                if usuario and usuario['rol'] == 'admin_maestro':
                    total_maestros = conn.execute(
                        "SELECT COUNT(*) as total FROM usuarios WHERE rol = 'admin_maestro'"
                    ).fetchone()['total']
                    
                    if total_maestros <= 1:
                        return False, "No se puede eliminar al unico Admin Maestro"
                
                conn.execute("DELETE FROM usuarios WHERE id = ?", (entidad_id,))
                return True, "Usuario eliminado exitosamente"
        
        elif tipo_accion == 'eliminar_lugar':
            # Verificar que no sea plantilla
            lugar = conn.execute(
                "SELECT es_plantilla FROM lugares WHERE id = ?", (entidad_id,)
            ).fetchone()
            
            if lugar and lugar['es_plantilla']:
                return False, "No se puede eliminar una posta plantilla"
            
            conn.execute("DELETE FROM lugares WHERE id = ?", (entidad_id,))
            return True, "Lugar eliminado exitosamente"
        
        elif tipo_accion == 'eliminar_respaldo':
            import os
            BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
            
            # entidad_id contiene el nombre del archivo
            backup_path = os.path.join(BACKUP_DIR, entidad_id)
            
            if os.path.exists(backup_path):
                os.remove(backup_path)
                return True, f"Respaldo {entidad_id} eliminado"
            else:
                return False, "Archivo de respaldo no encontrado"
        
        elif tipo_accion == 'modificar_usuario':
            datos_nuevos = json.loads(solicitud['datos_nuevos']) if solicitud['datos_nuevos'] else {}
            
            if datos_nuevos:
                campos = []
                valores = []
                for campo, valor in datos_nuevos.items():
                    if campo not in ['id', 'password_hash', 'password']:
                        campos.append(f"{campo} = ?")
                        valores.append(valor)
                
                if campos:
                    valores.append(entidad_id)
                    conn.execute(
                        f"UPDATE usuarios SET {', '.join(campos)} WHERE id = ?",
                        valores
                    )
                    return True, "Usuario modificado exitosamente"
            
            return False, "No hay datos para modificar"
        
        elif tipo_accion == 'modificar_lugar':
            datos_nuevos = json.loads(solicitud['datos_nuevos']) if solicitud['datos_nuevos'] else {}
            
            if datos_nuevos:
                campos = []
                valores = []
                for campo, valor in datos_nuevos.items():
                    if campo not in ['id']:
                        campos.append(f"{campo} = ?")
                        valores.append(valor)
                
                if campos:
                    valores.append(entidad_id)
                    conn.execute(
                        f"UPDATE lugares SET {', '.join(campos)} WHERE id = ?",
                        valores
                    )
                    return True, "Lugar modificado exitosamente"
            
            return False, "No hay datos para modificar"
        
        else:
            return False, f"Tipo de accion no implementado: {tipo_accion}"
    
    except Exception as e:
        return False, f"Error ejecutando accion: {str(e)}"


def obtener_descripcion_accion(tipo_accion):
    """
    Obtiene la descripción legible de un tipo de acción.
    """
    if tipo_accion in ACCIONES_REQUIEREN_APROBACION:
        return ACCIONES_REQUIEREN_APROBACION[tipo_accion]['descripcion']
    return tipo_accion


def es_admin_maestro(rol):
    """Verifica si un rol es Admin Maestro."""
    return rol == 'admin_maestro'


def puede_aprobar(rol):
    """Verifica si un rol puede aprobar solicitudes."""
    return rol == 'admin_maestro'
