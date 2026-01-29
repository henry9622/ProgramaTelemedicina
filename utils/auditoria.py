import json
from .seguridad import obtener_timestamp_chile, generar_checksum_registro
from .database import get_db_connection

def registrar_auditoria(conn, usuario_id, usuario_nombre, usuario_rol, accion, categoria,
                        resultado, mensaje=None, entidad_tipo=None, entidad_id=None,
                        datos_antes=None, datos_despues=None, ip_origen=None, user_agent=None):
    """
    Registra una acción en la tabla de auditoría.
    """
    try:
        fecha = obtener_timestamp_chile()
        
        datos_registro = {
            'usuario_id': usuario_id,
            'usuario_nombre': usuario_nombre,
            'usuario_rol': usuario_rol,
            'accion': accion,
            'categoria': categoria,
            'resultado': resultado,
            'fecha': fecha,
            'mensaje': mensaje,
            'entidad_tipo': entidad_tipo,
            'entidad_id': entidad_id,
        }
        
        checksum = generar_checksum_registro(datos_registro)
        
        conn.execute('''
            INSERT INTO auditoria (
                usuario_id, usuario_nombre, usuario_rol, accion, categoria,
                entidad_tipo, entidad_id, datos_antes, datos_despues,
                ip_origen, user_agent, resultado, mensaje, fecha, checksum
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            usuario_id, usuario_nombre, usuario_rol, accion, categoria,
            entidad_tipo, entidad_id, datos_antes, datos_despues,
            ip_origen, user_agent, resultado, mensaje, fecha, checksum
        ))
        
    except Exception as e:
        print(f"[AUDITORIA] Error al registrar: {e}")

def obtener_auditoria(limite=100, categoria=None, usuario_id=None):
    """
    Obtiene registros de auditoría con filtros opcionales.
    """
    conn = get_db_connection()
    
    query = 'SELECT * FROM auditoria WHERE 1=1'
    params = []
    
    if categoria:
        query += ' AND categoria = ?'
        params.append(categoria)
    
    if usuario_id:
        query += ' AND usuario_id = ?'
        params.append(usuario_id)
    
    query += ' ORDER BY fecha DESC LIMIT ?'
    params.append(limite)
    
    registros = conn.execute(query, params).fetchall()
    conn.close()
    
    return registros
