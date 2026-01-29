# Módulos de utilidades para Telemedicina Clínica
from .seguridad import (
    # Zona horaria
    TIMEZONE_CHILE,
    obtener_fecha_hora_chile,
    formatear_fecha_iso_chile,
    formatear_fecha_display,
    obtener_timestamp_chile,
    # Contraseñas
    hashear_password,
    verificar_password,
    validar_politica_password,
    # RUT
    validar_rut_chileno,
    formatear_rut,
    normalizar_rut,
    enmascarar_rut,
    hashear_rut,
    # Cifrado AES-256-GCM (Ley 19.628)
    cifrar_rut,
    descifrar_rut,
    # CIP - Código de Identificación de Paciente
    generar_cip,
    validar_cip,
    # Auditoría
    generar_checksum_registro,
    verificar_integridad_registro,
)

from .aprobaciones import (
    # Constantes
    ACCIONES_REQUIEREN_APROBACION,
    # Funciones de verificación
    requiere_aprobacion,
    es_admin_maestro,
    puede_aprobar,
    obtener_descripcion_accion,
    # Gestión de solicitudes
    crear_solicitud,
    obtener_solicitudes_pendientes,
    obtener_solicitudes_usuario,
    contar_solicitudes_pendientes,
    aprobar_solicitud,
    rechazar_solicitud,
)

