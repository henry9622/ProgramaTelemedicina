# ==========================================
# MÓDULO DE SEGURIDAD - TELEMEDICINA CLÍNICA
# ==========================================
# Cumplimiento: Ley 20.584, Ley 19.628
# Zona Horaria: America/Santiago

import re
import os
import hashlib
import secrets
import pytz
import base64
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================
# CONFIGURACIÓN DE ZONA HORARIA CHILE
# ==========================================
TIMEZONE_CHILE = pytz.timezone('America/Santiago')


def obtener_fecha_hora_chile():
    """Retorna fecha/hora actual en zona horaria de Chile"""
    return datetime.now(TIMEZONE_CHILE)


def formatear_fecha_iso_chile(dt=None):
    """Formatea datetime a ISO 8601 con zona horaria de Chile"""
    if dt is None:
        dt = obtener_fecha_hora_chile()
    elif dt.tzinfo is None:
        dt = TIMEZONE_CHILE.localize(dt)
    return dt.isoformat()


def formatear_fecha_display(dt):
    """Formatea para mostrar en interfaz: 27/01/2026 11:15"""
    if dt is None:
        return "N/A"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except:
            return dt
    if dt.tzinfo is None:
        dt = TIMEZONE_CHILE.localize(dt)
    return dt.strftime('%d/%m/%Y %H:%M')


def obtener_timestamp_chile():
    """Retorna timestamp formateado para BD: 2026-01-27 11:15:30"""
    return obtener_fecha_hora_chile().strftime('%Y-%m-%d %H:%M:%S')


# ==========================================
# HASH DE CONTRASEÑAS
# ==========================================

def hashear_password(password):
    """
    Genera hash seguro de contraseña usando PBKDF2-SHA256.
    Werkzeug usa 260,000 iteraciones por defecto.
    """
    return generate_password_hash(password, method='pbkdf2:sha256:260000')


def verificar_password(password, hash_guardado):
    """Verifica contraseña contra hash almacenado"""
    if not hash_guardado:
        return False
    return check_password_hash(hash_guardado, password)


def validar_politica_password(password):
    """
    Valida política de contraseñas.
    
    Reglas:
    - Mínimo 8 caracteres
    - Al menos 1 mayúscula
    - Al menos 1 minúscula
    - Al menos 1 número
    
    Retorna: (es_valido, mensaje)
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una mayúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una minúscula"
    
    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número"
    
    return True, "Contraseña válida"


# ==========================================
# VALIDACIÓN DE RUT CHILENO
# ==========================================

def validar_rut_chileno(rut):
    """
    Valida RUT chileno completo (formato y dígito verificador).
    
    Formatos aceptados:
    - 12.345.678-9
    - 12345678-9
    - 123456789
    
    Retorna: (es_valido, numero, digito_verificador, mensaje)
    """
    if not rut or not isinstance(rut, str):
        return False, None, None, "RUT no proporcionado"
    
    # Limpiar entrada: remover puntos, guiones, espacios
    rut_limpio = re.sub(r'[.\-\s]', '', rut.upper().strip())
    
    if len(rut_limpio) < 2:
        return False, None, None, "RUT demasiado corto"
    
    if len(rut_limpio) > 9:
        return False, None, None, "RUT demasiado largo"
    
    # Separar número y dígito verificador
    numero = rut_limpio[:-1]
    dv_ingresado = rut_limpio[-1]
    
    # Validar que el número sea numérico
    if not numero.isdigit():
        return False, None, None, "El RUT debe contener solo números"
    
    # Validar que el DV sea número o K
    if dv_ingresado not in '0123456789K':
        return False, None, None, "Dígito verificador inválido"
    
    # Calcular dígito verificador usando algoritmo Módulo 11
    suma = 0
    multiplicador = 2
    
    for digito in reversed(numero):
        suma += int(digito) * multiplicador
        multiplicador = multiplicador + 1 if multiplicador < 7 else 2
    
    resto = suma % 11
    dv_calculado = str(11 - resto)
    
    if dv_calculado == '11':
        dv_calculado = '0'
    elif dv_calculado == '10':
        dv_calculado = 'K'
    
    # Comparar dígito verificador
    if dv_calculado != dv_ingresado:
        return False, None, None, f"Dígito verificador incorrecto. Debería ser {dv_calculado}"
    
    return True, numero, dv_ingresado, "RUT válido"


def formatear_rut(numero, dv):
    """
    Formatea RUT con puntos y guión.
    Ej: 12345678, 9 → 12.345.678-9
    """
    if not numero or not dv:
        return None
    numero_formateado = '{:,}'.format(int(numero)).replace(',', '.')
    return f"{numero_formateado}-{dv}"


def normalizar_rut(rut):
    """
    Normaliza RUT a formato estándar: 12345678-9
    Sin puntos, con guión.
    """
    es_valido, numero, dv, _ = validar_rut_chileno(rut)
    if es_valido:
        return f"{numero}-{dv}"
    return None


def enmascarar_rut(rut):
    """
    Enmascara RUT para display seguro.
    Ej: 12345678-9 → ****5678-9
    """
    es_valido, numero, dv, _ = validar_rut_chileno(rut)
    if not es_valido:
        return "****-*"
    
    if len(numero) > 4:
        return f"****{numero[-4:]}-{dv}"
    return f"****-{dv}"


def hashear_rut(rut, salt="telemedicina_utalca_2026"):
    """
    Genera hash SHA256 del RUT para almacenamiento seguro.
    Usado en historial clínico para no guardar RUT en texto plano.
    """
    rut_normalizado = normalizar_rut(rut)
    if not rut_normalizado:
        return None
    
    datos = f"{rut_normalizado}{salt}"
    return hashlib.sha256(datos.encode()).hexdigest()


# ==========================================
# FUNCIONES DE AUDITORÍA
# ==========================================

def generar_checksum_registro(datos):
    """
    Genera checksum SHA256 para verificar integridad de un registro.
    
    Args:
        datos: diccionario con los datos del registro
    
    Returns:
        str: Hash SHA256 de los datos
    """
    import json
    # Excluir el propio checksum si existe
    datos_limpios = {k: v for k, v in datos.items() if k != 'checksum'}
    # Ordenar claves para consistencia
    contenido = json.dumps(datos_limpios, sort_keys=True, default=str)
    return hashlib.sha256(contenido.encode()).hexdigest()[:32]


def verificar_integridad_registro(datos):
    """
    Verifica que un registro no ha sido alterado.
    
    Returns:
        bool: True si el registro es íntegro
    """
    checksum_guardado = datos.get('checksum')
    if not checksum_guardado:
        return False
    checksum_calculado = generar_checksum_registro(datos)
    return checksum_guardado == checksum_calculado


# ==========================================
# CIFRADO AES-256-GCM PARA DATOS SENSIBLES
# ==========================================
# Cumplimiento: Ley Marco de Ciberseguridad, Ley 19.628

def _obtener_clave_cifrado():
    """
    Obtiene la clave de cifrado desde variables de entorno.
    La clave debe ser de 32 bytes (256 bits) codificada en base64.
    """
    clave_b64 = os.environ.get('ENCRYPTION_KEY')
    if not clave_b64:
        raise ValueError("ENCRYPTION_KEY no configurada en variables de entorno")
    
    try:
        clave = base64.b64decode(clave_b64)
        if len(clave) != 32:
            raise ValueError("ENCRYPTION_KEY debe ser de 32 bytes (256 bits)")
        return clave
    except Exception as e:
        raise ValueError(f"Error al decodificar ENCRYPTION_KEY: {e}")


def cifrar_rut(rut):
    """
    Cifra un RUT usando AES-256-GCM.
    
    Args:
        rut: RUT en cualquier formato válido
    
    Returns:
        str: RUT cifrado en formato base64 (nonce + ciphertext + tag)
        None: Si el RUT es inválido
    """
    rut_normalizado = normalizar_rut(rut)
    if not rut_normalizado:
        return None
    
    try:
        clave = _obtener_clave_cifrado()
        aesgcm = AESGCM(clave)
        
        # Generar nonce único de 12 bytes (96 bits) - recomendado para GCM
        nonce = secrets.token_bytes(12)
        
        # Cifrar el RUT
        ciphertext = aesgcm.encrypt(nonce, rut_normalizado.encode('utf-8'), None)
        
        # Concatenar nonce + ciphertext y codificar en base64
        datos_cifrados = nonce + ciphertext
        return base64.b64encode(datos_cifrados).decode('utf-8')
    
    except Exception as e:
        print(f"[SEGURIDAD] Error cifrando RUT: {e}")
        return None


def descifrar_rut(rut_cifrado):
    """
    Descifra un RUT cifrado con AES-256-GCM.
    
    Args:
        rut_cifrado: RUT cifrado en formato base64
    
    Returns:
        str: RUT descifrado en formato normalizado (12345678-9)
        None: Si hay error de descifrado o integridad
    """
    if not rut_cifrado:
        return None
    
    try:
        clave = _obtener_clave_cifrado()
        aesgcm = AESGCM(clave)
        
        # Decodificar de base64
        datos_cifrados = base64.b64decode(rut_cifrado)
        
        # Separar nonce (12 bytes) y ciphertext
        nonce = datos_cifrados[:12]
        ciphertext = datos_cifrados[12:]
        
        # Descifrar y verificar integridad (GCM hace esto automáticamente)
        rut_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return rut_bytes.decode('utf-8')
    
    except Exception as e:
        print(f"[SEGURIDAD] Error descifrando RUT: {e}")
        return None


# ==========================================
# CÓDIGO DE IDENTIFICACIÓN DE PACIENTE (CIP)
# ==========================================
# Privacy by Design: Identificador pseudoanónimo

def generar_cip(codigo_posta):
    """
    Genera un Código de Identificación de Paciente único.
    
    Formato: AAA-99999
        - AAA: 3 primeras letras del código/nombre de posta (mayúsculas)
        - 99999: 5 dígitos aleatorios criptográficamente seguros
    
    Args:
        codigo_posta: Nombre o código de la posta/centro de salud
    
    Returns:
        str: CIP en formato AAA-99999
    """
    # Limpiar y obtener prefijo de 3 letras
    if not codigo_posta:
        prefijo = "GEN"  # Genérico si no hay posta
    else:
        # Remover tildes y caracteres especiales, tomar primeras 3 letras
        import unicodedata
        texto_limpio = unicodedata.normalize('NFD', codigo_posta)
        texto_limpio = ''.join(c for c in texto_limpio if unicodedata.category(c) != 'Mn')
        texto_limpio = ''.join(c for c in texto_limpio if c.isalpha())
        prefijo = texto_limpio[:3].upper().ljust(3, 'X')
    
    # Generar sufijo numérico aleatorio (criptográficamente seguro)
    sufijo = secrets.randbelow(100000)
    
    return f"{prefijo}-{sufijo:05d}"


def validar_cip(cip):
    """
    Valida el formato de un CIP.
    
    Args:
        cip: Código de Identificación de Paciente
    
    Returns:
        bool: True si el formato es válido
    """
    if not cip or not isinstance(cip, str):
        return False
    return bool(re.match(r'^[A-Z]{3}-\d{5}$', cip))


def generar_clave_cifrado():
    """
    Genera una nueva clave de cifrado AES-256 segura.
    Usar esta función UNA VEZ para generar la clave inicial.
    
    Returns:
        str: Clave de 32 bytes codificada en base64
    """
    clave = secrets.token_bytes(32)
    return base64.b64encode(clave).decode('utf-8')
