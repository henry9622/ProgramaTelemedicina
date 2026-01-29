# 🏥 Arquitectura de Sistema Clínico v2.0
## Panel de Administración con Cumplimiento Normativo Chileno

**Fecha:** 2026-01-27  
**Zona Horaria Oficial:** America/Santiago (UTC-3/-4)  
**Normativa Base:** Ley 20.584 (Derechos y Deberes de los Pacientes)

---

## 📋 ÍNDICE

1. [Diagnóstico del Sistema Actual](#1-diagnóstico-del-sistema-actual)
2. [Modelo de Datos Mejorado](#2-modelo-de-datos-mejorado)
3. [Jerarquía de Roles y Permisos](#3-jerarquía-de-roles-y-permisos)
4. [Flujo de Aprobaciones](#4-flujo-de-aprobaciones)
5. [Validación de RUT Chileno](#5-validación-de-rut-chileno)
6. [Sistema de Auditoría](#6-sistema-de-auditoría)
7. [Protección de Datos Base](#7-protección-de-datos-base)
8. [Gestión de Zona Horaria](#8-gestión-de-zona-horaria)
9. [Seguridad de Credenciales](#9-seguridad-de-credenciales)
10. [Plan de Implementación](#10-plan-de-implementación)

---

## 1. DIAGNÓSTICO DEL SISTEMA ACTUAL

### 🔴 Problemas Críticos Identificados

| Área | Problema | Severidad | Riesgo Normativo |
|------|----------|-----------|------------------|
| **Contraseñas** | Almacenadas en texto plano | CRÍTICO | Alto - Ley 19.628 |
| **Timestamps** | Sin zona horaria definida | CRÍTICO | Trazabilidad inválida |
| **Roles** | Sin jerarquía de aprobación | ALTO | Sin segregación de funciones |
| **RUT** | Sin validación de formato/DV | ALTO | Datos inconsistentes |
| **Auditoría** | Inexistente | CRÍTICO | Sin reconstrucción forense |
| **Historial Clínico** | Puede eliminarse | CRÍTICO | Ley 20.584 violada |
| **Datos Base** | Sin protección | ALTO | Eliminación accidental posible |

### 🟡 Problemas Moderados

| Área | Problema |
|------|----------|
| Secret key hardcodeada | Debería estar en variables de entorno |
| SQLite en producción | Considerar migración a PostgreSQL |
| Sin rate limiting | Vulnerable a ataques de fuerza bruta |
| Sin HTTPS forzado | Datos en tránsito sin cifrar |

---

## 2. MODELO DE DATOS MEJORADO

### 2.1 Nueva Estructura de Tablas

```sql
-- ==========================================
-- CONFIGURACIÓN DEL SISTEMA
-- ==========================================

CREATE TABLE configuracion_sistema (
    clave TEXT PRIMARY KEY,
    valor TEXT NOT NULL,
    descripcion TEXT,
    modificable BOOLEAN DEFAULT 1,
    fecha_modificacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- USUARIOS CON JERARQUÍA Y SEGURIDAD
-- ==========================================

CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    rut TEXT UNIQUE NOT NULL,           -- Formato: 12345678-9
    rut_dv TEXT NOT NULL,               -- Dígito verificador validado
    correo TEXT UNIQUE NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('admin_maestro', 'admin', 'medico', 'tens')),
    password_hash TEXT NOT NULL,         -- Bcrypt hash
    es_plantilla BOOLEAN DEFAULT 0,      -- Protegido contra eliminación
    activo BOOLEAN DEFAULT 1,
    ultimo_acceso TIMESTAMP,
    intentos_fallidos INTEGER DEFAULT 0,
    bloqueado_hasta TIMESTAMP,
    creado_por INTEGER,
    fecha_creacion TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    fecha_modificacion TIMESTAMP,
    FOREIGN KEY (creado_por) REFERENCES usuarios(id)
);

-- ==========================================
-- LUGARES (POSTAS) CON PROTECCIÓN
-- ==========================================

CREATE TABLE lugares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre_posta TEXT NOT NULL,
    direccion TEXT NOT NULL,
    codigo_deis TEXT,                    -- Código DEIS del establecimiento
    es_plantilla BOOLEAN DEFAULT 0,      -- Protegido contra eliminación
    activo BOOLEAN DEFAULT 1,
    creado_por INTEGER,
    fecha_creacion TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (creado_por) REFERENCES usuarios(id)
);

-- ==========================================
-- HISTORIAL CLÍNICO (INMUTABLE)
-- ==========================================

CREATE TABLE historial_consultas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_consulta TEXT NOT NULL UNIQUE,
    token_seguridad TEXT NOT NULL,
    rut_paciente_hash TEXT NOT NULL,     -- Hash del RUT, no texto plano
    rut_paciente_masked TEXT NOT NULL,   -- Ejemplo: ****5678-9
    nombre_medico TEXT NOT NULL,
    medico_id INTEGER NOT NULL,
    tens_nombre TEXT NOT NULL,
    tens_id INTEGER NOT NULL,
    nombre_posta TEXT NOT NULL,
    lugar_id INTEGER NOT NULL,
    fecha_inicio TIMESTAMP NOT NULL,
    fecha_fin TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    -- Metadatos de auditoría inmutables
    ip_medico TEXT,
    ip_tens TEXT,
    checksum TEXT NOT NULL,              -- Integridad del registro
    FOREIGN KEY (medico_id) REFERENCES usuarios(id),
    FOREIGN KEY (tens_id) REFERENCES usuarios(id),
    FOREIGN KEY (lugar_id) REFERENCES lugares(id)
);

-- ==========================================
-- SOLICITUDES DE APROBACIÓN
-- ==========================================

CREATE TABLE solicitudes_aprobacion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo_accion TEXT NOT NULL CHECK (tipo_accion IN (
        'eliminar_usuario', 
        'eliminar_lugar', 
        'eliminar_respaldo',
        'modificar_usuario',
        'modificar_lugar',
        'exportar_historial',
        'acceso_historial_completo'
    )),
    entidad_tipo TEXT NOT NULL,          -- 'usuario', 'lugar', 'respaldo', 'historial'
    entidad_id TEXT NOT NULL,            -- ID o nombre del recurso
    datos_originales TEXT,               -- JSON con estado antes del cambio
    datos_nuevos TEXT,                   -- JSON con cambio propuesto
    solicitante_id INTEGER NOT NULL,
    solicitante_rol TEXT NOT NULL,
    justificacion TEXT,
    estado TEXT DEFAULT 'pendiente' CHECK (estado IN ('pendiente', 'aprobada', 'rechazada', 'expirada')),
    aprobador_id INTEGER,
    fecha_solicitud TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    fecha_resolucion TIMESTAMP,
    motivo_resolucion TEXT,
    FOREIGN KEY (solicitante_id) REFERENCES usuarios(id),
    FOREIGN KEY (aprobador_id) REFERENCES usuarios(id)
);

-- ==========================================
-- LOG DE AUDITORÍA (APPEND-ONLY)
-- ==========================================

CREATE TABLE auditoria (
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
    datos_antes TEXT,                    -- JSON del estado anterior
    datos_despues TEXT,                  -- JSON del estado nuevo
    ip_origen TEXT,
    user_agent TEXT,
    resultado TEXT NOT NULL CHECK (resultado IN ('exito', 'error', 'denegado', 'pendiente')),
    mensaje TEXT,
    fecha TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    checksum TEXT NOT NULL               -- Hash para verificar integridad
);

-- ==========================================
-- SESIONES ACTIVAS
-- ==========================================

CREATE TABLE sesiones_activas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    token_sesion TEXT UNIQUE NOT NULL,
    ip_origen TEXT,
    user_agent TEXT,
    fecha_inicio TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    fecha_expiracion TIMESTAMP NOT NULL,
    activa BOOLEAN DEFAULT 1,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

-- ==========================================
-- RESPALDOS CON METADATOS
-- ==========================================

CREATE TABLE respaldos_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre_archivo TEXT UNIQUE NOT NULL,
    tipo TEXT NOT NULL CHECK (tipo IN ('auto', 'manual', 'inicial')),
    tamaño_bytes INTEGER NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    creado_por INTEGER,
    fecha_creacion TIMESTAMP DEFAULT (datetime('now', 'localtime')),
    eliminado BOOLEAN DEFAULT 0,
    eliminado_por INTEGER,
    fecha_eliminacion TIMESTAMP,
    FOREIGN KEY (creado_por) REFERENCES usuarios(id),
    FOREIGN KEY (eliminado_por) REFERENCES usuarios(id)
);
```

---

## 3. JERARQUÍA DE ROLES Y PERMISOS

### 3.1 Matriz de Roles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JERARQUÍA DE ROLES                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────┐                                                   │
│  │  ADMIN MAESTRO       │ ← Autoridad máxima del sistema                   │
│  │  (1 por sistema)     │   • Aprueba/rechaza solicitudes                  │
│  │                      │   • Crea otros administradores                   │
│  │                      │   • Acceso a auditoría completa                  │
│  │                      │   • Gestión de datos plantilla                   │
│  └──────────┬───────────┘                                                   │
│             │                                                               │
│             │ Aprueba                                                       │
│             ▼                                                               │
│  ┌──────────────────────┐                                                   │
│  │  ADMIN REGULAR       │ ← Gestión operativa                              │
│  │  (múltiples)         │   • CRUD usuarios (requiere aprobación)          │
│  │                      │   • CRUD lugares (requiere aprobación)           │
│  │                      │   • Gestión de respaldos (requiere aprobación)   │
│  │                      │   • Ver historial (auditado)                     │
│  └──────────┬───────────┘                                                   │
│             │                                                               │
│             │ Gestiona                                                      │
│             ▼                                                               │
│  ┌──────────────────────┐  ┌──────────────────────┐                        │
│  │  MÉDICO              │  │  TENS                │                        │
│  │                      │  │                      │                        │
│  │  • Ver consultas     │  │  • Crear consultas   │                        │
│  │  • Atender pacientes │  │  • Acompañar en sala │                        │
│  │  • Finalizar consult │  │  • Ver sus consultas │                        │
│  └──────────────────────┘  └──────────────────────┘                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Matriz de Permisos Detallada

| Acción | Admin Maestro | Admin Regular | Médico | TENS |
|--------|:-------------:|:-------------:|:------:|:----:|
| **USUARIOS** |
| Ver lista de usuarios | ✅ | ✅ | ❌ | ❌ |
| Crear usuario | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| Modificar usuario | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| Eliminar usuario | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| Cambiar contraseña propia | ✅ | ✅ | ✅ | ✅ |
| Cambiar contraseña otros | ❌ | ❌ | ❌ | ❌ |
| **LUGARES** |
| Ver lugares | ✅ | ✅ | ✅ | ✅ |
| Crear lugar | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| Modificar lugar | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| Eliminar lugar | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| **HISTORIAL CLÍNICO** |
| Ver historial | ✅ Auditado | ✅ Auditado | Solo propias | Solo propias |
| Exportar historial | ✅ Directo | 📋 Solicitud | ❌ | ❌ |
| Eliminar historial | ❌ Prohibido | ❌ Prohibido | ❌ | ❌ |
| **RESPALDOS** |
| Ver respaldos | ✅ | ✅ | ❌ | ❌ |
| Crear respaldo | ✅ Directo | ✅ Directo | ❌ | ❌ |
| Descargar respaldo | ✅ Directo | ✅ Auditado | ❌ | ❌ |
| Eliminar respaldo | ✅ + Reauth | 📋 Solicitud | ❌ | ❌ |
| **AUDITORÍA** |
| Ver logs completos | ✅ | ❌ | ❌ | ❌ |
| Ver logs propios | ✅ | ✅ | ✅ | ✅ |
| **APROBACIONES** |
| Ver solicitudes | ✅ | Solo propias | ❌ | ❌ |
| Aprobar/Rechazar | ✅ | ❌ | ❌ | ❌ |

**Leyenda:**
- ✅ Directo: Ejecución inmediata
- 📋 Solicitud: Requiere aprobación de Admin Maestro
- ✅ Auditado: Se registra cada acceso
- ✅ + Reauth: Requiere reautenticación

---

## 4. FLUJO DE APROBACIONES

### 4.1 Diagrama de Flujo

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    FLUJO DE SOLICITUD DE APROBACIÓN                        │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Admin Regular                                                             │
│       │                                                                    │
│       ▼                                                                    │
│  ┌─────────────────┐                                                       │
│  │ Solicita acción │ (ej: eliminar usuario)                               │
│  │ sensible        │                                                       │
│  └────────┬────────┘                                                       │
│           │                                                                │
│           ▼                                                                │
│  ┌─────────────────┐                                                       │
│  │ Sistema valida  │ ← Verifica permisos del rol                          │
│  │ y registra      │ ← Guarda en tabla solicitudes_aprobacion             │
│  │ solicitud       │ ← Registra en auditoría (estado: pendiente)          │
│  └────────┬────────┘                                                       │
│           │                                                                │
│           ▼                                                                │
│  ┌─────────────────┐                                                       │
│  │ Notificación a  │ ← Badge en dashboard del Admin Maestro               │
│  │ Admin Maestro   │ ← (Opcional: email/notificación)                     │
│  └────────┬────────┘                                                       │
│           │                                                                │
│           ▼                                                                │
│  ┌─────────────────┐                                                       │
│  │ Admin Maestro   │                                                       │
│  │ revisa          │                                                       │
│  └────────┬────────┘                                                       │
│           │                                                                │
│     ┌─────┴─────┐                                                          │
│     ▼           ▼                                                          │
│  ┌──────┐   ┌──────────┐                                                   │
│  │APRUEBA│   │ RECHAZA  │                                                  │
│  └───┬───┘   └────┬─────┘                                                  │
│      │            │                                                        │
│      ▼            ▼                                                        │
│  ┌──────────┐  ┌──────────────┐                                            │
│  │Ejecuta   │  │Notifica al   │                                            │
│  │acción    │  │solicitante   │                                            │
│  └────┬─────┘  └──────────────┘                                            │
│       │                                                                    │
│       ▼                                                                    │
│  ┌─────────────────┐                                                       │
│  │ Registro en     │ ← Auditoría completa                                 │
│  │ auditoría       │ ← Quién solicitó, quién aprobó, cuándo               │
│  └─────────────────┘                                                       │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Estados de Solicitud

| Estado | Descripción | Tiempo Límite |
|--------|-------------|---------------|
| `pendiente` | Esperando revisión | 72 horas |
| `aprobada` | Ejecutada por Admin Maestro | - |
| `rechazada` | Denegada con justificación | - |
| `expirada` | Sin respuesta en 72h | Automático |

---

## 5. VALIDACIÓN DE RUT CHILENO

### 5.1 Algoritmo de Validación

```python
def validar_rut_chileno(rut: str) -> tuple[bool, str, str]:
    """
    Valida RUT chileno y retorna (válido, número, dígito verificador).
    
    Formatos aceptados:
    - 12.345.678-9
    - 12345678-9
    - 123456789
    
    Retorna:
    - (True, "12345678", "9") si es válido
    - (False, None, None) si es inválido
    """
    import re
    
    # Limpiar entrada
    rut_limpio = re.sub(r'[.\-\s]', '', rut.upper())
    
    if len(rut_limpio) < 2:
        return False, None, None
    
    # Separar número y DV
    numero = rut_limpio[:-1]
    dv_ingresado = rut_limpio[-1]
    
    # Validar que el número sea numérico
    if not numero.isdigit():
        return False, None, None
    
    # Calcular dígito verificador
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
    
    # Comparar
    if dv_calculado == dv_ingresado:
        return True, numero, dv_ingresado
    
    return False, None, None


def formatear_rut(numero: str, dv: str) -> str:
    """Formatea RUT con puntos y guión: 12.345.678-9"""
    numero_formateado = '{:,}'.format(int(numero)).replace(',', '.')
    return f"{numero_formateado}-{dv}"


def enmascarar_rut(numero: str, dv: str) -> str:
    """Enmascara RUT para display: ****5678-9"""
    if len(numero) > 4:
        return f"****{numero[-4:]}-{dv}"
    return f"****-{dv}"


def hashear_rut(numero: str, dv: str, salt: str) -> str:
    """Genera hash seguro del RUT para almacenamiento"""
    import hashlib
    rut_completo = f"{numero}{dv}{salt}"
    return hashlib.sha256(rut_completo.encode()).hexdigest()
```

### 5.2 Reglas de Manejo de RUT

| Contexto | Tratamiento |
|----------|-------------|
| **Formularios de entrada** | Validación en frontend + backend obligatoria |
| **Base de datos (usuarios)** | Almacenar formateado: `12345678-9` |
| **Base de datos (historial)** | Almacenar hash + versión enmascarada |
| **Logs de auditoría** | Solo versión enmascarada o hash |
| **Exportaciones CSV** | RUT completo solo con permiso explícito |
| **API responses** | Nunca exponer RUT completo sin necesidad |

---

## 6. SISTEMA DE AUDITORÍA

### 6.1 Eventos a Registrar (Obligatorios)

#### Autenticación
- `login_exitoso` - Inicio de sesión correcto
- `login_fallido` - Intento fallido (con IP)
- `logout` - Cierre de sesión
- `sesion_expirada` - Timeout automático
- `cuenta_bloqueada` - Bloqueo por intentos fallidos

#### Gestión de Usuarios
- `usuario_creado` - Nuevo usuario registrado
- `usuario_modificado` - Datos de usuario cambiados
- `usuario_eliminado` - Usuario eliminado (soft delete recomendado)
- `usuario_desactivado` - Usuario deshabilitado
- `password_cambiado` - Cambio de contraseña propia

#### Gestión de Lugares
- `lugar_creado` - Nueva posta registrada
- `lugar_modificado` - Datos de posta cambiados
- `lugar_eliminado` - Posta eliminada

#### Consultas Clínicas
- `consulta_creada` - TENS crea consulta
- `consulta_iniciada` - Médico entra a videollamada
- `consulta_finalizada` - Médico cierra consulta

#### Historial Clínico
- `historial_consultado` - Acceso a lista de historial
- `historial_detalle_visto` - Acceso a consulta específica
- `historial_exportado` - Exportación a CSV

#### Respaldos
- `respaldo_creado` - Nuevo backup generado
- `respaldo_descargado` - Backup descargado
- `respaldo_eliminado` - Backup removido

#### Solicitudes de Aprobación
- `solicitud_creada` - Admin regular solicita acción
- `solicitud_aprobada` - Admin maestro aprueba
- `solicitud_rechazada` - Admin maestro rechaza
- `solicitud_expirada` - Sin respuesta en tiempo límite

### 6.2 Estructura del Registro de Auditoría

```python
registro_auditoria = {
    "id": 12345,
    "fecha": "2026-01-27T11:15:30-03:00",  # ISO 8601 con zona horaria Chile
    "usuario_id": 2,
    "usuario_nombre": "Dr. Juan Pérez",
    "usuario_rol": "admin",
    "categoria": "usuarios",
    "accion": "usuario_eliminado",
    "entidad_tipo": "usuario",
    "entidad_id": "15",
    "datos_antes": {
        "nombre": "María González",
        "rol": "tens",
        "rut_masked": "****4567-8"
    },
    "datos_despues": None,
    "ip_origen": "192.168.1.100",
    "user_agent": "Mozilla/5.0 ...",
    "resultado": "pendiente",  # Requiere aprobación
    "mensaje": "Solicitud de eliminación enviada a Admin Maestro",
    "checksum": "a1b2c3d4..."  # SHA256 del registro
}
```

### 6.3 Integridad de Logs

```python
def generar_checksum_auditoria(registro: dict) -> str:
    """Genera checksum para verificar integridad del registro"""
    import hashlib
    import json
    
    # Excluir el propio checksum si existe
    datos = {k: v for k, v in registro.items() if k != 'checksum'}
    
    # Ordenar claves para consistencia
    contenido = json.dumps(datos, sort_keys=True, default=str)
    
    return hashlib.sha256(contenido.encode()).hexdigest()


def verificar_integridad_auditoria(registro: dict) -> bool:
    """Verifica que un registro no ha sido alterado"""
    checksum_guardado = registro.get('checksum')
    checksum_calculado = generar_checksum_auditoria(registro)
    return checksum_guardado == checksum_calculado
```

---

## 7. PROTECCIÓN DE DATOS BASE (PLANTILLAS)

### 7.1 Concepto de Datos Plantilla

Los **datos plantilla** son registros protegidos que:
- No pueden eliminarse desde la interfaz
- Solo pueden modificarse por Admin Maestro
- Sirven como respaldo ante errores humanos
- Garantizan funcionamiento mínimo del sistema

### 7.2 Datos Plantilla Recomendados

#### Usuarios Plantilla
```sql
INSERT INTO usuarios (nombre, rut, correo, rol, password_hash, es_plantilla)
VALUES 
('Administrador Maestro', '1-9', 'admin.maestro@clinica.cl', 'admin_maestro', '$2b$...', 1);
```

#### Lugares Plantilla
```sql
INSERT INTO lugares (nombre_posta, direccion, codigo_deis, es_plantilla)
VALUES 
('Posta Central (Respaldo)', 'Dirección por definir', 'RESP-001', 1),
('Centro de Referencia', 'Dirección por definir', 'RESP-002', 1);
```

### 7.3 Lógica de Protección en Backend

```python
def puede_eliminar_entidad(entidad_tipo: str, entidad_id: int, usuario_rol: str) -> tuple[bool, str]:
    """
    Verifica si una entidad puede ser eliminada.
    
    Retorna: (puede_eliminar, motivo)
    """
    conn = get_db_connection()
    
    if entidad_tipo == 'usuario':
        usuario = conn.execute(
            'SELECT es_plantilla, rol FROM usuarios WHERE id = ?', 
            (entidad_id,)
        ).fetchone()
        
        if not usuario:
            return False, "Usuario no existe"
        
        if usuario['es_plantilla']:
            return False, "Este usuario es una plantilla protegida del sistema"
        
        if usuario['rol'] == 'admin_maestro':
            return False, "No se puede eliminar al Administrador Maestro"
        
        # Admin regular necesita aprobación
        if usuario_rol == 'admin':
            return False, "REQUIERE_APROBACION"
    
    elif entidad_tipo == 'lugar':
        lugar = conn.execute(
            'SELECT es_plantilla FROM lugares WHERE id = ?', 
            (entidad_id,)
        ).fetchone()
        
        if not lugar:
            return False, "Lugar no existe"
        
        if lugar['es_plantilla']:
            return False, "Esta posta es una plantilla protegida del sistema"
        
        if usuario_rol == 'admin':
            return False, "REQUIERE_APROBACION"
    
    conn.close()
    return True, "OK"
```

---

## 8. GESTIÓN DE ZONA HORARIA

### 8.1 Configuración Backend (Python)

```python
import pytz
from datetime import datetime

# Zona horaria oficial de Chile
TIMEZONE_CHILE = pytz.timezone('America/Santiago')

def obtener_fecha_hora_chile() -> datetime:
    """Retorna fecha/hora actual en zona horaria de Chile"""
    return datetime.now(TIMEZONE_CHILE)

def formatear_fecha_chile(dt: datetime) -> str:
    """Formatea datetime a ISO 8601 con zona horaria"""
    if dt.tzinfo is None:
        dt = TIMEZONE_CHILE.localize(dt)
    return dt.isoformat()

def formatear_fecha_display(dt: datetime) -> str:
    """Formatea para mostrar en interfaz: 27/01/2026 11:15"""
    if dt.tzinfo is None:
        dt = TIMEZONE_CHILE.localize(dt)
    return dt.strftime('%d/%m/%Y %H:%M')

# Configuración SQLite para zona horaria local
def get_db_connection():
    conn = sqlite3.connect('telemedicina.db')
    conn.row_factory = sqlite3.Row
    # Usar hora local en lugar de UTC
    conn.execute("PRAGMA timezone = 'America/Santiago'")
    return conn
```

### 8.2 Configuración Frontend (JavaScript)

```javascript
// Configuración global de zona horaria
const TIMEZONE_CHILE = 'America/Santiago';

function formatearFechaChile(fechaISO) {
    const fecha = new Date(fechaISO);
    return fecha.toLocaleString('es-CL', {
        timeZone: TIMEZONE_CHILE,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function obtenerFechaHoraChileActual() {
    return new Date().toLocaleString('es-CL', {
        timeZone: TIMEZONE_CHILE
    });
}
```

### 8.3 Validación de Consistencia

```python
def validar_timestamp_chile(fecha_str: str) -> bool:
    """Verifica que un timestamp tenga zona horaria de Chile"""
    try:
        dt = datetime.fromisoformat(fecha_str)
        # Verificar que tenga offset de Chile (-03:00 o -04:00)
        if dt.tzinfo is None:
            return False
        offset_hours = dt.utcoffset().total_seconds() / 3600
        return offset_hours in [-3, -4]  # Chile usa -3 (verano) o -4 (invierno)
    except:
        return False
```

---

## 9. SEGURIDAD DE CREDENCIALES

### 9.1 Hashing de Contraseñas

```python
from werkzeug.security import generate_password_hash, check_password_hash

def hashear_password(password: str) -> str:
    """Genera hash seguro de contraseña usando PBKDF2"""
    return generate_password_hash(password, method='pbkdf2:sha256:260000')

def verificar_password(password: str, hash_guardado: str) -> bool:
    """Verifica contraseña contra hash almacenado"""
    return check_password_hash(hash_guardado, password)

# Política de contraseñas
def validar_politica_password(password: str) -> tuple[bool, str]:
    """
    Valida política de contraseñas:
    - Mínimo 8 caracteres
    - Al menos 1 mayúscula
    - Al menos 1 minúscula
    - Al menos 1 número
    """
    import re
    
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una mayúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una minúscula"
    
    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número"
    
    return True, "OK"
```

### 9.2 Reautenticación para Acciones Críticas

```python
def requiere_reautenticacion(accion: str) -> bool:
    """Define qué acciones requieren verificación de contraseña"""
    acciones_criticas = [
        'eliminar_respaldo',
        'eliminar_usuario_permanente',
        'cambiar_password_propio',
        'exportar_historial_completo',
        'acceso_auditoria_completa'
    ]
    return accion in acciones_criticas

@app.route('/api/verificar-password', methods=['POST'])
def verificar_password_actual():
    """Endpoint para reautenticación"""
    password = request.form.get('password')
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    usuario = conn.execute(
        'SELECT password_hash FROM usuarios WHERE id = ?', 
        (user_id,)
    ).fetchone()
    conn.close()
    
    if usuario and verificar_password(password, usuario['password_hash']):
        # Generar token temporal de reautenticación (válido 5 minutos)
        token = generar_token_reauth(user_id)
        return jsonify({'success': True, 'reauth_token': token})
    
    registrar_auditoria(
        usuario_id=user_id,
        accion='reautenticacion_fallida',
        categoria='seguridad',
        resultado='error'
    )
    
    return jsonify({'success': False, 'error': 'Contraseña incorrecta'}), 401
```

---

## 10. PLAN DE IMPLEMENTACIÓN

### 10.1 Fases de Desarrollo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PLAN DE IMPLEMENTACIÓN                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  FASE 1: FUNDAMENTOS DE SEGURIDAD (Prioridad CRÍTICA)                      │
│  ────────────────────────────────────────────────────                       │
│  □ Migrar contraseñas a hash (bcrypt/PBKDF2)                               │
│  □ Implementar validación de RUT chileno                                   │
│  □ Configurar zona horaria Chile en todo el sistema                        │
│  □ Crear tabla de auditoría                                                │
│  □ Implementar logging básico de acciones                                  │
│  Tiempo estimado: 2-3 días                                                 │
│                                                                             │
│  FASE 2: JERARQUÍA DE ROLES                                                │
│  ───────────────────────────                                               │
│  □ Agregar rol 'admin_maestro' al sistema                                  │
│  □ Crear tabla de solicitudes de aprobación                                │
│  □ Implementar flujo de solicitud/aprobación                               │
│  □ Modificar UI para mostrar solicitudes pendientes                        │
│  □ Bloquear acciones directas para admin regular                           │
│  Tiempo estimado: 3-4 días                                                 │
│                                                                             │
│  FASE 3: PROTECCIÓN DE DATOS                                               │
│  ───────────────────────────                                               │
│  □ Agregar campo 'es_plantilla' a tablas                                   │
│  □ Crear datos plantilla iniciales                                         │
│  □ Implementar lógica de protección en backend                             │
│  □ Bloquear eliminación de historial clínico                               │
│  □ Enmascarar RUT en logs y exports                                        │
│  Tiempo estimado: 2-3 días                                                 │
│                                                                             │
│  FASE 4: AUDITORÍA COMPLETA                                                │
│  ──────────────────────────                                                │
│  □ Implementar registro de todas las acciones                              │
│  □ Agregar checksums a registros de auditoría                              │
│  □ Crear interfaz de visualización de logs (solo admin maestro)            │
│  □ Implementar exportación de logs                                         │
│  □ Agregar verificación de integridad                                      │
│  Tiempo estimado: 3-4 días                                                 │
│                                                                             │
│  FASE 5: MEJORAS DE SEGURIDAD ADICIONALES                                  │
│  ─────────────────────────────────────────                                 │
│  □ Implementar reautenticación para acciones críticas                      │
│  □ Agregar bloqueo por intentos fallidos                                   │
│  □ Implementar política de contraseñas                                     │
│  □ Agregar gestión de sesiones activas                                     │
│  □ Configurar variables de entorno para secrets                            │
│  Tiempo estimado: 2-3 días                                                 │
│                                                                             │
│  TOTAL ESTIMADO: 12-17 días de desarrollo                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Checklist de Cumplimiento Ley 20.584

| Requisito | Estado Actual | Estado Objetivo | Fase |
|-----------|:-------------:|:---------------:|:----:|
| Acceso restringido a ficha clínica | ⚠️ Parcial | ✅ | 3 |
| Trazabilidad de accesos | ❌ | ✅ | 4 |
| Derecho a información | ⚠️ Parcial | ✅ | 3 |
| Confidencialidad | ⚠️ Parcial | ✅ | 1, 3 |
| Consentimiento informado | ✅ | ✅ | - |
| Identificación de personal | ⚠️ Sin validar | ✅ | 1 |

---

## PRÓXIMOS PASOS RECOMENDADOS

1. **Inmediato (Hoy)**: Migrar contraseñas a hash
2. **Esta semana**: Implementar validación RUT y auditoría básica
3. **Próxima semana**: Jerarquía de roles y sistema de aprobaciones
4. **Siguiente**: Protección de datos y auditoría completa

¿Desea proceder con la implementación de alguna fase específica?
