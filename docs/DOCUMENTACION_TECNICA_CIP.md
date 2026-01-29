# ══════════════════════════════════════════════════════════════════════════════
# DOCUMENTACIÓN TÉCNICA: SISTEMA DE PSEUDOANONIMIZACIÓN DE PACIENTES (CIP)
# ══════════════════════════════════════════════════════════════════════════════
# Programa de Telemedicina - Universidad de Talca / Servicio de Salud del Maule
# Versión: 1.1 + Fase CIP
# Fecha de implementación: 27 de enero de 2026
# ══════════════════════════════════════════════════════════════════════════════

## 1. RESUMEN EJECUTIVO

Este documento describe la implementación del sistema de Código de Identificación 
de Paciente (CIP), diseñado para cumplir con la normativa chilena de protección 
de datos personales y confidencialidad de la información clínica.

### Objetivo
Eliminar la exposición del RUT de pacientes en la interfaz del sistema, 
reemplazándolo por un identificador pseudoanónimo que permite la trazabilidad 
interna sin comprometer la privacidad del paciente.

### Cumplimiento Normativo

| Normativa | Artículo/Principio | Implementación |
|-----------|-------------------|----------------|
| Ley N.º 19.628 | Art. 4 - Datos personales solo para fines autorizados | RUT solo visible por personal autorizado |
| Ley N.º 20.584 | Art. 12 - Reserva de información clínica | Identificador no contiene datos del paciente |
| Ley Marco de Ciberseguridad | Cifrado de datos sensibles | AES-256-GCM para almacenamiento |
| Normativa MINSAL Telemedicina | Protección en transmisión | CIP usado como identificador de sala |

---

## 2. ARQUITECTURA DEL SISTEMA

### 2.1 Flujo de Datos

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FLUJO DE CREACIÓN DE CONSULTA                        │
└─────────────────────────────────────────────────────────────────────────────┘

   TENS                    SISTEMA                         BASE DE DATOS
    │                         │                                  │
    │  1. Ingresa RUT         │                                  │
    │ ────────────────────────>                                  │
    │                         │                                  │
    │                   2. Valida RUT                            │
    │                   (Módulo 11)                              │
    │                         │                                  │
    │                   3. Genera CIP                            │
    │                   (AAA-99999)                              │
    │                         │                                  │
    │                   4. Cifra RUT                             │
    │                   (AES-256-GCM)                            │
    │                         │                                  │
    │                         │  5. Almacena mapeo               │
    │                         │ ─────────────────────────────────>
    │                         │     mapeo_pacientes:             │
    │                         │     - cip                        │
    │                         │     - rut_cifrado                │
    │                         │     - rut_hash                   │
    │                         │                                  │
    │                         │  6. Crea consulta                │
    │                         │ ─────────────────────────────────>
    │                         │     consultas:                   │
    │                         │     - cip (visible)              │
    │                         │     - rut_paciente_hash          │
    │                         │                                  │
    │  7. Muestra CIP         │                                  │
    │ <────────────────────────                                  │
    │  (RUT NUNCA visible)    │                                  │
```

### 2.2 Componentes Modificados

```
ProgramaTelemedicina/
├── app.py                      # Rutas principales (modificado)
├── .env                        # Variables de entorno (+ ENCRYPTION_KEY)
├── utils/
│   ├── __init__.py            # Exports (modificado)
│   └── seguridad.py           # Módulo de seguridad (+ cifrado + CIP)
├── templates/
│   ├── dashboard_tens.html    # Formulario TENS (modificado)
│   ├── dashboard_medico.html  # Lista de espera (modificado)
│   ├── dashboard_admin.html   # Historial (modificado)
│   └── consulta.html          # Sala de videollamada (modificado)
├── migrar_rut_a_cip.py        # Script de migración (nuevo)
└── VERIFICACION_CIP.md        # Documento de verificación (nuevo)
```

---

## 3. ESPECIFICACIONES TÉCNICAS

### 3.1 Código de Identificación de Paciente (CIP)

**Formato:** `AAA-99999`

| Componente | Descripción | Ejemplo |
|------------|-------------|---------|
| `AAA` | 3 primeras letras del nombre de la posta (mayúsculas) | `POS`, `COL`, `SAN` |
| `-` | Separador fijo | `-` |
| `99999` | 5 dígitos aleatorios criptográficamente seguros | `47821` |

**Ejemplo completo:** `COL-47821` (Posta Colín, paciente #47821)

**Generación:**
```python
import secrets
def generar_cip(codigo_posta):
    prefijo = codigo_posta[:3].upper().ljust(3, 'X')
    sufijo = secrets.randbelow(100000)
    return f"{prefijo}-{sufijo:05d}"
```

**Unicidad:** El sistema verifica que el CIP no exista antes de asignarlo.

### 3.2 Cifrado AES-256-GCM

**Algoritmo:** AES (Advanced Encryption Standard)
**Modo:** GCM (Galois/Counter Mode) - proporciona autenticación
**Tamaño de clave:** 256 bits (32 bytes)
**Tamaño de nonce:** 96 bits (12 bytes) - único por cada cifrado

**Estructura del dato cifrado:**
```
┌────────────┬─────────────────────────────┬──────────────┐
│  Nonce     │       Ciphertext            │   Auth Tag   │
│ (12 bytes) │    (tamaño variable)        │  (16 bytes)  │
└────────────┴─────────────────────────────┴──────────────┘
                        │
                        ▼
            Codificado en Base64 para almacenamiento
```

**Propiedades de seguridad:**
- **Confidencialidad:** El RUT no puede leerse sin la clave
- **Integridad:** GCM detecta cualquier modificación del dato
- **No determinístico:** El mismo RUT produce diferentes cifrados (por el nonce aleatorio)

### 3.3 Hash SHA-256

**Uso:** Búsqueda de pacientes sin exponer el RUT
**Algoritmo:** SHA-256 con salt fijo
**Salt:** `telemedicina_utalca_2026`

```python
def hashear_rut(rut):
    datos = f"{rut_normalizado}telemedicina_utalca_2026"
    return hashlib.sha256(datos.encode()).hexdigest()
```

---

## 4. ESQUEMA DE BASE DE DATOS

### 4.1 Nueva tabla: `mapeo_pacientes`

```sql
CREATE TABLE mapeo_pacientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cip TEXT UNIQUE NOT NULL,           -- Código de Identificación de Paciente
    rut_cifrado TEXT NOT NULL,          -- RUT cifrado con AES-256-GCM (base64)
    rut_hash TEXT NOT NULL,             -- Hash SHA-256 del RUT (para búsquedas)
    rut_enmascarado TEXT NOT NULL,      -- RUT visible parcialmente: ****5678-9
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    creado_por_id INTEGER,              -- ID del TENS que creó el registro
    FOREIGN KEY (creado_por_id) REFERENCES usuarios (id)
);
```

### 4.2 Tabla modificada: `consultas`

```sql
-- Columnas eliminadas:
--   rut_paciente TEXT     (contenía RUT en texto plano)

-- Columnas agregadas:
--   cip TEXT NOT NULL                 -- Referencia al CIP del paciente
--   rut_paciente_hash TEXT NOT NULL   -- Hash para validación
```

### 4.3 Tabla modificada: `historial_consultas`

```sql
-- Columnas eliminadas:
--   rut_paciente TEXT     (contenía RUT en texto plano)

-- Columnas agregadas:
--   cip TEXT NOT NULL                      -- CIP del paciente
--   rut_paciente_cifrado TEXT NOT NULL     -- RUT cifrado (trazabilidad)
--   rut_paciente_hash TEXT NOT NULL        -- Hash para validación
```

---

## 5. FUNCIONES IMPLEMENTADAS

### 5.1 Módulo `utils/seguridad.py`

| Función | Descripción | Parámetros | Retorno |
|---------|-------------|------------|---------|
| `cifrar_rut(rut)` | Cifra un RUT con AES-256-GCM | RUT en cualquier formato | String base64 |
| `descifrar_rut(rut_cifrado)` | Descifra un RUT | String base64 | RUT normalizado |
| `generar_cip(codigo_posta)` | Genera CIP único | Nombre de posta | String `AAA-99999` |
| `validar_cip(cip)` | Valida formato CIP | String | Boolean |
| `hashear_rut(rut)` | Genera hash SHA-256 | RUT | String hex 64 chars |
| `enmascarar_rut(rut)` | Enmascara RUT para display | RUT | String `****5678-9` |

### 5.2 Rutas Modificadas en `app.py`

| Ruta | Método | Cambio |
|------|--------|--------|
| `/tens/crear-consulta` | POST | Genera CIP, cifra RUT, almacena en mapeo |
| `/iniciar-consulta` | POST | Usa CIP como identificador de sala |
| `/finalizar-consulta` | POST | Almacena CIP y RUT cifrado en historial |
| `/admin/exportar-historial` | GET | CSV exporta CIP, no RUT |

---

## 6. GUÍA DE OPERACIONES

### 6.1 Recuperar RUT de un CIP (Solo Admin Maestro)

```python
from utils.seguridad import descifrar_rut
import sqlite3

def recuperar_rut(cip):
    conn = sqlite3.connect('telemedicina.db')
    cursor = conn.cursor()
    
    resultado = cursor.execute(
        'SELECT rut_cifrado FROM mapeo_pacientes WHERE cip = ?', 
        (cip,)
    ).fetchone()
    
    if resultado:
        rut = descifrar_rut(resultado[0])
        return rut
    return None

# Ejemplo:
# rut = recuperar_rut('COL-47821')
# print(rut)  # 12345678-5
```

### 6.2 Buscar Consultas por RUT (Sin exponer el RUT)

```python
from utils.seguridad import hashear_rut

def buscar_consultas_por_rut(rut):
    rut_hash = hashear_rut(rut)
    
    conn = sqlite3.connect('telemedicina.db')
    cursor = conn.cursor()
    
    consultas = cursor.execute('''
        SELECT c.*, m.cip 
        FROM consultas c
        JOIN mapeo_pacientes m ON c.cip = m.cip
        WHERE m.rut_hash = ?
    ''', (rut_hash,)).fetchall()
    
    return consultas
```

### 6.3 Migrar Datos Históricos

```bash
# Migrar sin eliminar columnas antiguas (reversible)
python migrar_rut_a_cip.py

# Migrar y eliminar columnas antiguas (irreversible)
python migrar_rut_a_cip.py --eliminar-rut
```

---

## 7. GESTIÓN DE CLAVES

### 7.1 Clave de Cifrado Actual

> ⚠️ **CONFIDENCIAL - NO COMPARTIR**

```
ENCRYPTION_KEY=/xkx2wDBFT1lxy2ONRTouQmb9wRDFESlWpLvVe/iNms=
```

**Ubicación:** Archivo `.env` en la raíz del proyecto
**Formato:** Base64 de 32 bytes (256 bits)

### 7.2 Procedimiento de Respaldo de Clave

1. **Copiar la clave** a un documento seguro fuera del servidor
2. **Almacenar en caja fuerte física** (recomendado)
3. **Almacenar en gestor de secretos** (ej: HashiCorp Vault)
4. **Nunca enviar por correo electrónico** sin cifrar
5. **Notificar al Oficial de Seguridad** de la existencia del respaldo

### 7.3 Rotación de Claves (Procedimiento Futuro)

Si se requiere rotar la clave de cifrado:

1. Generar nueva clave:
   ```bash
   python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
   ```

2. Descifrar todos los RUT con la clave antigua
3. Re-cifrar todos los RUT con la clave nueva
4. Actualizar `.env` con la nueva clave
5. Eliminar la clave antigua de forma segura

### 7.4 Recuperación ante Pérdida de Clave

> ⚠️ **SI SE PIERDE LA CLAVE DE CIFRADO:**
> - Los RUT cifrados serán **IRRECUPERABLES**
> - Los CIP seguirán funcionando para identificar pacientes
> - La trazabilidad hacia el RUT real se perderá
> - Se requerirá crear nuevos mapeos manualmente

---

## 8. AUDITORÍA Y TRAZABILIDAD

### 8.1 Eventos Registrados

El sistema registra automáticamente en la tabla `auditoria`:

| Evento | Datos Registrados |
|--------|-------------------|
| Creación de consulta | CIP, usuario TENS, timestamp |
| Inicio de consulta | CIP, usuario médico, timestamp |
| Finalización de consulta | CIP, código de consulta, timestamp |
| Exportación de historial | Usuario admin, timestamp |

### 8.2 Ejemplo de Registro de Auditoría

```json
{
    "id": 123,
    "usuario_id": 5,
    "usuario_nombre": "TENS María González",
    "accion": "crear_consulta",
    "entidad_tipo": "paciente",
    "entidad_id": "COL-47821",
    "resultado": "exito",
    "ip_origen": "192.168.1.100",
    "timestamp": "2026-01-27 16:45:30"
}
```

---

## 9. VERIFICACIÓN DE IMPLEMENTACIÓN

### Lista de Verificación

- [x] Columna `rut_paciente` eliminada de tabla `consultas`
- [x] Columna `rut_paciente` eliminada de tabla `historial_consultas`
- [x] Tabla `mapeo_pacientes` creada y funcional
- [x] Cifrado AES-256-GCM implementado y probado
- [x] Generación de CIP funcionando (formato AAA-99999)
- [x] Dashboard médico muestra CIP en lugar de RUT
- [x] Dashboard TENS muestra nota de confidencialidad
- [x] Sala de consulta muestra "Código de Atención"
- [x] Exportación CSV no contiene RUT
- [x] Clave de cifrado documentada y respaldada

---

## 10. CONTACTO Y SOPORTE

**Desarrollado por:** Equipo de Telemedicina UTalca
**Versión del documento:** 1.0
**Última actualización:** 27 de enero de 2026, 17:09 hrs

Para consultas técnicas sobre el sistema de pseudoanonimización, 
contactar al equipo de desarrollo o al Oficial de Seguridad de la Información.

---

*Este documento contiene información confidencial. Su distribución está 
restringida al personal autorizado del proyecto de Telemedicina.*
