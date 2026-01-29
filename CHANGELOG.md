# Historial de Cambios (CHANGELOG)
## Programa de Telemedicina - UTalca / Servicio de Salud del Maule

---

## [1.1.1] - 2026-01-27

### 🔐 Fase CIP: Sistema de Pseudoanonimización de Pacientes

**Objetivo:** Cumplimiento de Ley 19.628, Ley 20.584 y Marco de Ciberseguridad

### Agregado

- **Cifrado AES-256-GCM para RUT de pacientes**
  - Nueva función `cifrar_rut()` en `utils/seguridad.py`
  - Nueva función `descifrar_rut()` en `utils/seguridad.py`
  - Variable de entorno `ENCRYPTION_KEY` en `.env`

- **Código de Identificación de Paciente (CIP)**
  - Nueva función `generar_cip()` - formato `AAA-99999`
  - Nueva función `validar_cip()` - validación de formato
  - Prefijo derivado del nombre de la posta de atención

- **Nueva tabla de base de datos: `mapeo_pacientes`**
  - Almacena relación CIP ↔ RUT cifrado
  - Campos: `cip`, `rut_cifrado`, `rut_hash`, `rut_enmascarado`
  - Trazabilidad con `creado_por_id` y `fecha_creacion`

- **Script de migración: `migrar_rut_a_cip.py`**
  - Migra consultas históricas al nuevo formato
  - Opción `--eliminar-rut` para purgar datos sensibles

- **Documentación técnica**
  - `docs/DOCUMENTACION_TECNICA_CIP.md`
  - `docs/RESPALDO_CLAVES_CONFIDENCIAL.txt`
  - `VERIFICACION_CIP.md`

### Modificado

- **`app.py`**
  - Ruta `/tens/crear-consulta`: genera CIP y cifra RUT
  - Ruta `/iniciar-consulta`: usa CIP como identificador de sala
  - Ruta `/finalizar-consulta`: almacena CIP en historial
  - Ruta `/admin/exportar-historial`: CSV exporta CIP, no RUT
  - Función `init_db()`: nuevas tablas y columnas

- **`utils/seguridad.py`**
  - Agregados imports: `os`, `secrets`, `base64`, `cryptography`
  - Nuevas funciones de cifrado y CIP

- **`utils/__init__.py`**
  - Exporta nuevas funciones: `cifrar_rut`, `descifrar_rut`, `generar_cip`, `validar_cip`

- **Templates HTML**
  - `dashboard_medico.html`: columna "Código de Atención" en lugar de "Paciente (RUT)"
  - `dashboard_tens.html`: nota informativa sobre confidencialidad del RUT
  - `dashboard_admin.html`: historial muestra CIP en lugar de RUT
  - `consulta.html`: etiqueta "Código de Atención" en sala de video

### Eliminado

- **Columnas de base de datos**
  - `consultas.rut_paciente` (contenía RUT en texto plano)
  - `historial_consultas.rut_paciente` (contenía RUT en texto plano)

### Seguridad

- RUT de pacientes ahora cifrado con AES-256-GCM
- Clave de cifrado almacenada en variable de entorno
- Hash SHA-256 para búsquedas sin exponer RUT
- Interfaz de usuario no muestra RUT en ningún momento

### Dependencias

- Agregada: `cryptography` (para AES-256-GCM)

---

## [1.1.0] - 2026-01-XX

### Sistema Base de Telemedicina

- Login por roles (Admin, Médico, TENS)
- Videollamadas con Jitsi Meet
- Sistema de postas/centros de salud
- Historial de consultas
- Respaldos automáticos
- Protección CSRF

---

## Notas de Versión

### Compatibilidad

- Python 3.8+
- SQLite 3.35.0+ (para eliminación de columnas)
- Flask 2.0+

### Migración desde versiones anteriores

Si se actualiza desde una versión anterior a 1.1.1:

1. Hacer respaldo de la base de datos
2. Instalar nueva dependencia: `pip install cryptography`
3. Agregar `ENCRYPTION_KEY` al archivo `.env`
4. Ejecutar: `python migrar_rut_a_cip.py`
5. Verificar funcionamiento
6. Ejecutar: `python migrar_rut_a_cip.py --eliminar-rut`

---

*Mantenido por: Equipo de Telemedicina UTalca*
