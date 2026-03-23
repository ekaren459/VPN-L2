# VPN Capa 2 (Layer 2) — VSwitch & VPort

> Implementación de un switch virtual L2 con cifrado AES-256-GCM, autenticación JWT y persistencia PostgreSQL.
> Proyecto académico — Universidad Santa María · Facultad de Arquitectura e Ingeniería · Ingeniería de Software II

---

## Tabla de contenidos

- [Descripción](#descripción)
- [Arquitectura](#arquitectura)
- [Requisitos](#requisitos)
- [Instalación y ejecución](#instalación-y-ejecución)
- [Uso del panel web](#uso-del-panel-web)
- [Conectar un VPort](#conectar-un-vport)
- [Resolución de errores comunes](#resolución-de-errores-comunes)
- [Estado actual del proyecto](#estado-actual-del-proyecto)
- [Pendiente por implementar](#pendiente-por-implementar)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Base de datos](#base-de-datos)

---

## Descripción

Este proyecto implementa una Red Privada Virtual de Capa 2 (VPN L2) funcional usando exclusivamente herramientas de código abierto. La arquitectura replica el comportamiento de un switch Ethernet físico mediante software:

- **VSwitch** (Python): servidor central que aprende direcciones MAC y reenvía tramas Ethernet entre clientes remotos.
- **VPort** (C): cliente que crea una interfaz TAP virtual en Linux y túnela las tramas hacia el VSwitch via UDP cifrado.
- **Panel Web** (Flask): interfaz de administración con login, visualización de la tabla MAC en tiempo real y registro de sesiones.
- **PostgreSQL**: persistencia de usuarios, tokens JWT, sesiones VPN y tabla MAC dinámica en modelo 3FN.

Toda la comunicación entre VPort y VSwitch viaja cifrada con **AES-256-GCM** y autenticada con **tokens JWT**.

---

## Arquitectura

```
┌─────────────────────────────────────┐
│           VSwitch (Python)          │
│    Puerto UDP 8888 — AES-256-GCM    │
│    Tabla MAC ──→ PostgreSQL         │
│    API REST  ──→ Flask :5000        │
└────────┬──────────────┬─────────────┘
         │ UDP cifrado  │ UDP cifrado
    ┌────┴────┐    ┌────┴────┐
    │ VPort 1 │    │ VPort 2 │
    │  (C)    │    │  (C)    │
    │tapyuan  │    │tapyuan  │
    │10.1.1.101    │10.1.1.102
    └─────────┘    └─────────┘
```

Flujo de un paquete:
1. Kernel Linux → TAP → VPort cifra con AES-256-GCM → UDP → VSwitch
2. VSwitch descifra → aprende MAC origen → consulta MAC destino → re-cifra → UDP → VPort destino
3. VPort destino descifra → inyecta en TAP → Kernel Linux

---

## Requisitos

- **Windows 10/11** con WSL2 habilitado
- **Docker Desktop** con soporte de virtualización activo
- **Git**
- **Puerto 8888/UDP** y **5000/TCP** disponibles

---

## Instalación y ejecución

### 1. Clonar el repositorio

```bash
git clone https://github.com/ekaren459/VPN-L2.git
cd vpn-l2-vswitch/VPN\ USM
```

### 2. Levantar todos los servicios

```bash
docker-compose up --build
```

Deberías ver en los logs:

```
vpn_server | [VSwitch] Hilo iniciado correctamente
vpn_server | [VSwitch] Iniciado en 0.0.0.0:8888 — AES-256-GCM activo
vpn_server | * Running on http://0.0.0.0:5000
vpn_database | database system is ready to accept connections
```

### 3. Crear el usuario admin (solo la primera vez)

```bash
# Entrar al contenedor de base de datos
docker exec -it vpn_database bash
psql -U vpnuser -d vpnl2
```

Dentro de PostgreSQL:

```sql
-- Generar primero el hash desde el servidor:
-- (en otra terminal) docker exec vpn_server python3 -c "import bcrypt; print(bcrypt.hashpw(b'admin123', bcrypt.gensalt(12)).decode())"

UPDATE T_Usuarios
SET password_hash = 'PEGA_EL_HASH_AQUI'
WHERE nombre_usuario = 'admin';

\q
```

> **Nota importante**: El campo `password_hash` debe ser `VARCHAR(60)`, no `CHAR(60)`. Si tienes problemas de login, ejecuta:
> ```sql
> ALTER TABLE T_Usuarios ALTER COLUMN password_hash TYPE VARCHAR(60);
> ```

---

## Uso del panel web

Abre **http://localhost:5000** en tu navegador.

| Campo | Valor |
|---|---|
| Usuario | `admin` |
| Contraseña | `admin123` |

El dashboard muestra:
- **Tabla MAC Cache**: direcciones MAC aprendidas por el VSwitch con su VPort asociado y timestamp
- **Sesiones Activas**: conexiones VPN abiertas con IP pública, inicio y estado

Para obtener un token JWT desde la terminal:

```powershell
# PowerShell
Invoke-RestMethod -Uri "http://localhost:5000/api/login" -Method POST -ContentType "application/json" -Body '{"nombre_usuario":"admin","password":"admin123"}'
```

```bash
# Linux/Mac
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"nombre_usuario":"admin","password":"admin123"}'
```

---

## Conectar un VPort

### Paso 1 — Obtener token JWT

```powershell
$resp = Invoke-RestMethod -Uri "http://localhost:5000/api/login" -Method POST -ContentType "application/json" -Body '{"nombre_usuario":"admin","password":"admin123"}'
$token = $resp.token
```

### Paso 2 — Limpiar contenedores anteriores si existen

```bash
docker rm -f vport1 vport2
```

### Paso 3 — Levantar VPort 1 (en una terminal nueva)

```bash
docker run --rm -it --privileged --cap-add=NET_ADMIN --device=/dev/net/tun --network vpn-l2_default --name vport1 vpnusm-client bash
```

Dentro del contenedor:

```bash
./vport 172.19.0.3 8888 "Token1" &
ip addr add 10.1.1.101/24 dev tapyuan
ip link set tapyuan up
```

### Paso 4 — Levantar VPort 2 (en otra terminal nueva)

```bash
docker run --rm -it --privileged --cap-add=NET_ADMIN --device=/dev/net/tun --network vpn-l2_default --name vport2 vpnusm-client bash
```

Dentro del contenedor:

```bash
./vport 172.19.0.3 8888 "token 2" &
ip addr add 10.1.1.102/24 dev tapyuan
ip link set tapyuan up
```

### Paso 5 — Verificar conectividad cifrada

Desde vport1:

```bash
ping 10.1.1.102
```

Si responde, las tramas viajan cifradas con AES-256-GCM a través del VSwitch. En los logs del servidor deberías ver:

```
[AUTH] VPort autenticado: ('172.18.0.x', ...) usuario 1
[DB] MAC guardada: xx:xx:xx:xx:xx:xx → 172.18.0.x:PORT
[MAC] Aprendida xx:xx:xx:xx:xx:xx → ('172.18.0.x', PORT)
```

---

## Resolución de errores comunes

### `Virtualization support not detected` al abrir Docker Desktop
- Reinicia el PC y entra al BIOS
- Habilita **Intel VT-x** (Intel) o **AMD-V / SVM** (AMD)
- En Windows: activa **Hyper-V** y **WSL2** desde Características de Windows
- En equipos corporativos: contactar al administrador de TI

### `failed to solve: dockerfile parse error on line N: unknown instruction: \`\`\``
El archivo Dockerfile contiene los backticks del bloque de código markdown. Abre el archivo y elimina cualquier línea que contenga solo ` ``` `.

### `docker: Error response... name already in use`
```bash
docker rm -f vport1
docker rm -f vport2
docker rm -f vpn_server
docker rm -f vpn_database
```

### `parent snapshot does not exist: not found` al hacer build
```bash
docker builder prune -f
docker image prune -f
docker-compose up --build --no-cache
```

### Login devuelve `Credenciales incorrectas`
Causa más común: el `password_hash` está truncado por ser `CHAR(60)` en lugar de `VARCHAR(60)`.

```bash
# 1. Verificar longitud del hash
docker exec -it vpn_database psql -U vpnuser -d vpnl2 \
  -c "SELECT nombre_usuario, LENGTH(password_hash) FROM T_Usuarios;"
# Debe mostrar 60. Si muestra menos:

# 2. Cambiar tipo de columna
docker exec -it vpn_database psql -U vpnuser -d vpnl2 \
  -c "ALTER TABLE T_Usuarios ALTER COLUMN password_hash TYPE VARCHAR(60);"

# 3. Generar hash correcto
docker exec vpn_server python3 -c \
  "import bcrypt; print(bcrypt.hashpw(b'admin123', bcrypt.gensalt(12)).decode())"

# 4. Actualizar (pegar el hash dentro del contenedor para evitar que PowerShell corte el $)
docker exec -it vpn_database bash
psql -U vpnuser -d vpnl2
UPDATE T_Usuarios SET password_hash = 'HASH_AQUI' WHERE nombre_usuario = 'admin';
\q
```

### VSwitch no aparece en los logs al arrancar
Verificar que en `server/auth.py` las líneas de importación estén **antes** del `if __name__`:

```python
# CORRECTO — antes del if __name__
from vswitch import iniciar_vswitch
iniciar_vswitch()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

### `Sin respuesta — VSwitch no está escuchando`
```bash
docker exec -it vpn_server python3 vswitch.py
```
Esto muestra el error exacto. Los más comunes son:
- **ImportError**: falta una librería → reconstruir con `docker-compose up --build`
- **OSError: [Errno 98] Address already in use**: otro proceso usa el puerto 8888 → `docker-compose down` y volver a subir

### La tabla MAC Cache aparece vacía en el dashboard
El VSwitch solo registra MACs cuando un VPort se conecta y envía tráfico. Conecta al menos un VPort siguiendo los pasos de la sección anterior y refresca el dashboard.

---

## Estado actual del proyecto

| Componente | Estado | Notas |
|---|---|---|
| Docker + contenedores | ✅ Funcional | VSwitch + Flask + PostgreSQL en un solo contenedor |
| Base de datos 3FN | ✅ Funcional | 5 tablas creadas |
| Login bcrypt + JWT | ✅ Funcional | Tokens guardados en T_Tokens |
| Dashboard web | ✅ Funcional | MAC Cache y Sesiones visibles |
| VSwitch AES-256-GCM | ✅ Implementado | Corre como hilo dentro de Flask |
| Handshake JWT VPort | ✅ Implementado | Autenticación al conectar |
| Cifrado VPort (C) | ✅ Implementado | OpenSSL AES-256-GCM |
| MACs en PostgreSQL | ⚠️ Pendiente verificar | Depende de conectar VPort exitosamente |
| Ping cifrado entre VPorts | ⚠️ Pendiente verificar | Requiere dos VPorts conectados |
| Sesiones en T_Sesiones | ⚠️ Pendiente | VSwitch no llama a registrar_sesion aún |
| Registro de usuarios web | ❌ No implementado | Solo se crea manualmente vía SQL |
| Dashboard tiempo real | ❌ No implementado | Requiere polling o WebSocket |

---

## Pendiente por implementar

Según el documento de diseño del proyecto, estas funcionalidades están definidas pero aún no desarrolladas:

### Sprint 4 — Pendiente completo

**1. Registro de usuarios desde la web**
- Agregar ruta `POST /api/registro` en `auth.py`
- Formulario en el dashboard para crear nuevos usuarios
- Registro automático de dispositivo en `T_Dispositivos` al conectar un VPort

**2. Registro de sesiones VPN en PostgreSQL**
- El VSwitch debe llamar a `registrar_sesion()` cuando un VPort se autentica exitosamente
- Actualizar `timestamp_fin` y `bytes_enviados/recibidos` al desconectarse
- Actualmente `T_Sesiones` siempre está vacía

**3. Dashboard con datos en tiempo real**
- Agregar polling automático cada 5 segundos en el frontend
- O implementar WebSocket con Flask-SocketIO
- Mostrar contador de bytes por sesión

**4. Pruebas de rendimiento**
- Medir latencia del ping a través del túnel cifrado
- Comparar throughput con/sin cifrado AES-256-GCM
- Documentar MTU efectivo con la sobrecarga de encapsulamiento (UDP + IV 12B + TAG 16B)

**5. Mejoras de seguridad identificadas**
- Migrar de Flask development server a Gunicorn o uWSGI en producción
- Implementar intercambio de claves Diffie-Hellman para eliminar el secreto compartido
- Agregar rate limiting en la API de login para prevenir fuerza bruta
- Soporte multitenant: aislar redes virtuales entre grupos de usuarios

**6. Limpieza automática de la tabla MAC**
- Implementar job periódico que ejecute:
  ```sql
  DELETE FROM T_Mac_Cache
  WHERE timestamp_ultimo_visto < NOW() - INTERVAL '5 minutes';
  ```

---

## Estructura del proyecto

```
VPN USM/
├── docker-compose.yml          # Orquestación de servicios
├── client/
│   ├── dockerfile              # Ubuntu + gcc + libssl-dev
│   └── vport.c                 # Cliente VPN en C con AES-256-GCM
├── database/
│   └── init.sql                # DDL PostgreSQL — 5 tablas en 3FN
└── server/
    ├── dockerfile              # Python 3.11-slim + dependencias
    ├── start.sh                # Script de inicio
    ├── auth.py                 # Flask API + login JWT + dashboard
    └── vswitch.py              # Switch virtual L2 + AES-256-GCM
```

---

## Base de datos

El sistema usa PostgreSQL con 5 tablas normalizadas en 3FN:

| Tabla | Descripción |
|---|---|
| `T_Usuarios` | Credenciales con contraseña hasheada en bcrypt |
| `T_Dispositivos` | Interfaces TAP registradas por usuario |
| `T_Tokens` | Tokens JWT emitidos con fecha de expiración |
| `T_Sesiones` | Registro de auditoría de conexiones VPN |
| `T_Mac_Cache` | Tabla de reenvío MAC dinámica del VSwitch |

Comandos útiles:

```bash
# Ver contenido de cualquier tabla
docker exec -it vpn_database psql -U vpnuser -d vpnl2 -c "SELECT * FROM T_Mac_Cache;"
docker exec -it vpn_database psql -U vpnuser -d vpnl2 -c "SELECT * FROM T_Sesiones;"
docker exec -it vpn_database psql -U vpnuser -d vpnl2 -c "SELECT id_user, nombre_usuario, activo FROM T_Usuarios;"

# Ver logs en tiempo real
docker logs -f vpn_server
docker logs -f vpn_database

# Reiniciar solo el servidor
docker-compose restart server

# Apagar todo
docker-compose down

# Apagar y borrar la base de datos (reset completo)
docker-compose down -v
```

---

## Tecnologías utilizadas

| Tecnología | Versión | Rol |
|---|---|---|
| Python | 3.11 | VSwitch + API Flask |
| C (C99) | gcc 14 | VPort cliente |
| PostgreSQL | 15 | Base de datos |
| Flask | 3.x | Panel web REST API |
| PyJWT | 2.x | Autenticación tokens |
| bcrypt | 5.x | Hash de contraseñas |
| cryptography | 46.x | AES-256-GCM / HKDF |
| OpenSSL | 3.x | Cifrado en VPort C |
| Docker | 27.x | Contenedores |
| Docker Compose | 2.x | Orquestación |

