
```markdown
# PAI-2: BYODSEC - Road Warrior VPN SSL para Universidad Pública (U-Secure)

Este repositorio contiene la implementación del proyecto PAI-2 para la infraestructura de acceso remoto seguro (BYOD) de la Universidad Pública U-Secure.

---

## 1. Trabajo Realizado: Rol 1 (PKI, Gestión de Usuarios y Autenticación en Dos Capas)

Se ha completado la infraestructura base de clave pública (PKI) y el servicio de autenticación corporativa, satisfaciendo los siguientes requisitos:

* **RS1 (Infraestructura PKI y Certificados X.509v3):**
  * Creación y gestión de la **Root-CA** corporativa autofirmada (RSA 4096 bits, SHA-256).
  * Emisión del certificado digital del servidor VPN con extensiones X.509v3 (`basicConstraints = CA:FALSE`, `keyUsage = digitalSignature, keyEncipherment`, `extendedKeyUsage = serverAuth` y SAN para `127.0.0.1` y `localhost`).
  * Emisión de certificados digitales para dispositivos BYOD con la extensión `extendedKeyUsage = clientAuth` y el rol asignado en la unidad organizativa (`OU`).

* **RF1 (Registro de Usuarios y Emparejamiento de Dispositivos):**
  * Almacenamiento seguro de contraseñas mediante derivación robusta **PBKDF2-HMAC-SHA256** (100.000 iteraciones y salt aleatorio de 16 bytes).
  * Extracción y vinculación inmutable de la clave pública del certificado X.509 en la base de datos SQLite (`u_secure.db`).

* **RF2 (Autenticación en Dos Capas - mTLS + Credenciales):**
  * **Capa 1 (Transporte):** Validación del certificado digital del cliente contra la CA corporativa y verificación de que el usuario no esté revocado.
  * **Capa 2 (Aplicación):** Comprobación en tiempo constante de usuario y contraseña corporativa.
  * **Coherencia de identidad:** Control estricto de que el `Common Name` (CN) del certificado presentado coincida exactamente con las credenciales introducidas.

* **RF5 (Precarga de Usuarios Corporativos):**
  * Cuentas iniciales precargadas para los tres perfiles universitarios: **PDI**, **PAS** e **Investigador**.
  * Script automatizado para la generación masiva de 300 cuentas y certificados para pruebas de carga.

---

## 2. Estructura del Proyecto

```text
PAI_2/
├── pki/
│   ├── ca/                  # Clave privada y certificado de la Root-CA corporativa
│   ├── server/              # Clave privada y certificado X.509v3 del servidor VPN
│   ├── clients/             # Certificados y claves privadas emitidos a usuarios BYOD
│   └── pki_manager.py       # Gestor y emisor automatizado de certificados mediante OpenSSL
│
├── server/
│   ├── database.py          # Gestión de SQLite, hashing PBKDF2 y registro inmutable
│   ├── auth_service.py      # Lógica de validación de autenticación en dos capas (RF2)
│   ├── test_auth.py         # Pruebas unitarias de la lógica de autenticación
│   └── u_secure.db          # Base de datos SQLite
│
├── scripts/
│   └── generate_300_users.py # Generación masiva de 300 cuentas para pruebas de concurrencia (Rol 3)
│
└── README.md
```

---

## 3. Instrucciones de Ejecución y Pruebas del Rol 1

Para regenerar la PKI o inicializar la base de datos desde cero:

```bash
# 1. Generar la Root-CA y el certificado del servidor
python3 pki/pki_manager.py

# 2. Inicializar la base de datos y precargar los usuarios iniciales (RF5)
python3 server/database.py

# 3. Ejecutar las pruebas unitarias de autenticación en dos capas (RF2)
python3 server/test_auth.py
```

---

## 4. Próximos Pasos para los Miembros del Equipo

### Para el Rol 2: Túnel VPN TLS 1.3, Sockets y Cierre de Sesión (RF4, RS2)
El Rol 2 debe construir el canal seguro de comunicación utilizando **Sockets TLS 1.3** nativos (`ssl` en Python):
1. **Configuración del Servidor Socket (`ssl.SSLContext`):**
    * Cargar el certificado y clave del servidor: `pki/server/server.crt` y `pki/server/server.key`.
    * Exigir autenticación mutua (mTLS): `context.verify_mode = ssl.CERT_REQUIRED`.
    * Cargar la CA de confianza para validar clientes: `context.load_verify_locations(cafile="pki/ca/ca.crt")`.
    * Restringir el protocolo exclusivamente a **TLS 1.3** (`ssl.TLSVersion.TLSv1_3`) y configurar Cipher Suites con PFS/AEAD (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) (RS2).
    * Al recibir la conexión, extraer el certificado con `socket.getpeercert()` y validar la sesión mediante `authenticate_two_layer(...)` de `server/auth_service.py`.
2. **Configuración del Cliente Socket:**
    * Validar el certificado del servidor contra `pki/ca/ca.crt`.
    * Presentar un certificado de cliente válido (ej. `pki/clients/profesor_garcia.crt` y su `.key`).
3. **Desmontaje del Túnel (RF4):**
    * Implementar el cierre explícito de sesión y la destrucción de las claves efímeras.

### Para el Rol 3: Benchmarking (300 Usuarios), Auditoría y Documentación (RS3, RS4)
1. **Pruebas de Carga y Concurrencia (RS3):**
    * Ejecutar `python3 scripts/generate_300_users.py` para generar las 300 cuentas con sus correspondientes certificados en `pki/clients/`.
    * Diseñar el script de prueba para simular 300 conexiones concurrentes sobre el túnel TLS 1.3 frente a tráfico plano.
    * Medir y comparar cuantitativamente: throughput, latencia (RTT) y consumo de recursos (CPU/RAM).
2. **Capturas de Red y Auditoría (RS4):**
    * Realizar capturas `.pcap` con Wireshark que demuestren que el tráfico de credenciales y datos viaja 100% cifrado por el túnel sobre la interfaz pública.
    * Redactar la memoria final (máximo 15 páginas).
```
