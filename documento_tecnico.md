# Documento Técnico — Simulación de Ransomware (Modelo B)

**Actividad III — Criptografía Aplicada**  
**Fecha:** Abril 2025  

---

## 1. Introducción

Esta actividad implementa una simulación controlada de un ransomware como caso de estudio en criptografía aplicada. Se utiliza el **Modelo B** (el atacante genera el par de claves RSA), donde la víctima genera una clave simétrica AES-256, cifra sus archivos, y envía la clave cifrada con RSA al atacante. La recuperación se simula tras un "pago" ficticio.

**Tecnologías utilizadas:**
- Python 3.x
- PyCryptodome (AES-256-GCM, generación de primos RSA)
- Sockets TCP para comunicación entre atacante y víctima

---

## 2. Especificación Algorítmica — Modelo B

### 2.1. Notación

| Símbolo | Descripción |
|---------|-------------|
| `(pk, sk) ← GRSA(λ)` | Generación de llaves RSA con parámetro de seguridad λ |
| `c ← FRSA(pk, m)` | Cifrado RSA: c = m^e mod n |
| `m ← IRSA(sk, c)` | Descifrado RSA con CRT |
| `Ksym $← K` | Elección aleatoria de clave simétrica de 256 bits |
| `SYM_ENC_K(f)` | Cifrado simétrico AES-256-GCM del archivo f con clave K |
| `SYM_DEC_K(f)` | Descifrado simétrico AES-256-GCM del archivo f con clave K |

### 2.2. Pasos detallados

#### Paso 1 — Generación de llaves RSA (Atacante)

El atacante genera un par de llaves RSA de 1024 bits (2 × 512 bits por primo) usando el teorema chino del residuo (CRT) para optimizar el descifrado:

1. Generar primo `p` de 512 bits tal que `GCD(p-1, e) = 1`
2. Generar primo `q` de 512 bits tal que `GCD(q-1, e) = 1` y `q ≠ p`
3. Calcular `n = p × q`, `φ(n) = (p-1)(q-1)`
4. Calcular `d = e⁻¹ mod φ(n)` (inverso modular)
5. Precomputar parámetros CRT: `dp = d mod (p-1)`, `dq = d mod (q-1)`, `qinv = q⁻¹ mod p`
6. Clave pública: `pk = (n, e)` con `e = 65537`
7. Clave privada: `sk = (p, q, dp, dq, qinv)`

#### Paso 2 — Intercambio de clave pública (A → V)

El atacante abre un servidor TCP en `127.0.0.1:9999` y espera la conexión de la víctima. Una vez conectada, envía su clave pública `pk = (n, e)` en formato JSON.

#### Paso 3 — Generación de Ksym y cifrado de archivos (Víctima)

1. La víctima genera `Ksym` de 32 bytes (256 bits) usando `get_random_bytes(32)`
2. Para cada archivo `f` en `lab/sample_plain/`:
   - Genera un nonce aleatorio de 12 bytes
   - Cifra `f` con AES-256-GCM usando `Ksym`
   - Escribe cabecera: `"AG02" || nonce || tag(16 bytes) || tamaño_original(8 bytes)`
   - Escribe el ciphertext
   - Guarda el archivo cifrado en `lab/sample_cipher/` con extensión `.enc`
   - Elimina el archivo original

#### Paso 4 — Envío de Ksym cifrada (V → A)

1. La víctima cifra `Ksym` con RSA: `c = FRSA(pk, Ksym)`
2. Envía `c` al atacante por el socket TCP
3. Borra `Ksym` de su memoria local

#### Paso 5 — Generación de nota de rescate (Víctima)

Se genera `ransom_note.txt` con:
- Fecha y hora del ataque
- Algoritmo utilizado (AES-256-GCM)
- Lista de archivos cifrados
- Mensaje ficticio de recuperación

#### Paso 6 — Descifrado de Ksym (Atacante)

El atacante descifra la clave simétrica usando RSA-CRT:

```
xp = c^dp mod p
xq = c^dq mod q
h  = qinv × (xp - xq) mod p
Ksym = xq + q × h
```

#### Paso 7 — Recuperación tras "pago" (A → V)

1. El atacante abre nuevamente el servidor TCP
2. La víctima reconecta
3. El atacante envía `Ksym` en claro (codificada en Base64)
4. La víctima descifra cada archivo `.enc` de `lab/sample_cipher/`:
   - Lee la cabecera (nonce, tag, tamaño original)
   - Descifra con AES-256-GCM usando `Ksym`
   - Verifica la integridad con el tag de autenticación
   - Restaura el archivo en `lab/sample_plain/`

---

## 3. Diagramas

### 3.1. Diagrama de secuencia — Flujo completo

```
Atacante (atacante.py)                         Víctima (victima.py)
─────────────────────                         ─────────────────────
                                               Setup: crear archivos
                                               de prueba en
                                               lab/sample_plain/

═══════════════ FASE 1: ATAQUE Y CIFRADO ═══════════════

(pk, sk) ← GRSA(512, 65537)
Abrir servidor TCP:9999
Esperar conexión...
                                               Conectar a TCP:9999
         ◄──────── conexión TCP ────────────
         
Enviar pk = (n, e)
         ────────── {n, e} ────────────────►
                                               Ksym ← random(32 bytes)
                                               ∀f ∈ lab/sample_plain/:
                                                 SYM_ENC_Ksym(f) → .enc
                                                 Eliminar f original
                                               c ← FRSA(pk, Ksym)
         ◄──────── {c} ────────────────────
         
Ksym ← IRSA(sk, c)                            Borrar Ksym de memoria
Guardar Ksym                                   Generar ransom_note.txt
Enviar ACK
         ────────── "OK" ──────────────────►
Cerrar conexión                                Cerrar conexión

═══════════════ FASE 2: PAGO Y RECUPERACIÓN ═══════════════

Abrir servidor TCP:9999
Esperar reconexión...
                                               Reconectar a TCP:9999
         ◄──────── conexión TCP ────────────
         
Enviar Ksym (Base64)
         ────────── {Ksym} ────────────────►
                                               ∀f ∈ lab/sample_cipher/:
                                                 SYM_DEC_Ksym(f)
                                                 Restaurar en sample_plain/
         ◄──────── "OK" ──────────────────
Cerrar conexión                                Cerrar conexión
```

### 3.2. Diagrama de flujo — Proceso de cifrado de un archivo

```
┌─────────────────────────────┐
│  Inicio: cifrar_archivo(f)  │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  Generar nonce (12 bytes)   │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  Crear instancia AES-GCM   │
│  con Ksym y nonce           │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  Obtener tamaño original    │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  Escribir cabecera:         │
│  "AG02" + nonce + tag_vacio │
│  + tamaño (8 bytes)         │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  Leer bloques de 64KB       │◄──┐
│  y cifrar con AES-GCM       │   │
└──────────────┬──────────────┘   │
               ▼                  │
         ¿Más bloques? ──── Sí ───┘
               │ No
               ▼
┌─────────────────────────────┐
│  Escribir tag de            │
│  autenticación en cabecera  │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  Fin: archivo .enc creado   │
└─────────────────────────────┘
```

### 3.3. Formato del archivo cifrado (.enc)

```
Offset   Tamaño   Campo
──────   ──────   ─────
0        4 bytes  Cabecera mágica "AG02"
4        12 bytes Nonce (aleatorio)
16       16 bytes Tag de autenticación GCM
32       8 bytes  Tamaño original del archivo (big-endian)
40       variable Datos cifrados (ciphertext)
```

---

## 4. Evidencia de ejecución

### 4.1. Archivos originales (antes del ataque)

```
lab/sample_plain/
  ├── resumen_champions.txt
  └── notas_lab.txt
```

> *Nota: Incluir capturas de pantalla de la terminal mostrando los archivos originales y su contenido.*

### 4.2. Archivos cifrados (después del ataque)

```
lab/sample_cipher/
  ├── resumen_champions.txt.enc
  └── notas_lab.txt.enc
```

> *Nota: Incluir capturas de la terminal mostrando que `lab/sample_plain/` está vacía y los archivos `.enc` existen en `lab/sample_cipher/`.*

### 4.3. Nota de rescate generada (ransom_note.txt)

```
¡ATENCION! ARCHIVOS CIFRADOS

Fecha: YYYY-MM-DD HH:MM
Algoritmo: AES-256-GCM

Archivos afectados:
- lab/sample_cipher/notas_lab.txt.enc
- lab/sample_cipher/resumen_champions.txt.enc

Para recuperar sus archivos, contacte al atacante
y realice el pago solicitado.
```

### 4.4. Archivos recuperados (después del pago)

```
lab/sample_plain/
  ├── resumen_champions.txt  (contenido idéntico al original)
  └── notas_lab.txt          (contenido idéntico al original)
```

> *Nota: Incluir capturas de la terminal mostrando los archivos restaurados y la primera línea de cada uno.*

---

## 5. Preguntas de reflexión

### 5.1. Como atacante: ¿Qué estrategias usaría para lograr que la víctima instale el ransomware?

Sin implementar nada, las estrategias más comunes de distribución de ransomware incluyen:

**Phishing por correo electrónico:** Es el vector de ataque más frecuente. El atacante envía correos que aparentan provenir de fuentes legítimas (bancos, empresas de paquetería, instituciones educativas) con archivos adjuntos maliciosos (.docx con macros, .pdf con exploits, o ejecutables disfrazados). El correo utiliza urgencia ("Su cuenta será bloqueada") o curiosidad ("Factura adjunta") para motivar al usuario a abrir el archivo.

**Ingeniería social dirigida (spear phishing):** A diferencia del phishing masivo, el atacante investiga a la víctima específica (redes sociales, LinkedIn, página institucional) y personaliza el ataque. Por ejemplo, enviar un correo que simula ser del departamento de TI de la universidad del estudiante, solicitando "actualizar credenciales" mediante un enlace que descarga el ransomware.

**Sitios web comprometidos (drive-by download):** El atacante compromete un sitio web legítimo o crea uno falso que explota vulnerabilidades del navegador para descargar y ejecutar el malware sin interacción del usuario más allá de visitar la página.

**Software pirata y cracks:** Distribuir el ransomware disfrazado como un activador de software (KMS, cracks de juegos, etc.). Los usuarios que descargan software pirata suelen desactivar el antivirus, facilitando la infección.

**Dispositivos USB infectados:** Dejar memorias USB en lugares estratégicos (estacionamientos, cafeterías de la empresa) con archivos aparentemente interesantes que al abrirse ejecutan el ransomware (técnica conocida como "USB drop attack").

**Explotación de servicios expuestos:** Si la víctima tiene servicios como RDP (Remote Desktop Protocol) expuestos a internet con contraseñas débiles, el atacante puede acceder remotamente e instalar el ransomware directamente.

### 5.2. ¿Qué otros canales podrían usarse en el paso 2 para evitar sospechas?

El objetivo es que el intercambio de claves no sea detectado por sistemas de monitoreo de red. Algunos canales encubiertos (covert channels) incluyen:

**Canal encubierto en tráfico ICMP:** Se pueden ocultar datos en el campo de datos (payload) de paquetes ICMP Echo Request/Reply (ping). Los firewalls rara vez inspeccionan el contenido de paquetes ICMP, ya que se consideran tráfico de diagnóstico inofensivo. La clave pública RSA podría fragmentarse y transmitirse en múltiples pings.

**Canal encubierto en consultas DNS:** Las consultas DNS son casi siempre permitidas por los firewalls. El atacante podría codificar la clave pública como subdominios en consultas DNS (por ejemplo, `base64fragment1.dominio-atacante.com`). El servidor DNS del atacante responde con la información necesaria en los registros TXT. Esta técnica se conoce como "DNS tunneling".

**Esteganografía en tráfico HTTP/HTTPS:** Ocultar la clave en imágenes publicadas en sitios web legítimos (por ejemplo, subir una imagen a un foro público con la clave embebida en los bits menos significativos de los píxeles). La víctima descarga la imagen como parte de la navegación normal y extrae la clave.

**Tráfico en redes sociales o servicios de mensajería:** Usar APIs de servicios legítimos (Twitter/X, Telegram, Pastebin) como canal de comunicación de comando y control (C2). El atacante publica la clave pública en un post o mensaje, y el ransomware la obtiene consultando esa plataforma. El tráfico hacia estas plataformas es considerado normal.

**Campos no utilizados de protocolos existentes:** Utilizar campos de encabezados TCP (opciones TCP, campos reservados), HTTP (cabeceras personalizadas en solicitudes aparentemente normales a sitios legítimos) o incluso el campo TTL de paquetes IP para transmitir datos bit a bit.

### 5.3. Como defensor: ¿Qué políticas y prácticas mitigarían este tipo de ataques?

**Copias de seguridad (Backups):**
- Implementar la regla **3-2-1**: 3 copias de los datos, en 2 tipos de medios diferentes, con 1 copia fuera del sitio (offsite/cloud).
- Las copias deben ser **inmutables** (no se pueden modificar ni eliminar) durante un período de retención definido.
- Realizar pruebas periódicas de restauración para verificar que los backups funcionan correctamente.
- Mantener copias desconectadas (air-gapped) para evitar que el ransomware las cifre también.

**Segmentación de red:**
- Dividir la red en segmentos aislados mediante VLANs y firewalls internos.
- Aplicar el principio de **mínimo privilegio**: cada usuario y sistema solo tiene acceso a los recursos que necesita.
- Separar las redes de servidores críticos, estaciones de trabajo y dispositivos IoT.
- Esto limita la propagación lateral del ransomware dentro de la organización.

**Monitoreo y detección:**
- Implementar un **SIEM** (Security Information and Event Management) para correlacionar eventos de seguridad.
- Utilizar **EDR** (Endpoint Detection and Response) en todas las estaciones de trabajo para detectar comportamientos anómalos como cifrado masivo de archivos.
- Monitorear tráfico de red con **IDS/IPS** (Intrusion Detection/Prevention Systems) para identificar comunicaciones con servidores C2 conocidos.
- Configurar alertas para actividades sospechosas: acceso masivo a archivos, conexiones a IPs desconocidas, ejecución de procesos inusuales.

**Hardening (endurecimiento de sistemas):**
- Mantener todos los sistemas actualizados con los últimos parches de seguridad.
- Deshabilitar servicios innecesarios (RDP si no se usa, macros de Office, PowerShell para usuarios que no lo necesitan).
- Configurar **AppLocker** o políticas de restricción de software para permitir solo la ejecución de programas autorizados (listas blancas).
- Implementar autenticación multifactor (MFA) en todos los accesos remotos.

**Concientización y capacitación:**
- Realizar campañas periódicas de **phishing simulado** para entrenar a los usuarios en la detección de correos maliciosos.
- Capacitar al personal sobre buenas prácticas: no abrir adjuntos desconocidos, verificar remitentes, reportar correos sospechosos.
- Establecer un protocolo claro de respuesta ante incidentes que todos conozcan.
- Crear una cultura de seguridad donde reportar un posible ataque no genere consecuencias negativas para el empleado.

**Plan de respuesta a incidentes:**
- Tener un plan documentado y ensayado para responder a un ataque de ransomware.
- Incluir procedimientos de aislamiento (desconectar equipos infectados de la red), notificación, análisis forense y restauración desde backups.
- Definir claramente que **no se recomienda pagar el rescate**, ya que no garantiza la recuperación y financia actividades criminales.

---

## 6. Conclusiones

Esta simulación demuestra el funcionamiento conceptual de un ransomware basado en criptografía asimétrica (RSA) y simétrica (AES-256-GCM). El Modelo B ofrece una arquitectura donde el atacante mantiene control total sobre la recuperación, ya que es el único que posee la clave privada RSA necesaria para descifrar `Ksym`.

Los puntos clave del diseño son:
- **RSA-CRT** permite un descifrado eficiente manteniendo la seguridad del esquema.
- **AES-256-GCM** proporciona tanto confidencialidad como integridad (autenticación) de los datos cifrados.
- La separación en dos programas independientes (`atacante.py` y `victima.py`) simula de manera realista la comunicación entre dos máquinas vía sockets TCP.
