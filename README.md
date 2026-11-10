# Álamo Borrado Seguro — ISO booteable (NIST SP 800-88)

Arranca desde USB (F12 en Dell), detecta los discos internos, aplica el borrado por firmware más fuerte que soporta cada uno, verifica el resultado y emite un certificado PDF que se guarda en la USB y se envía a Power Automate.

## Contenido

| Ruta | Qué es |
|---|---|
| `config/includes.chroot/opt/alamo/alamo_wipe.py` | Motor e interfaz (Python 3, sin dependencias externas salvo WeasyPrint) |
| `config/package-lists/alamo.list.chroot` | Paquetes de la imagen (shim/GRUB firmados, nvme-cli, hdparm, firmware de red…) |
| `config/hooks/live/0100-alamo.hook.chroot` | Ajustes: servicio en tty1, zona horaria, reloj en hora local |
| `config/includes.chroot/etc/systemd/system/alamo-wipe.service` | Lanza la interfaz al arrancar y la reinicia si se cierra |
| `auto/config` | Opciones de `live-build` (Debian 13 trixie, Secure Boot, ISO híbrida) |
| `build-iso.sh` | Construye la ISO |
| `.github/workflows/build-iso.yml` | Construcción automática en GitHub Actions |
| `usb/alamo-wipe.conf` | Configuración que va en la raíz de la USB (webhook, opciones) |

## 1. Construir la ISO

Necesita un Linux Debian/Ubuntu con acceso a Internet (descarga ~400 MB de paquetes). Tarda 20–40 min. Elija una opción:

**A) GitHub Actions (sin instalar nada)**
1. Suba esta carpeta a un repositorio **privado** de GitHub.
2. Pestaña *Actions* → *Construir ISO Alamo Borrado Seguro* → *Run workflow*.
3. Al terminar, descargue el artefacto `alamo-borrado-seguro-iso` (contiene la ISO y su SHA-256).

**B) Máquina virtual Debian 13 (o Ubuntu con Docker)**
```bash
sudo ./build-iso.sh                       # en Debian 13
# o, en cualquier Linux con Docker:
docker run --rm --privileged -v "$PWD":/work -w /work debian:trixie ./build-iso.sh
```
La ISO queda en `salida/alamo-borrado-seguro-AAAAMMDD.iso`.

Para incluir el logotipo en la imagen, coloque `logo.png` junto a `build-iso.sh` antes de construir (también puede ponerlo después en la raíz de la USB).

> La URL del webhook **no** va dentro de la ISO: se configura en la USB. Así la ISO puede compartirse sin exponer la credencial.

## 2. Preparar la USB (Rufus, en Windows)

1. Rufus → seleccione la ISO.
2. **Esquema de partición: GPT** · **Sistema destino: UEFI (no CSM)** · Sistema de archivos: **FAT32**.
3. Al pulsar *Empezar*, si pregunta, elija **"Escribir en modo Imagen ISO (Recomendado)"** — *no* modo DD. El modo ISO deja la USB en FAT32 escribible, donde se guardan los certificados.
4. Copie a la **raíz** de la USB:
   - `usb/alamo-wipe.conf` con `webhook_url` llenado,
   - `logo.png` (opcional).

No use Ventoy: obliga a registrar una llave MOK en cada equipo para arrancar con Secure Boot.

## 3. Uso en campo

1. Conecte la USB y el **cargador**; si hay cable de red, conéctelo.
2. Encienda y pulse **F12** → elija la USB en *UEFI Boot*.
3. La interfaz arranca sola:
   - **Red**: si no hay cable, elija *Conectar a Wi-Fi* o *Continuar sin red* (el envío queda pendiente en la USB y se manda solo en el siguiente arranque con red).
   - **Menú**: 1 Borrado · 2 Simulación · 3 Prueba de recuperación · 4 Diagnóstico · 5 Red/reenvío · 6 Consola · 7 Apagar · 8 Reiniciar.
   - **Selección**: marque discos con **Espacio**, Enter para continuar. La USB de arranque nunca aparece.
   - **Confirmación**: escriba `BORRAR`.
4. Al terminar verá el resultado; el certificado queda en `Reportes_Borrado_Seguro\` de la USB.

### Archivos en la USB

| Carpeta / archivo | Contenido |
|---|---|
| `Reportes_Borrado_Seguro\Certificado_BorradoSeguro_<serie>_<fecha>.pdf` | Certificado |
| `…_datos.json` | Datos completos del certificado (para auditoría y verificación de la huella) |
| `Log_<serie>_<fecha>.txt` | Bitácora de la ejecución |
| `Diagnostico_<serie>_<fecha>.txt` | Resultado del diagnóstico |
| `Evidencia_PruebaRecuperacion_<serie>_<fecha>.pdf` | Prueba de recuperación (opcional) |
| `Pendientes_Envio\` | Envíos que no se pudieron hacer; `enviados\` guarda los ya mandados |

## 4. Qué hace con cada disco

| Tipo | Orden de métodos (si uno falla se intenta el siguiente) | Nivel NIST |
|---|---|---|
| NVMe | Sanitize Crypto → Sanitize Block → Format SES=2 → Format SES=1 | Purge |
| SATA SSD | ATA Sanitize Crypto → ATA Sanitize Block → Enhanced Security Erase → Security Erase | Purge |
| SATA HDD | ATA Sanitize → Security Erase → sobrescritura con ceros | Purge / Clear |
| Otros (eMMC, USB) | Sobrescritura con ceros | Clear |

Las capacidades se leen como bits (`sanicap`, `fna`, `oacs` en NVMe; bloque *Security* de `hdparm -I` en SATA), no buscando texto, y el resultado de cada comando se comprueba: un fallo nunca produce un certificado "Exitoso".

**Discos SATA en estado "frozen"**: se suspende el equipo 8 s (`rtcwake`) para que el disco se reinicie. En laptops que solo tienen *Modern Standby* (sin S3) puede no funcionar; el certificado lo registra y se intenta el siguiente método. La contraseña ATA temporal se retira siempre al final.

**Verificación**: antes del borrado se leen 32 muestras de 64 KiB (inicio, mitad, final y posiciones aleatorias) y se guarda su SHA-256. Después se releen sin caché (`O_DIRECT`). Si alguna muestra que tenía datos queda igual, el disco se marca **Fallido**. Si el disco ya estaba vacío, la verificación sale "No concluyente" y el resultado se basa en la confirmación del firmware.

**Estados**: *Exitoso* (método OK + verificación aprobada o no concluyente) · *Parcial* (sobrescritura en SSD) · *Fallido* (ningún método funcionó o la verificación detectó datos).

## 4.1 Prueba de recuperación (opcional, evidencia aparte)

Al terminar un borrado real, la interfaz ofrece una prueba de recuperación. También está en el menú principal (**3 Prueba de recuperación**) para hacerla después. Ninguna de las dos pruebas escribe en el disco.

| Prueba | Qué hace | Tiempo |
|---|---|---|
| **Rápida** | Sin particiones ni firmas (`wipefs`); lee el primer 512 MiB, los últimos 64 MiB y 2048 bloques aleatorios buscando NTFS, BitLocker, FAT/exFAT, GPT, MFT y cabeceras de PDF, Office, Outlook, imágenes, comprimidos, registro de Windows, SQLite y video | ~1 min |
| **Completa** | PhotoRec sobre todo el disco (más de 400 tipos de archivo). Lo recuperado va solo a memoria RAM y se elimina; se registra únicamente cantidad y tipo. Se detiene sola si supera 200 archivos | NVMe 3–10 min · SSD SATA 10–20 min · HDD 1.5–3 h |

El resultado se guarda en la USB como `Evidencia_PruebaRecuperacion_<serie>_<fecha>.pdf` (+ `_datos.json`), con el folio del certificado de referencia. **No modifica el certificado ni se envía a Power Automate.** Resultado esperado tras un borrado correcto: ninguna firma y 0 archivos recuperados.

## 5. Power Automate

Se envía el mismo esquema del sistema de reasignación (`hostname`, `serie`, `modelo`, `tecnico`, `usuarios`, `fecha`, `nombreArchivo`, `archivoBase64`) y además `tipo` (`BorradoSeguro`), `resultado`, `folio`, `huella` y `hashPdf`. El disparador HTTP acepta campos adicionales, así que el flujo actual funciona sin cambios. Para aprovecharlos, agregue al esquema esos campos y columnas en la lista (o use una lista aparte para borrados).

- `hostname` lleva el valor de `etiqueta_hostname` (el equipo ya no tiene sistema operativo).
- `usuarios` lleva el resumen de discos: `ruta modelo S/N serie: estado (método)`.

## 6. Verificar un certificado

La huella del pie del PDF es el SHA-256 (o HMAC-SHA256 si se definió `clave_hmac`) del JSON `…_datos.json` **sin** la clave `huella`, serializado con claves ordenadas:

```python
import json, hashlib
d = json.load(open("Certificado_..._datos.json", encoding="utf-8")); d.pop("huella")
print(hashlib.sha256(json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest())
```
Debe coincidir con el PDF y con la columna `huella` registrada en SharePoint.

## 7. Requisitos en equipos Dell

- **Secure Boot puede quedarse activo.** En modelos recientes (Secured-core), si la USB no arranca, active en BIOS *Secure Boot → Enable Microsoft UEFI CA*.
- **RAID On / VMD**: normalmente Linux ve el NVMe igual. Si el diagnóstico no muestra discos, cambie *Storage → SATA/NVMe Operation* a **AHCI/NVMe** (no afecta, el disco se va a borrar).
- **Contraseña de BIOS**: si el equipo la tiene, F12 puede pedirla.

## 8. Plan de pruebas recomendado

1. En 2–3 modelos Dell distintos (uno viejo y uno reciente), arrancar y ejecutar **3 Diagnóstico**. Revisar el `.txt`: Secure Boot, discos detectados, métodos y estado *frozen*.
2. Ejecutar **2 Simulación** y revisar el PDF y el log.
3. Borrado real en un equipo de prueba con archivos reconocibles y, al terminar, elegir la prueba **Ambas**: debe dar 0 firmas y 0 archivos recuperados.
4. Probar sin red → arrancar con red → confirmar que el pendiente llega a SharePoint.

## Modo línea de comandos (desde la consola de soporte)

```bash
python3 /opt/alamo/alamo_wipe.py --diagnostico
python3 /opt/alamo/alamo_wipe.py --disco /dev/nvme0n1 --simulacion
python3 /opt/alamo/alamo_wipe.py --disco /dev/nvme0n1 --confirmar BORRAR
python3 /opt/alamo/alamo_wipe.py --disco /dev/nvme0n1 --prueba ambas      # solo prueba de recuperación
```
