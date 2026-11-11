#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Alamo Seguros TI - Borrado Seguro de Discos y Certificacion (NIST SP 800-88 Rev. 1)

Se ejecuta dentro de la ISO Debian Live. Flujo:
  1. Prepara la USB (particion FAT32 creada por Rufus) para guardar reportes y lee alamo-wipe.conf.
  2. Red: verifica conexion al webhook; permite Wi-Fi (asistente con nmcli) o continuar sin red.
  3. Detecta discos internos (excluye la USB de arranque) y sus capacidades de borrado por firmware.
  4. El tecnico selecciona discos y confirma escribiendo BORRAR.
  5. Por disco: muestreo previo -> borrado por firmware (con cadena de respaldo) -> verificacion.
  6. Certificado PDF (WeasyPrint) + JSON de datos + huella SHA-256/HMAC -> USB -> Power Automate.
     Sin red, el envio queda en cola (Pendientes_Envio) y se reintenta en el siguiente arranque con red.

Modos: borrado real, simulacion (no borra, PDF marcado) y diagnostico (solo reporta capacidades).

Codigos de metodo (de mas a menos preferido):
  NVMe : nvme-sanitize-crypto > nvme-sanitize-block > nvme-format-crypto > nvme-format-user
  SATA : ata-sanitize-crypto > ata-sanitize-block > ata-secure-erase-enhanced > ata-secure-erase
  HDD  : ata-secure-erase > sobrescritura
  Otro : sobrescritura
"""

import argparse
import base64
import configparser
import datetime as dt
import glob
import hashlib
import hmac
import html
import json
import mmap
import os
import random
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.1.2"
MEDIO_LIVE = "/run/live/medium"
PUNTO_MONTAJE_EXTRA = "/mnt/alamo_usb"
CARPETA_REPORTES = "Reportes_Borrado_Seguro"
CARPETA_PENDIENTES = "Pendientes_Envio"
NOMBRE_CONF = "alamo-wipe.conf"
DIR_APP = os.path.dirname(os.path.abspath(__file__))

CONF_DEFECTO = {
    "empresa": "Álamo Seguros",
    "webhook_url": "",
    "reintentos_webhook": "3",
    "etiqueta_hostname": "BORRADO-SEGURO",
    "muestras_verificacion": "32",
    "requerir_corriente": "si",
    "permitir_usb_externos": "no",
    "sobrescribir_ssd_si_falla": "no",
    "clave_hmac": "",
}

NIVEL_METODO = {
    "nvme-sanitize-crypto": ("Purge", "Borrado criptográfico (NVMe Sanitize - Crypto Erase)"),
    "nvme-sanitize-block": ("Purge", "Borrado de bloques (NVMe Sanitize - Block Erase)"),
    "nvme-format-crypto": ("Purge", "Borrado criptográfico (NVMe Format SES=2)"),
    "nvme-format-user": ("Purge", "Borrado de datos de usuario (NVMe Format SES=1)"),
    "ata-sanitize-crypto": ("Purge", "Borrado criptográfico (ATA Sanitize - Crypto Scramble)"),
    "ata-sanitize-block": ("Purge", "Borrado de bloques (ATA Sanitize - Block Erase)"),
    "ata-secure-erase-enhanced": ("Purge", "ATA Enhanced Security Erase (firmware)"),
    "ata-secure-erase": ("Purge", "ATA Security Erase (firmware)"),
    "sobrescritura": ("Clear", "Sobrescritura de 1 pasada con ceros (shred)"),
}

GENERICOS_DMI = re.compile(
    r"^(to be filled.*|default string|system serial number|system product name|not specified|"
    r"none|o\.e\.m\.?|oem|0+|x+|n/a|chassis serial number)$", re.I)


# =====================================================================================
#  Utilidades
# =====================================================================================

class Bitacora:
    def __init__(self):
        self.lineas = []
        self.ruta = "/tmp/alamo_wipe_%s.log" % dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _w(self, nivel, msg, consola=True):
        linea = "%s [%s] %s" % (dt.datetime.now().strftime("%H:%M:%S"), nivel, msg)
        self.lineas.append(linea)
        try:
            with open(self.ruta, "a", encoding="utf-8") as f:
                f.write(linea + "\n")
        except OSError:
            pass
        if consola:
            colores = {"OK": "\033[32m", "ERR": "\033[31m", "AVISO": "\033[33m", "PASO": "\033[36m"}
            c = colores.get(nivel, "")
            print("%s[%s]\033[0m %s" % (c, nivel, msg) if c else "[%s] %s" % (nivel, msg), flush=True)

    def paso(self, m): self._w("PASO", m)
    def ok(self, m): self._w("OK", m)
    def err(self, m): self._w("ERR", m)
    def aviso(self, m): self._w("AVISO", m)
    def info(self, m, consola=True): self._w("INFO", m, consola)


LOG = Bitacora()


def run(cmd, timeout=120, entrada=None):
    """Ejecuta un comando (lista, sin shell). Devuelve (codigo, stdout, stderr). Nunca lanza."""
    try:
        p = subprocess.run(cmd, input=entrada, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "Comando no encontrado: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "Tiempo agotado (%ss): %s" % (timeout, " ".join(cmd))


def cmd_txt(cmd):
    return " ".join(cmd)


def es_verdadero(v):
    return v in (True, 1, "1", "true", "True")


def tam_legible(b):
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "N/D"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1000 or u == "TB":
            return ("%.0f %s" if u in ("B", "KB") else "%.1f %s") % (b, u)
        b /= 1000.0
    return "N/D"


def duracion(seg):
    seg = int(seg)
    h, r = divmod(seg, 3600)
    m, s = divmod(r, 60)
    return "%d h %02d min %02d s" % (h, m, s) if h else "%d min %02d s" % (m, s)


def buscar_clave(obj, clave):
    """Busca recursivamente una clave en JSON anidado (la salida de nvme-cli cambia entre versiones)."""
    if isinstance(obj, dict):
        if clave in obj:
            return obj[clave]
        for v in obj.values():
            r = buscar_clave(v, clave)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = buscar_clave(v, clave)
            if r is not None:
                return r
    return None


def leer(ruta, defecto=""):
    try:
        with open(ruta, "r", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return defecto


# =====================================================================================
#  Interfaz (whiptail)
# =====================================================================================

class UI:
    TITULO = "Álamo Seguros - Borrado Seguro NIST 800-88"

    def __init__(self, interactiva=True):
        self.interactiva = interactiva and sys.stdin.isatty() and shutil.which("whiptail")

    def _wt(self, args):
        p = subprocess.run(["whiptail", "--backtitle", self.TITULO] + args, stderr=subprocess.PIPE, text=True)
        return p.returncode, p.stderr.strip()

    def mensaje(self, titulo, texto, alto=14, ancho=74):
        if not self.interactiva:
            print("\n== %s ==\n%s\n" % (titulo, texto))
            return
        self._wt(["--title", titulo, "--msgbox", texto, str(alto), str(ancho)])

    def si_no(self, titulo, texto, si="Sí", no="No", alto=14, ancho=74):
        if not self.interactiva:
            return True
        rc, _ = self._wt(["--title", titulo, "--yes-button", si, "--no-button", no,
                          "--yesno", texto, str(alto), str(ancho)])
        return rc == 0

    def menu(self, titulo, texto, opciones, alto=20, ancho=78):
        if not self.interactiva:
            return None
        args = ["--title", titulo, "--menu", texto, str(alto), str(ancho), str(len(opciones))]
        for clave, desc in opciones:
            args += [clave, desc]
        rc, sal = self._wt(args)
        return sal if rc == 0 else None

    def lista(self, titulo, texto, opciones, alto=20, ancho=78):
        """opciones: [(clave, descripcion, marcado)]. Devuelve lista de claves o None."""
        if not self.interactiva:
            return None
        args = ["--title", titulo, "--separate-output", "--checklist", texto, str(alto), str(ancho),
                str(min(len(opciones), 8))]
        for clave, desc, on in opciones:
            args += [clave, desc, "ON" if on else "OFF"]
        rc, sal = self._wt(args)
        if rc != 0:
            return None
        return [l.strip().strip('"') for l in sal.splitlines() if l.strip()]

    def entrada(self, titulo, texto, alto=14, ancho=74):
        if not self.interactiva:
            return None
        rc, sal = self._wt(["--title", titulo, "--inputbox", texto, str(alto), str(ancho)])
        return sal if rc == 0 else None

    def clave(self, titulo, texto, alto=11, ancho=74):
        if not self.interactiva:
            return None
        rc, sal = self._wt(["--title", titulo, "--passwordbox", texto, str(alto), str(ancho)])
        return sal if rc == 0 else None

    def archivo(self, titulo, ruta):
        if self.interactiva:
            self._wt(["--title", titulo, "--scrolltext", "--textbox", ruta, "24", "90"])

    def pausa(self, texto="Presione Enter para continuar..."):
        if self.interactiva:
            try:
                input("\n" + texto)
            except EOFError:
                pass


# =====================================================================================
#  USB de reportes y configuracion
# =====================================================================================

def disco_padre(dispositivo):
    rc, out, _ = run(["lsblk", "-n", "-o", "PKNAME", dispositivo])
    padre = out.strip().splitlines()[0].strip() if rc == 0 and out.strip() else ""
    return "/dev/" + padre if padre else ""


def disco_arranque():
    """Disco fisico que contiene el sistema live (nunca debe ofrecerse para borrado).
    Con 'toram' el medio ya no esta montado: tambien se excluye por montaje (discos_con_montajes),
    porque preparar_destino monta la USB para guardar reportes."""
    rc, out, _ = run(["findmnt", "-n", "-o", "SOURCE", MEDIO_LIVE])
    fuente = out.strip().splitlines()[0] if rc == 0 and out.strip() else ""
    if not fuente.startswith("/dev/"):
        return ""
    return disco_padre(fuente) or fuente


def probar_escritura(directorio):
    try:
        os.makedirs(directorio, exist_ok=True)
        prueba = os.path.join(directorio, ".prueba_escritura")
        with open(prueba, "w") as f:
            f.write("ok")
        os.remove(prueba)
        return True
    except OSError:
        return False


def preparar_destino():
    """Devuelve (raiz_usb, es_usb). La raiz contiene alamo-wipe.conf y la carpeta de reportes."""
    # 1) El propio medio live, solo si es la USB fisica (FAT32/exFAT/NTFS). Con 'toram' el sistema
    #    corre desde RAM y este punto puede no existir o ser memoria: entonces se usa el paso 2.
    tipo_medio = run(["findmnt", "-n", "-o", "FSTYPE", MEDIO_LIVE])[1].strip()
    if os.path.ismount(MEDIO_LIVE) and tipo_medio in ("vfat", "exfat", "ntfs", "ntfs3", "fuseblk"):
        run(["mount", "-o", "remount,rw", MEDIO_LIVE])
        if probar_escritura(os.path.join(MEDIO_LIVE, CARPETA_REPORTES)):
            return MEDIO_LIVE, True
    # 2) Cualquier particion FAT/exFAT/NTFS de un dispositivo USB.
    rc, out, _ = run(["lsblk", "-J", "-p", "-o", "NAME,TYPE,TRAN,FSTYPE,MOUNTPOINT,PKNAME"])
    if rc == 0:
        datos = json.loads(out)
        def recorrer(nodos, tran_padre=""):
            for n in nodos:
                tran = n.get("tran") or tran_padre
                yield n, tran
                for h in recorrer(n.get("children") or [], tran):
                    yield h
        candidatos = []
        for i, (n, tran) in enumerate(recorrer(datos.get("blockdevices", []))):
            if n.get("type") != "part" or tran != "usb":
                continue
            if (n.get("fstype") or "") not in ("vfat", "exfat", "ntfs"):
                continue
            punto = n.get("mountpoint") or "%s%d" % (PUNTO_MONTAJE_EXTRA, i)
            if not n.get("mountpoint"):
                os.makedirs(punto, exist_ok=True)
                tipo = "ntfs3" if n["fstype"] == "ntfs" else n["fstype"]
                if run(["mount", "-t", tipo, "-o", "rw", n["name"], punto])[0] != 0:
                    continue
            # Preferir la USB de arranque (tiene alamo-wipe.conf o la carpeta live/).
            prioridad = 0 if os.path.isfile(os.path.join(punto, NOMBRE_CONF)) else (
                1 if os.path.isdir(os.path.join(punto, "live")) else 2)
            candidatos.append((prioridad, punto))
        for _, punto in sorted(candidatos):
            if probar_escritura(os.path.join(punto, CARPETA_REPORTES)):
                return punto, True
    # 3) Sin USB escribible: solo memoria RAM (se pierde al apagar).
    local = "/root/alamo"
    os.makedirs(os.path.join(local, CARPETA_REPORTES), exist_ok=True)
    return local, False


def leer_conf(raiz):
    # interpolation=None: las URL de Power Automate llevan '%2F', que ConfigParser trataria como variable.
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict({"general": CONF_DEFECTO})
    for ruta in (os.path.join(DIR_APP, NOMBRE_CONF), os.path.join(raiz, NOMBRE_CONF)):
        if os.path.isfile(ruta):
            try:
                cp.read(ruta, encoding="utf-8-sig")
                LOG.info("Configuración leída: %s" % ruta, consola=False)
            except configparser.Error as e:
                LOG.aviso("No se pudo leer %s: %s" % (ruta, e))
    return dict(cp["general"])


def sincronizar_usb():
    run(["sync"], timeout=60)


# =====================================================================================
#  Datos del equipo
# =====================================================================================

def dmi(clave):
    rc, out, _ = run(["dmidecode", "-s", clave])
    v = out.strip().splitlines()[-1].strip() if rc == 0 and out.strip() else ""
    return "" if (not v or GENERICOS_DMI.match(v)) else v


def estado_secure_boot():
    base = "/sys/firmware/efi"
    if not os.path.isdir(base):
        return "No (arranque BIOS legado)"
    ruta = os.path.join(base, "efivars", "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    try:
        with open(ruta, "rb") as f:
            datos = f.read()
        return "Activo" if datos and datos[-1] == 1 else "Inactivo"
    except OSError:
        return "Desconocido"


def info_equipo():
    cpu = ""
    for l in leer("/proc/cpuinfo").splitlines():
        if l.startswith("model name"):
            cpu = re.sub(r"\s+", " ", l.split(":", 1)[1]).strip()
            break
    ram = ""
    m = re.search(r"MemTotal:\s+(\d+)", leer("/proc/meminfo"))
    if m:
        ram = "%.0f GB" % (int(m.group(1)) / 1024 / 1024)
    ahora = dt.datetime.now()
    return {
        "fabricante": dmi("system-manufacturer") or "NO-DISPONIBLE",
        "modelo": dmi("system-product-name") or "NO-DISPONIBLE",
        "serie": dmi("system-serial-number") or dmi("baseboard-serial-number") or "NO-DISPONIBLE",
        "sku": dmi("system-sku-number"),
        "activo": dmi("chassis-asset-tag"),
        "bios": dmi("bios-version"),
        "cpu": cpu or "N/D",
        "ram": ram or "N/D",
        "secure_boot": estado_secure_boot(),
        "fecha_inicio": ahora.strftime("%Y-%m-%d %H:%M:%S"),
        "fecha_archivo": ahora.strftime("%Y%m%d_%H%M%S"),
        "folio": str(uuid.uuid4()).upper(),
        "ntp": "N/D",
    }


def controlador_raid():
    """Detecta controladoras en modo RAID/VMD (Intel RST) que pueden ocultar discos."""
    rc, out, _ = run(["lspci", "-nn"])
    hallazgos = []
    for l in out.splitlines():
        if "RAID bus controller" in l or "Volume Management Device" in l or "VMD" in l:
            hallazgos.append(l.strip())
    return hallazgos


def hora_sincronizada():
    rc, out, _ = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    return out.strip() == "yes"


# =====================================================================================
#  Deteccion de discos y capacidades
# =====================================================================================

def discos_con_montajes():
    usados = set()
    for l in leer("/proc/mounts").splitlines():
        fuente = l.split(" ")[0]
        if fuente.startswith("/dev/"):
            usados.add(disco_padre(fuente) or fuente)
    return usados


def listar_discos(conf):
    excluir = {disco_arranque()} | discos_con_montajes()
    excluir.discard("")
    permitir_loop = os.environ.get("ALAMO_PERMITIR_LOOP") == "1"   # solo pruebas de laboratorio
    rc, out, err = run(["lsblk", "-J", "-b", "-d", "-o", "NAME,PATH,SIZE,TYPE,TRAN,MODEL,SERIAL,ROTA,RO"])
    if rc != 0:
        LOG.err("lsblk falló: %s" % err.strip())
        return [], []
    discos, excluidos = [], []
    for d in json.loads(out).get("blockdevices", []):
        nombre, ruta, tipo = d.get("name", ""), d.get("path") or "/dev/" + d.get("name", ""), d.get("type")
        tran = (d.get("tran") or "").lower()
        if tipo == "loop" and permitir_loop and int(d.get("size") or 0) > 0:
            pass
        elif tipo != "disk" or nombre.startswith(("zram", "ram", "sr")):
            continue
        motivo = ""
        if ruta in excluir:
            motivo = "USB de arranque o disco con particiones montadas"
        elif es_verdadero(d.get("ro")):
            motivo = "solo lectura"
        elif not int(d.get("size") or 0):
            motivo = "sin medio / tamaño 0"
        elif tran == "usb" and conf.get("permitir_usb_externos", "no").lower() not in ("si", "sí", "yes"):
            motivo = "dispositivo USB externo (deshabilitado en alamo-wipe.conf)"
        reg = {
            "nombre": nombre, "ruta": ruta, "tam": int(d.get("size") or 0),
            "modelo": (d.get("model") or "").strip(), "serie": (d.get("serial") or "").strip(),
            "tran": tran, "rotacional": es_verdadero(d.get("rota")),
        }
        if motivo:
            reg["motivo"] = motivo
            excluidos.append(reg)
        else:
            discos.append(reg)
    for d in discos:
        analizar_disco(d, conf)
    return discos, excluidos


def info_smart(d):
    rc, out, _ = run(["smartctl", "-j", "-i", "-H", "-A", d["ruta"]], timeout=60)
    try:
        j = json.loads(out)
    except ValueError:
        return
    d["modelo"] = j.get("model_name") or d["modelo"]
    d["serie"] = j.get("serial_number") or d["serie"]
    d["firmware"] = j.get("firmware_version") or d.get("firmware", "")
    estado = (j.get("smart_status") or {}).get("passed")
    d["salud"] = "Correcta (PASSED)" if estado is True else ("FALLA (FAILED)" if estado is False else "N/D")
    horas = (j.get("power_on_time") or {}).get("hours")
    d["horas"] = str(horas) if horas is not None else "N/D"


def analizar_disco(d, conf):
    d.setdefault("firmware", "")
    d.update({"salud": "N/D", "horas": "N/D", "capacidades": [], "notas": [], "metodos": []})
    info_smart(d)
    if d["nombre"].startswith("nvme"):
        d["clase"] = "NVMe"
        analizar_nvme(d)
    elif d["tran"] in ("sata", "ata") or (d["nombre"].startswith("sd") and d["tran"] != "usb"):
        d["clase"] = "SATA HDD" if d["rotacional"] else "SATA SSD"
        analizar_ata(d)
    else:
        d["clase"] = {"mmc": "eMMC", "usb": "USB"}.get(d["tran"], "Otro") if d["tran"] else (
            "eMMC" if d["nombre"].startswith("mmcblk") else "Otro")
    # Respaldo por sobrescritura: siempre en HDD/otros; en SSD solo si se habilita.
    ssd = d["clase"] in ("NVMe", "SATA SSD", "eMMC") or not d["rotacional"]
    if not ssd or d["clase"] in ("Otro", "USB") or conf.get("sobrescribir_ssd_si_falla", "no").lower() in ("si", "sí", "yes"):
        d["metodos"].append("sobrescritura")
    d["es_ssd"] = ssd
    d["propuesto"] = d["metodos"][0] if d["metodos"] else ""


def analizar_nvme(d):
    ctrl = os.path.basename(os.path.realpath("/sys/block/%s/device" % d["nombre"]))
    d["ctrl"] = "/dev/" + ctrl if ctrl.startswith("nvme") else re.sub(r"n\d+$", "", d["ruta"])
    nsid = leer("/sys/block/%s/nsid" % d["nombre"])
    if not nsid.isdigit():
        m = re.search(r"n(\d+)$", d["nombre"])
        nsid = m.group(1) if m else "1"
    d["nsid"] = nsid
    rc, out, err = run(["nvme", "id-ctrl", d["ctrl"], "-o", "json"])
    try:
        j = json.loads(out)
    except ValueError:
        d["notas"].append("nvme id-ctrl falló: %s" % (err.strip() or "sin salida"))
        return
    sanicap, fna, oacs = int(j.get("sanicap") or 0), int(j.get("fna") or 0), int(j.get("oacs") or 0)
    d["firmware"] = d["firmware"] or str(j.get("fr", "")).strip()
    d["sanicap"], d["fna"], d["oacs"] = sanicap, fna, oacs
    if sanicap & 0x1:
        d["capacidades"].append("Sanitize Crypto Erase"); d["metodos"].append("nvme-sanitize-crypto")
    if sanicap & 0x2:
        d["capacidades"].append("Sanitize Block Erase"); d["metodos"].append("nvme-sanitize-block")
    if sanicap & 0x4:
        d["capacidades"].append("Sanitize Overwrite")
    if oacs & 0x2:
        if fna & 0x4:
            d["capacidades"].append("Format Crypto Erase"); d["metodos"].append("nvme-format-crypto")
        d["capacidades"].append("Format User Data Erase"); d["metodos"].append("nvme-format-user")
    nn = int(j.get("nn") or 1)
    if nn > 1:
        d["notas"].append("El controlador admite %d namespaces; Sanitize afecta a todos." % nn)


def analizar_ata(d):
    rc, out, err = run(["hdparm", "-I", d["ruta"]])
    d["ata"] = {}
    if rc != 0 or "Security:" not in out:
        d["notas"].append("hdparm -I no devolvió el bloque de seguridad ATA (%s)." % (err.strip() or "sin datos"))
        return
    m = re.search(r"Firmware Revision:\s*(\S+)", out)
    if m and not d["firmware"]:
        d["firmware"] = m.group(1)
    seguridad, dentro = set(), False
    for linea in out.splitlines():
        if linea.startswith("Security:"):
            dentro = True
            continue
        if dentro:
            if linea and not linea[0].isspace():
                break
            norm = " ".join(linea.split())
            if norm:
                seguridad.add(norm)
    texto_seg = " | ".join(sorted(seguridad))
    t_normal = re.search(r"(\d+)min for SECURITY ERASE UNIT", out)
    t_mejor = re.search(r"(\d+)min for ENHANCED SECURITY ERASE UNIT", out)
    a = {
        "soporta": "supported" in seguridad,
        "habilitada": "enabled" in seguridad,
        "bloqueado": "locked" in seguridad,
        "congelado": "frozen" in seguridad,
        "enhanced": "supported: enhanced erase" in seguridad,
        "min_normal": int(t_normal.group(1)) if t_normal else 0,
        "min_enhanced": int(t_mejor.group(1)) if t_mejor else 0,
        "sanitize": "SANITIZE feature set" in out,
        "crypto": "CRYPTO_SCRAMBLE_EXT" in out,
        "block": "BLOCK_ERASE_EXT" in out,
        "texto": texto_seg,
    }
    d["ata"] = a
    if a["sanitize"] and a["crypto"]:
        d["capacidades"].append("ATA Sanitize Crypto"); d["metodos"].append("ata-sanitize-crypto")
    if a["sanitize"] and a["block"]:
        d["capacidades"].append("ATA Sanitize Block"); d["metodos"].append("ata-sanitize-block")
    if a["soporta"]:
        if a["enhanced"] and not d["rotacional"]:
            d["capacidades"].append("Enhanced Security Erase"); d["metodos"].append("ata-secure-erase-enhanced")
        d["capacidades"].append("Security Erase"); d["metodos"].append("ata-secure-erase")
    if a["congelado"]:
        d["notas"].append("Seguridad ATA en estado FROZEN (se intentará suspender/reanudar).")
    if a["bloqueado"]:
        d["notas"].append("El disco está BLOQUEADO con contraseña ATA.")


# =====================================================================================
#  Verificacion por muestreo (antes / despues)
# =====================================================================================

TAM_MUESTRA = 64 * 1024


def tam_dispositivo(ruta):
    rc, out, _ = run(["blockdev", "--getsize64", ruta])
    return int(out.strip()) if rc == 0 and out.strip().isdigit() else 0


def posiciones(tam, n, semilla):
    rnd = random.Random(semilla)
    bloques = max(1, tam // TAM_MUESTRA)
    pos = {0, (bloques // 2) * TAM_MUESTRA, max(0, (bloques - 1) * TAM_MUESTRA)}
    while len(pos) < min(n, bloques):
        pos.add(rnd.randrange(bloques) * TAM_MUESTRA)
    return sorted(pos)


def vaciar_cache(ruta):
    run(["blockdev", "--flushbufs", ruta])
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
    except OSError:
        pass


def leer_muestras(ruta, offsets):
    """Lee con O_DIRECT (evita que la cache del kernel devuelva datos previos al borrado)."""
    vaciar_cache(ruta)
    resultado = []
    fd, directo = None, True
    try:
        fd = os.open(ruta, os.O_RDONLY | getattr(os, "O_DIRECT", 0))
    except OSError:
        directo = False
        fd = os.open(ruta, os.O_RDONLY)
    buf = mmap.mmap(-1, TAM_MUESTRA)
    try:
        for off in offsets:
            try:
                if directo:
                    try:
                        n = os.preadv(fd, [buf], off)
                        datos = bytes(buf[:n])
                    except OSError:
                        directo = False
                        os.close(fd)
                        fd = os.open(ruta, os.O_RDONLY)
                        datos = os.pread(fd, TAM_MUESTRA, off)
                else:
                    datos = os.pread(fd, TAM_MUESTRA, off)
                    try:
                        os.posix_fadvise(fd, off, TAM_MUESTRA, os.POSIX_FADV_DONTNEED)
                    except (AttributeError, OSError):
                        pass
                resultado.append({"offset": off, "hash": hashlib.sha256(datos).hexdigest(),
                                  "clase": clasificar(datos)})
            except OSError as e:
                resultado.append({"offset": off, "hash": "", "clase": "error", "error": str(e)})
    finally:
        buf.close()
        os.close(fd)
    return resultado


def clasificar(datos):
    if not datos:
        return "vacio"
    primero = datos[0]
    if datos.count(primero) == len(datos):
        return {0x00: "ceros", 0xFF: "unos"}.get(primero, "uniforme")
    return "datos"


def evaluar_verificacion(antes, despues, exige_ceros=False):
    previas = {m["offset"]: m for m in antes}
    con_datos = [m for m in antes if m["clase"] == "datos"]
    sin_cambio, errores = [], [m for m in despues if m["clase"] == "error"]
    conteo = {}
    for m in despues:
        conteo[m["clase"]] = conteo.get(m["clase"], 0) + 1
        p = previas.get(m["offset"])
        if p and p["clase"] == "datos" and m["clase"] != "error" and m["hash"] == p["hash"]:
            sin_cambio.append(m["offset"])
    patron = ", ".join("%s: %d" % (k, v) for k, v in sorted(conteo.items()))
    r = {"total": len(despues), "con_datos_previos": len(con_datos), "sin_cambio": len(sin_cambio),
         "errores_lectura": len(errores), "patron_posterior": patron}
    if errores and len(errores) == len(despues):
        r["estado"], r["texto"] = "Fallida", "No fue posible leer el disco después del borrado."
    elif sin_cambio:
        r["estado"] = "Fallida"
        r["texto"] = "%d de %d muestras con datos previos quedaron SIN CAMBIO." % (len(sin_cambio), len(con_datos))
    elif exige_ceros and conteo.get("ceros", 0) != len(despues) - len(errores):
        r["estado"], r["texto"] = "Fallida", "La sobrescritura no dejó todas las muestras en ceros."
    elif not con_datos:
        r["estado"] = "No concluyente"
        r["texto"] = ("Las %d muestras previas no contenían datos (disco vacío o en ceros); "
                      "el borrado se respalda en la confirmación del firmware." % len(antes))
    else:
        r["estado"] = "Aprobada"
        r["texto"] = "%d de %d muestras con datos previos cambiaron tras el borrado; ninguna conserva su contenido." % (
            len(con_datos), len(con_datos))
    return r


# =====================================================================================
#  Metodos de borrado
# =====================================================================================

def progreso(texto):
    sys.stdout.write("\r    %s\033[K" % texto)
    sys.stdout.flush()


def estado_sanitize_nvme(ctrl):
    rc, out, _ = run(["nvme", "sanitize-log", ctrl, "-o", "json"])
    try:
        j = json.loads(out)
    except ValueError:
        return None, None
    sstat, sprog = buscar_clave(j, "sstat"), buscar_clave(j, "sprog")
    try:
        return int(sstat), int(sprog or 0)
    except (TypeError, ValueError):
        return None, None


def m_nvme_sanitize(d, sanact):
    cmd = ["nvme", "sanitize", d["ctrl"], "--sanact=%d" % sanact]
    rc, out, err = run(cmd, timeout=180)
    if rc != 0:
        return False, "El controlador rechazó Sanitize (rc=%d): %s" % (rc, (err or out).strip()[:300]), cmd
    inicio, visto, intentos_none = time.time(), False, 0
    while time.time() - inicio < 8 * 3600:
        sstat, sprog = estado_sanitize_nvme(d["ctrl"])
        if sstat is None:
            intentos_none += 1
            if intentos_none > 30:
                return False, "No se pudo leer el sanitize-log del controlador.", cmd
        else:
            codigo = sstat & 0x7
            if codigo == 2:
                visto = True
                progreso("Sanitize en curso: %.1f %%  (%s)" % (sprog * 100.0 / 65535, duracion(time.time() - inicio)))
            elif codigo in (1, 4):
                print()
                run(["nvme", "ns-rescan", d["ctrl"]])
                run(["blockdev", "--rereadpt", d["ruta"]])
                return True, "Sanitize completado (SSTAT=0x%X%s) en %s." % (
                    sstat, ", en curso observado" if visto else "", duracion(time.time() - inicio)), cmd
            elif codigo == 3:
                print()
                return False, "El controlador reportó FALLO de Sanitize (SSTAT=0x%X)." % sstat, cmd
            elif codigo == 0 and time.time() - inicio > 120:
                return False, "El controlador no inició el Sanitize (SSTAT=0).", cmd
        time.sleep(2)
    return False, "Tiempo máximo de espera agotado para Sanitize.", cmd


def m_nvme_format(d, ses):
    cmd = ["nvme", "format", d["ruta"], "--namespace-id=%s" % d["nsid"], "--ses=%d" % ses, "--force"]
    rc, out, err = run(cmd, timeout=4 * 3600)
    if rc != 0:
        return False, "nvme format falló (rc=%d): %s" % (rc, (err or out).strip()[:300]), cmd
    run(["blockdev", "--rereadpt", d["ruta"]])
    return True, "Format NVM completado: %s" % out.strip()[:200], cmd


def m_ata_sanitize(d, tipo):
    opcion = "--sanitize-crypto-scramble" if tipo == "crypto" else "--sanitize-block-erase"
    cmd = ["hdparm", "--yes-i-know-what-i-am-doing", opcion, d["ruta"]]
    rc, out, err = run(cmd, timeout=180)
    if rc != 0:
        return False, "ATA Sanitize rechazado (rc=%d): %s" % (rc, (err or out).strip()[:300]), cmd
    inicio = time.time()
    while time.time() - inicio < 8 * 3600:
        rc, out, _ = run(["hdparm", "--sanitize-status", d["ruta"]])
        if "In Process" in out:
            m = re.search(r"\((\d+)%\)", out)
            progreso("Sanitize en curso: %s %%  (%s)" % (m.group(1) if m else "?", duracion(time.time() - inicio)))
        elif "Completed Without Error" in out:
            print()
            return True, "ATA Sanitize completado sin error en %s." % duracion(time.time() - inicio), cmd
        elif re.search(r"fail", out, re.I):
            print()
            return False, "El disco reportó fallo de Sanitize: %s" % " ".join(out.split())[:200], cmd
        time.sleep(3)
    return False, "Tiempo máximo de espera agotado para ATA Sanitize.", cmd


def descongelar_ata(d):
    modos = leer("/sys/power/mem_sleep")
    LOG.aviso("Disco FROZEN: suspendiendo 8 s para que el disco se reinicie (modos: %s)." % (modos or "N/D"))
    if "deep" not in modos:
        LOG.aviso("Este equipo no anuncia suspensión S3 ('deep'); puede seguir congelado.")
    run(["rtcwake", "-m", "mem", "-s", "8"], timeout=90)
    time.sleep(6)
    analizar_ata(d)
    return not d.get("ata", {}).get("congelado", True)


def m_ata_security(d, enhanced):
    analizar_ata(d)
    a = d.get("ata", {})
    if not a.get("soporta"):
        return False, "El disco no soporta el conjunto de seguridad ATA.", []
    if a.get("congelado") and not descongelar_ata(d):
        return False, ("El disco sigue FROZEN tras suspender. Apague, conecte de nuevo y reintente, "
                       "o use otro método."), []
    a = d["ata"]
    if a.get("bloqueado"):
        return False, "El disco está bloqueado con una contraseña ATA desconocida.", []
    clave = "Alamo" + secrets.token_hex(4)
    rc, out, err = run(["hdparm", "--user-master", "u", "--security-set-pass", clave, d["ruta"]])
    if rc != 0:
        return False, "No se pudo fijar la contraseña temporal: %s" % (err or out).strip()[:200], []
    opcion = "--security-erase-enhanced" if enhanced else "--security-erase"
    minutos = a.get("min_enhanced" if enhanced else "min_normal") or 0
    limite = int(minutos * 60 * 1.5 + 1800) if minutos else 8 * 3600
    cmd = ["hdparm", "--user-master", "u", opcion, "********", d["ruta"]]
    LOG.info("Tiempo estimado por el fabricante: %s min." % (minutos or "N/D"))
    inicio = time.time()
    rc, out, err = run(["hdparm", "--user-master", "u", opcion, clave, d["ruta"]], timeout=limite)
    # Nunca dejar el disco con contrasena: comprobar y retirar si quedo habilitada.
    analizar_ata(d)
    if d.get("ata", {}).get("bloqueado"):
        run(["hdparm", "--user-master", "u", "--security-unlock", clave, d["ruta"]])
    if d.get("ata", {}).get("habilitada") or d.get("ata", {}).get("bloqueado"):
        run(["hdparm", "--user-master", "u", "--security-disable", clave, d["ruta"]])
        analizar_ata(d)
    if d.get("ata", {}).get("habilitada"):
        LOG.err("¡ATENCIÓN! El disco quedó con contraseña ATA temporal: %s" % clave)
    if rc != 0:
        return False, "Security Erase falló (rc=%d): %s" % (rc, (err or out).strip()[:300]), cmd
    run(["blockdev", "--rereadpt", d["ruta"]])
    return True, "Security Erase completado en %s; contraseña temporal retirada." % duracion(time.time() - inicio), cmd


def m_sobrescritura(d):
    cmd = ["shred", "-v", "-n", "0", "-z", d["ruta"]]
    LOG.info("Sobrescritura en curso (puede tardar horas en discos grandes)...")
    try:
        p = subprocess.run(cmd)
        rc = p.returncode
    except OSError as e:
        return False, "No se pudo ejecutar shred: %s" % e, cmd
    run(["sync"], timeout=600)
    if rc != 0:
        return False, "shred terminó con código %d." % rc, cmd
    return True, "Sobrescritura completa con ceros (1 pasada).", cmd


def ejecutar_metodo(d, metodo):
    if metodo == "nvme-sanitize-crypto":
        return m_nvme_sanitize(d, 4)
    if metodo == "nvme-sanitize-block":
        return m_nvme_sanitize(d, 2)
    if metodo == "nvme-format-crypto":
        return m_nvme_format(d, 2)
    if metodo == "nvme-format-user":
        return m_nvme_format(d, 1)
    if metodo == "ata-sanitize-crypto":
        return m_ata_sanitize(d, "crypto")
    if metodo == "ata-sanitize-block":
        return m_ata_sanitize(d, "block")
    if metodo == "ata-secure-erase-enhanced":
        return m_ata_security(d, True)
    if metodo == "ata-secure-erase":
        return m_ata_security(d, False)
    if metodo == "sobrescritura":
        return m_sobrescritura(d)
    return False, "Método desconocido: %s" % metodo, []


def borrar_disco(d, conf, simulacion):
    """Ejecuta la cadena de metodos con verificacion previa/posterior. Devuelve el registro para el certificado."""
    r = {k: d.get(k, "") for k in ("ruta", "clase", "modelo", "serie", "firmware", "tam", "salud", "horas")}
    r.update({"capacidades": d.get("capacidades", []), "notas": list(d.get("notas", [])), "intentos": [],
              "metodo": "", "nivel": "", "comando": "", "inicio": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    t0 = time.time()
    LOG.paso("Disco %s | %s | S/N %s | %s" % (d["ruta"], d["modelo"] or "?", d["serie"] or "?", tam_legible(d["tam"])))
    if not d["metodos"]:
        r.update({"estado": "Fallido", "fin": r["inicio"], "duracion": "0 s",
                  "verificacion": {"estado": "N/A", "texto": "No se ejecutó."}})
        r["notas"].append("No hay método de borrado disponible para este disco (¿controladora en RAID/VMD?).")
        LOG.err(r["notas"][-1])
        return r

    tam = tam_dispositivo(d["ruta"]) or d["tam"]
    n = int(conf.get("muestras_verificacion", "32") or 32)
    offs = posiciones(tam, n, secrets.randbits(64))
    LOG.info("Muestreo previo: %d muestras de 64 KiB..." % len(offs))
    antes = leer_muestras(d["ruta"], offs)
    LOG.info("Muestras con datos antes del borrado: %d/%d" % (sum(1 for m in antes if m["clase"] == "datos"), len(antes)))

    if simulacion:
        metodo = d["metodos"][0]
        nivel, desc = NIVEL_METODO[metodo]
        r.update({"metodo": desc, "nivel": nivel, "estado": "Simulación", "comando": "(no ejecutado)",
                  "verificacion": {"estado": "Simulación", "texto": "Muestreo previo realizado (%d muestras); "
                                   "no se borró ni se verificó el disco." % len(antes)}})
        r["intentos"].append({"metodo": desc, "resultado": "Simulación", "detalle": "No ejecutado."})
        LOG.aviso("[SIMULACIÓN] Se aplicaría: %s" % desc)
    else:
        exito = False
        senal_previa = signal.signal(signal.SIGINT, signal.SIG_IGN)   # no interrumpir un borrado a medias
        try:
            for metodo in d["metodos"]:
                nivel, desc = NIVEL_METODO[metodo]
                LOG.paso("Aplicando: %s" % desc)
                ok, detalle, cmd = ejecutar_metodo(d, metodo)
                r["intentos"].append({"metodo": desc, "resultado": "Correcto" if ok else "Falló", "detalle": detalle})
                (LOG.ok if ok else LOG.err)(detalle)
                if ok:
                    r.update({"metodo": desc, "nivel": nivel, "comando": cmd_txt(cmd), "metodo_id": metodo})
                    exito = True
                    break
                LOG.aviso("Se intentará el siguiente método disponible.")
        finally:
            signal.signal(signal.SIGINT, senal_previa)

        if not exito:
            r.update({"estado": "Fallido", "verificacion": {"estado": "N/A", "texto": "Ningún método se completó."}})
        else:
            LOG.info("Verificación posterior...")
            time.sleep(2)
            despues = leer_muestras(d["ruta"], offs)
            v = evaluar_verificacion(antes, despues, exige_ceros=(r.get("metodo_id") == "sobrescritura"))
            r["verificacion"] = v
            (LOG.ok if v["estado"] != "Fallida" else LOG.err)("Verificación %s: %s" % (v["estado"], v["texto"]))
            if v["estado"] == "Fallida":
                r["estado"] = "Fallido"
            elif r.get("metodo_id") == "sobrescritura" and d.get("es_ssd"):
                r["estado"] = "Parcial"
                r["notas"].append("Sobrescritura en SSD: el firmware puede conservar bloques de reserva "
                                  "(NIST 800-88 no la considera Purge para memoria flash).")
            else:
                r["estado"] = "Exitoso"
    r["fin"] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    r["duracion"] = duracion(time.time() - t0)
    r["muestras"] = len(offs)
    return r


# =====================================================================================
#  Prueba de recuperacion (evidencia opcional, documento aparte del certificado)
# =====================================================================================

# Firmas de estructura de disco: (posicion dentro del sector de 512 B, bytes, descripcion).
FIRMAS_SECTOR = [
    (0, b"EFI PART", "Encabezado de tabla de particiones GPT"),
    (3, b"NTFS    ", "Sector de arranque NTFS"),
    (3, b"-FVE-FS-", "Volumen cifrado BitLocker"),
    (3, b"EXFAT   ", "Sector de arranque exFAT"),
    (82, b"FAT32   ", "Sector de arranque FAT32"),
    (0, b"FILE0", "Registro de la tabla MFT de NTFS"),
    (0, b"INDX(", "Índice de carpeta NTFS"),
]
# Cabeceras de archivo: (posicion dentro del bloque de 4 KiB, bytes, tipo). Firmas de 4+ bytes
# para que datos aleatorios (borrado criptografico) no produzcan falsos positivos.
FIRMAS_ARCHIVO = [
    (0, b"%PDF-", "PDF"),
    (0, b"PK\x03\x04", "ZIP / Office (docx, xlsx, pptx)"),
    (0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Office antiguo (doc, xls, ppt) / MSI / Outlook"),
    (0, b"!BDN", "Buzón de Outlook (PST/OST)"),
    (0, b"\xFF\xD8\xFF\xE0", "Imagen JPEG"),
    (0, b"\xFF\xD8\xFF\xE1", "Imagen JPEG (EXIF)"),
    (0, b"\x89PNG\r\n\x1a\n", "Imagen PNG"),
    (0, b"Rar!\x1a\x07", "RAR"),
    (0, b"7z\xBC\xAF\x27\x1C", "7-Zip"),
    (0, b"regf", "Registro de Windows"),
    (0, b"SQLite format 3\x00", "Base de datos SQLite (navegadores, apps)"),
    (0, b"{\\rtf", "Documento RTF"),
    (4, b"ftypisom", "Video MP4"),
    (4, b"ftypqt  ", "Video MOV"),
]
REGION_INICIO = 512 * 1024 * 1024      # GPT, particion EFI, MSR e inicio de la particion de Windows
REGION_FINAL = 64 * 1024 * 1024        # GPT de respaldo y particion de recuperacion
MUESTRAS_RAPIDA = 2048                 # bloques aleatorios de 64 KiB (~128 MiB)
LIMITE_PHOTOREC_ARCHIVOS = 200         # si se recuperan mas, se detiene: el resultado ya es "Fallida"
LIMITE_PHOTOREC_BYTES = 512 * 1024 * 1024
VELOCIDAD_MB_S = {"NVMe": 1500, "SATA SSD": 450, "SATA HDD": 120}


def tiempo_estimado(d):
    seg = (d.get("tam") or 0) / (VELOCIDAD_MB_S.get(d.get("clase"), 100) * 1e6)
    return "%d min" % max(1, round(seg / 60)) if seg < 5400 else "%.1f h" % (seg / 3600)


def _buscar_firmas(buf, base, firmas, alineacion, hallazgos, limite=200):
    for pos_rel, firma, desc in firmas:
        i = buf.find(firma)
        while i != -1 and len(hallazgos) < limite:
            inicio = i - pos_rel
            h = {"offset": base + inicio, "tipo": desc}
            if inicio >= 0 and (base + inicio) % alineacion == 0 and h not in hallazgos:   # regiones pueden solaparse
                hallazgos.append(h)
            i = buf.find(firma, i + 1)


def _leer_bloques(fd, inicio, total, tam_bloque, directo):
    """Generador de (offset, bytes) leyendo [inicio, inicio+total) en bloques."""
    buf = mmap.mmap(-1, tam_bloque)
    try:
        off = inicio
        while off < inicio + total:
            n_pedido = min(tam_bloque, inicio + total - off)
            try:
                if directo:
                    n = os.preadv(fd, [buf], off)
                    datos = bytes(buf[:min(n, n_pedido)])
                else:
                    datos = os.pread(fd, n_pedido, off)
            except OSError:
                datos = b""
            if not datos:
                break
            yield off, datos
            off += len(datos)
    finally:
        buf.close()


def prueba_rapida(d):
    """Sin escribir nada: particiones, firmas de sistemas de archivos y cabeceras de archivos conocidos."""
    t0 = time.time()
    ruta = d["ruta"]
    tam = tam_dispositivo(ruta) or d.get("tam", 0)
    run(["blockdev", "--rereadpt", ruta])
    vaciar_cache(ruta)
    r = {"tipo": "Rápida", "inicio": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "comprobaciones": []}

    # 1) Particiones que ve el kernel y firmas que reconoce wipefs (no modifica nada con -n).
    nombre = os.path.basename(ruta)
    particiones = sorted(p for p in os.listdir("/sys/block/%s" % nombre)
                         if p.startswith(nombre) and p != nombre) if os.path.isdir("/sys/block/%s" % nombre) else []
    rc, out, _ = run(["wipefs", "-n", "-J", ruta])
    firmas_wipefs = []
    try:
        firmas_wipefs = ["%s (offset %s)" % (s.get("type"), s.get("offset"))
                         for s in json.loads(out or "{}").get("signatures", [])]
    except ValueError:
        pass
    r["comprobaciones"].append({"nombre": "Tabla de particiones / particiones detectadas",
                                "resultado": ", ".join(particiones) or "Ninguna", "ok": not particiones})
    r["comprobaciones"].append({"nombre": "Firmas reconocidas por wipefs",
                                "resultado": "; ".join(firmas_wipefs) or "Ninguna", "ok": not firmas_wipefs})

    # 2) Lectura de inicio, final y bloques aleatorios buscando firmas.
    hallazgos, leidos, ceros = [], 0, 0
    ultimo_pct = -1
    try:
        fd, directo = os.open(ruta, os.O_RDONLY | getattr(os, "O_DIRECT", 0)), True
    except OSError:
        fd, directo = os.open(ruta, os.O_RDONLY), False
    try:
        regiones = [(0, min(REGION_INICIO, tam)), (max(0, tam - REGION_FINAL), min(REGION_FINAL, tam))]
        rnd = random.Random(secrets.randbits(64))
        bloques = max(1, tam // TAM_MUESTRA)
        regiones += [(rnd.randrange(bloques) * TAM_MUESTRA, TAM_MUESTRA) for _ in range(MUESTRAS_RAPIDA)]
        total = sum(t for _, t in regiones)
        for inicio, largo in regiones:
            for off, datos in _leer_bloques(fd, inicio, largo, 1024 * 1024 if largo > TAM_MUESTRA else TAM_MUESTRA, directo):
                leidos += len(datos)
                ceros += len(datos) if datos.count(0) == len(datos) else 0
                _buscar_firmas(datos, off, FIRMAS_SECTOR, 512, hallazgos)
                _buscar_firmas(datos, off, FIRMAS_ARCHIVO, 4096, hallazgos)
            pct = leidos * 100 // max(total, 1)
            if pct != ultimo_pct:
                ultimo_pct = pct
                progreso("Prueba rápida: %d %%  |  firmas encontradas: %d" % (pct, len(hallazgos)))
    finally:
        os.close(fd)
    print()
    tipos = {}
    for h in hallazgos:
        tipos[h["tipo"]] = tipos.get(h["tipo"], 0) + 1
    r["comprobaciones"].append({
        "nombre": "Búsqueda de firmas de sistemas de archivos y cabeceras de archivos (%s analizados)" % tam_legible(min(leidos, tam)),
        "resultado": "; ".join("%s: %d" % kv for kv in sorted(tipos.items())) or "Ninguna firma encontrada",
        "ok": not hallazgos})
    r["hallazgos"] = hallazgos[:50]
    r["leido"] = leidos
    r["contenido"] = "%.0f %% en ceros, %.0f %% con otro contenido (aleatorio o datos)" % (
        ceros * 100.0 / max(leidos, 1), 100 - ceros * 100.0 / max(leidos, 1))
    r["estado"] = "Aprobada" if all(c["ok"] for c in r["comprobaciones"]) else "Fallida"
    r["duracion"] = duracion(time.time() - t0)
    r["herramienta"] = "Análisis propio (alamo_wipe %s) + wipefs" % VERSION
    return r


def _archivo_uniforme(ruta):
    """True si el archivo esta vacio o todos sus bytes son iguales (no contiene informacion)."""
    try:
        with open(ruta, "rb") as f:
            primero = None
            while True:
                bloque = f.read(1024 * 1024)
                if not bloque:
                    return True
                if primero is None:
                    primero = bloque[0]
                if bloque.count(primero) != len(bloque):
                    return False
    except OSError:
        return False


def _descartar_vacios(destino, vistos):
    """Elimina de inmediato lo 'recuperado' que solo contiene un byte repetido. Devuelve cuantos quito."""
    n = 0
    for f in glob.glob(destino + ".*/*"):
        if f in vistos or f.endswith("report.xml") or not os.path.isfile(f):
            continue
        vistos.add(f)
        if _archivo_uniforme(f):
            try:
                os.remove(f)
                n += 1
            except OSError:
                pass
    return n


def prueba_photorec(d):
    """PhotoRec sobre todo el disco. Lo recuperado va a RAM (/tmp), nunca a la USB, y se borra al terminar."""
    t0 = time.time()
    r = {"tipo": "Completa (PhotoRec)", "inicio": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "comprobaciones": []}
    if not shutil.which("photorec"):
        r.update({"estado": "No disponible", "duracion": "0 s", "herramienta": "PhotoRec (no instalado)"})
        return r
    m = re.search(r"Version:\s*(\S+)", run(["photorec", "/version"])[1])
    r["herramienta"] = "PhotoRec %s (TestDisk) - firmas predeterminadas, disco completo" % (m.group(1) if m else "")
    tmp = tempfile.mkdtemp(prefix="photorec_", dir="/tmp")
    destino, log = os.path.join(tmp, "rec"), os.path.join(tmp, "photorec.log")
    cmd = ["photorec", "/log", "/logname", log, "/d", destino, "/cmd", d["ruta"],
           # Firmas predeterminadas de PhotoRec. Las que vienen desactivadas de fabrica (p. ej. 'dovecot',
           # que se detecta con 48 bytes en cero) dan falsos positivos en un disco recien borrado.
           "partition_none,options,paranoid,keep_corrupted_file_no,fileopt,dovecot,disable,search"]
    detenido = ""
    vistos, descartados = set(), 0
    try:
        vaciar_cache(d["ruta"])
        with open(os.path.join(tmp, "salida.txt"), "w") as salida:
            p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=salida, stderr=subprocess.STDOUT)
            while p.poll() is None:
                descartados += _descartar_vacios(destino, vistos)
                archivos = [f for f in glob.glob(destino + ".*/*") if not f.endswith("report.xml")]
                tam = sum(os.path.getsize(f) for f in archivos if os.path.isfile(f))
                progreso("PhotoRec en curso: %s  |  archivos recuperados: %d  |  %s" % (
                    duracion(time.time() - t0), len(archivos), "analizando..."))
                if len(archivos) > LIMITE_PHOTOREC_ARCHIVOS or tam > LIMITE_PHOTOREC_BYTES:
                    detenido = "Se detuvo al superar %d archivos recuperados." % LIMITE_PHOTOREC_ARCHIVOS
                    p.terminate()
                    try:
                        p.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        p.kill()
                    break
                time.sleep(3)
        print()
        descartados += _descartar_vacios(destino, vistos)
        archivos = [f for f in glob.glob(destino + ".*/*") if not f.endswith("report.xml") and os.path.isfile(f)]
        por_tipo = {}
        for f in archivos:
            ext = os.path.splitext(f)[1].lstrip(".").lower() or "sin extensión"
            por_tipo[ext] = por_tipo.get(ext, 0) + 1
        resumen_log = re.findall(r"^(\S+): (\d+)/(\d+) recovered", leer(log), re.M)
        r["archivos"] = len(archivos)
        r["por_tipo"] = por_tipo
        r["descartados_vacios"] = descartados
        r["comprobaciones"].append({
            "nombre": "Archivos recuperados por PhotoRec",
            "resultado": ("%d (%s)" % (len(archivos), ", ".join("%s: %d" % kv for kv in sorted(por_tipo.items())))
                          if archivos else "0") + (" - " + detenido if detenido else ""),
            "ok": not archivos})
        if not archivos and p.returncode not in (0, None) and not detenido:
            r["comprobaciones"][-1]["resultado"] = "PhotoRec terminó con código %s" % p.returncode
            r["comprobaciones"][-1]["ok"] = False
        r["comprobaciones"].append({
            "nombre": "Coincidencias descartadas por no contener datos",
            "resultado": ("%d (contenido formado solo por ceros u otro byte repetido; no es información "
                          "recuperable)" % descartados) if descartados else "0",
            "ok": True})
        r["estado"] = "Aprobada" if all(c["ok"] for c in r["comprobaciones"]) else "Fallida"
        r["log_resumen"] = ["%s: %s/%s" % x for x in resumen_log]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)   # nada recuperado sale de la memoria
    r["duracion"] = duracion(time.time() - t0)
    return r


def ejecutar_pruebas(discos, tipo):
    resultados = []
    for d in discos:
        LOG.paso("Prueba de recuperación en %s (%s %s)" % (d["ruta"], d.get("modelo") or "", d.get("serie") or ""))
        pruebas = []
        if tipo in ("rapida", "ambas"):
            pruebas.append(prueba_rapida(d))
            (LOG.ok if pruebas[-1]["estado"] == "Aprobada" else LOG.err)(
                "Prueba rápida: %s (%s)" % (pruebas[-1]["estado"], pruebas[-1]["duracion"]))
        if tipo in ("completa", "ambas"):
            LOG.info("PhotoRec leerá todo el disco. Tiempo estimado: %s." % tiempo_estimado(d))
            pruebas.append(prueba_photorec(d))
            (LOG.ok if pruebas[-1]["estado"] == "Aprobada" else LOG.err)(
                "PhotoRec: %s, %s archivo(s) recuperado(s) (%s)" % (pruebas[-1]["estado"],
                                                                  pruebas[-1].get("archivos", "?"), pruebas[-1]["duracion"]))
        resultados.append({"ruta": d["ruta"], "clase": d.get("clase", ""), "modelo": d.get("modelo", ""),
                           "serie": d.get("serie", ""), "tam": d.get("tam", 0), "pruebas": pruebas,
                           "estado": "Aprobada" if all(p["estado"] == "Aprobada" for p in pruebas) else
                           ("No disponible" if all(p["estado"] == "No disponible" for p in pruebas) else "Fallida")})
    return resultados


PLANTILLA_EVIDENCIA = r"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Evidencia de Prueba de Recuperación - {{SERIE}}</title>
<style>
@page { size: Letter; margin: 13mm 14mm 15mm 14mm;
  @bottom-right { content: "Página " counter(page) " de " counter(pages); font-size: 7.5pt; color: #7B8794;
  font-family: 'Liberation Sans', 'DejaVu Sans', Arial, sans-serif; } }
body { font-family: 'Liberation Sans', 'DejaVu Sans', Arial, sans-serif; color: #1F2933; font-size: 9.5pt; margin: 0; }
.header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #1F3A5F; padding-bottom: 10px; }
.logo-img { height: 46px; } .marca-texto { font-size: 16pt; font-weight: 700; color: #1F3A5F; }
.folio { text-align: right; font-size: 8.5pt; color: #5B6B7C; } .folio strong { display: block; color: #1F3A5F; font-size: 11pt; }
.titulo { margin: 12px 0 3px; font-size: 14pt; font-weight: 700; } .lead { color: #5B6B7C; margin: 0 0 6px; }
h2 { font-size: 10.5pt; color: #1F3A5F; margin: 12px 0 5px; padding-bottom: 3px; border-bottom: 1px solid #D9E0E7; text-transform: uppercase; }
h3 { font-size: 10pt; margin: 0 0 5px; color: #1F3A5F; display: flex; justify-content: space-between; }
table { width: 100%; border-collapse: collapse; }
.datos td { padding: 4px 8px; border: 1px solid #E3E8EE; vertical-align: top; }
.datos td.k { width: 22%; background: #F5F7FA; color: #5B6B7C; font-weight: 700; }
.lista th { background: #1F3A5F; color: #fff; text-align: left; padding: 5px 7px; font-size: 8.5pt; }
.lista td { padding: 5px 7px; border-bottom: 1px solid #E3E8EE; vertical-align: top; font-size: 8.5pt; }
.mono { font-family: 'DejaVu Sans Mono', monospace; font-size: 8pt; word-break: break-all; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 9px; font-size: 8pt; font-weight: 700; white-space: nowrap; }
.ok { background: #E6F4EA; color: #1E7B34; border: 1px solid #B7DFC2; } .err { background: #FCE8E6; color: #B3261E; border: 1px solid #F4C7C3; }
.neutral { background: #EEF1F5; color: #4A5868; border: 1px solid #D9E0E7; }
.disco { border: 1px solid #D9E0E7; border-radius: 6px; padding: 8px 10px; margin-top: 8px; page-break-inside: avoid; }
.nota { font-size: 8pt; color: #5B6B7C; margin-top: 4px; line-height: 1.35; }
.aviso { margin-top: 8px; padding: 6px 12px; background: #EEF1F5; border: 1px solid #D9E0E7; color: #4A5868; border-radius: 6px; font-size: 8.5pt; }
.footer { margin-top: 14px; padding-top: 6px; border-top: 1px solid #D9E0E7; font-size: 7.5pt; color: #7B8794; }
</style></head><body>
<div class="header"><div>{{LOGO}}</div><div class="folio">Evidencia<strong>{{FOLIO_CORTO}}</strong>{{FECHA}}</div></div>
<div class="titulo">Evidencia de Prueba de Recuperación de Datos</div>
<p class="lead">Documento complementario. Registra los intentos de recuperar información de los medios de
almacenamiento después de su sanitización. Resultado global: {{ESTADO}}</p>
<div class="aviso">Este documento <b>no sustituye</b> al Certificado de Borrado Seguro; es evidencia adicional
opcional. Certificado de referencia: <b class="mono">{{FOLIO_CERT}}</b></div>

<h2>Equipo</h2>
<table class="datos">
<tr><td class="k">Fabricante / Modelo</td><td>{{EQUIPO}}</td><td class="k">Número de serie</td><td class="mono">{{SERIE}}</td></tr>
<tr><td class="k">Fecha de la prueba</td><td>{{FECHA}}</td><td class="k">Folio de evidencia</td><td class="mono">{{FOLIO}}</td></tr>
</table>

<h2>Resultados por disco</h2>
{{DISCOS}}

<h2>Método</h2>
<div class="nota">
<b>Prueba rápida:</b> sin escribir en el disco, comprueba que el sistema no detecte particiones ni firmas
(wipefs) y lee el primer 512 MiB, los últimos 64 MiB y {{MUESTRAS}} bloques aleatorios de 64 KiB buscando
estructuras de NTFS, BitLocker, FAT/exFAT, GPT y tabla MFT, así como cabeceras de archivos comunes (PDF,
Office, Outlook, imágenes, comprimidos, registro de Windows, bases SQLite, video).<br>
<b>Prueba completa:</b> PhotoRec (CGSecurity) recorre todo el disco buscando cientos de tipos de archivo
por su contenido (firmas predeterminadas), sin depender del sistema de archivos. Lo recuperado se guarda solo
en memoria RAM y se elimina al terminar; únicamente se registra la cantidad y el tipo. Las coincidencias cuyo
contenido es solo un byte repetido (por ejemplo, puros ceros) se descartan, porque no contienen información.<br>
Resultado esperado tras un borrado correcto: ninguna firma y 0 archivos recuperados.
</div>
<div class="footer">Folio de evidencia: <span class="mono">{{FOLIO}}</span> &middot; Certificado de referencia: <span class="mono">{{FOLIO_CERT}}</span><br>
Huella de integridad (SHA-256): <span class="mono">{{HUELLA}}</span><br>alamo_wipe.py v{{VERSION}}</div>
</body></html>
"""


def html_evidencia_disco(i, r):
    filas = ""
    for p in r["pruebas"]:
        comps = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(c["nombre"]), esc(c["resultado"]), badge("Correcto" if c["ok"] else "Falló"))
            for c in p.get("comprobaciones", []))
        extra = ""
        if p.get("contenido"):
            extra += '<div class="nota">Contenido leído: %s.</div>' % esc(p["contenido"])
        if p.get("hallazgos"):
            extra += '<div class="nota">Primeras posiciones con firma: %s</div>' % esc(", ".join(
                "%s @ %d" % (h["tipo"], h["offset"]) for h in p["hallazgos"][:8]))
        filas += """<table class="datos" style="margin-top:6px">
<tr><td class="k">Prueba</td><td>%s %s</td><td class="k">Duración</td><td>%s</td></tr>
<tr><td class="k">Herramienta</td><td colspan="3">%s</td></tr></table>
<table class="lista"><thead><tr><th style="width:42%%">Comprobación</th><th>Resultado</th><th style="width:12%%">Estado</th></tr></thead>
<tbody>%s</tbody></table>%s""" % (esc(p["tipo"]), badge(p["estado"]), esc(p.get("duracion", "")),
                                    esc(p.get("herramienta", "")), comps or '<tr><td colspan="3">Sin datos.</td></tr>', extra)
    return """<div class="disco"><h3><span>Disco %d &middot; <span class="mono">%s</span> &middot; %s &middot; %s &middot; S/N %s</span>%s</h3>%s</div>""" % (
        i, esc(r["ruta"]), esc(r["clase"]), esc(r["modelo"] or "N/D"), esc(r["serie"] or "N/D"), badge(r["estado"]), filas)


def generar_evidencia(raiz, conf, equipo, resultados, folio_cert):
    ahora = dt.datetime.now()
    folio = str(uuid.uuid4()).upper()
    global_ = "Aprobada" if resultados and all(r["estado"] == "Aprobada" for r in resultados) else "Fallida"
    datos = {"version": VERSION, "tipo": "EvidenciaRecuperacion", "folio": folio, "certificado_referencia": folio_cert,
             "fecha": ahora.strftime("%Y-%m-%d %H:%M:%S"), "resultado": global_,
             "equipo": {k: equipo.get(k) for k in ("fabricante", "modelo", "serie")}, "discos": resultados}
    etiqueta, valor = huella(datos, conf.get("clave_hmac", ""))
    datos["huella"] = {"algoritmo": etiqueta, "valor": valor}
    valores = {
        "{{LOGO}}": logo_html(raiz, conf["empresa"]), "{{FOLIO}}": esc(folio), "{{FOLIO_CORTO}}": esc(folio[:8]),
        "{{FECHA}}": esc(datos["fecha"]), "{{ESTADO}}": badge(global_), "{{FOLIO_CERT}}": esc(folio_cert or "N/D"),
        "{{EQUIPO}}": esc("%s %s" % (equipo["fabricante"], equipo["modelo"])), "{{SERIE}}": esc(equipo["serie"]),
        "{{MUESTRAS}}": str(MUESTRAS_RAPIDA), "{{HUELLA}}": esc(valor), "{{VERSION}}": VERSION,
        "{{DISCOS}}": "".join(html_evidencia_disco(i + 1, r) for i, r in enumerate(resultados)),
    }
    doc = PLANTILLA_EVIDENCIA
    for k, v in valores.items():
        doc = doc.replace(k, v)
    serie = re.sub(r"[^A-Za-z0-9_-]", "", equipo["serie"]) or "SINSERIE"
    base = "Evidencia_PruebaRecuperacion_%s_%s" % (serie, ahora.strftime("%Y%m%d_%H%M%S"))
    carpeta = os.path.join(raiz, CARPETA_REPORTES)
    os.makedirs(carpeta, exist_ok=True)
    with open(os.path.join(carpeta, base + "_datos.json"), "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    ruta = os.path.join(carpeta, base + ".pdf")
    try:
        from weasyprint import HTML
        HTML(string=doc, base_url=carpeta).write_pdf(ruta)
    except Exception as e:   # noqa: BLE001
        LOG.err("No se pudo generar el PDF de evidencia (%s). Se guarda HTML." % e)
        ruta = os.path.join(carpeta, base + ".html")
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(doc)
    sincronizar_usb()
    return ruta, global_


def menu_prueba(ui, discos, permitir_omitir=True):
    est = ", ".join("%s ~%s" % (os.path.basename(d["ruta"]), tiempo_estimado(d)) for d in discos)
    opciones = [("1", "Rápida (~1 min): particiones, firmas y cabeceras de archivos"),
                ("2", "Completa con PhotoRec (todo el disco: %s)" % est[:40]),
                ("3", "Ambas")]
    if permitir_omitir:
        opciones.append(("4", "No realizar prueba"))
    op = ui.menu("Prueba de recuperación (opcional)",
                 "Evidencia adicional en un documento aparte; no modifica el certificado.\n"
                 "Las pruebas solo leen el disco.\nTiempo estimado de la completa: %s" % est, opciones, 16, 86)
    return {"1": "rapida", "2": "completa", "3": "ambas"}.get(op)


def flujo_prueba(ui, raiz, conf, equipo, discos, tipo, folio_cert):
    os.system("clear")
    print("=" * 78)
    print("  PRUEBA DE RECUPERACIÓN (evidencia, solo lectura) - %s" % equipo["serie"])
    print("=" * 78)
    resultados = ejecutar_pruebas(discos, tipo)
    ruta, global_ = generar_evidencia(raiz, conf, equipo, resultados, folio_cert)
    LOG.ok("Evidencia: %s" % ruta)
    lineas = []
    for r in resultados:
        for p in r["pruebas"]:
            det = ("%s archivo(s) recuperado(s)" % p.get("archivos", 0)) if "PhotoRec" in p["tipo"] else (
                "; ".join(c["resultado"] for c in p["comprobaciones"] if not c["ok"]) or "sin firmas")
            lineas.append("%s  %-20s %s - %s" % (r["ruta"], p["tipo"], p["estado"], det[:60]))
    ui.pausa("Prueba terminada. Presione Enter para ver el resumen...")
    ui.mensaje("Prueba de recuperación: %s" % global_,
               "%s\n\nDocumento: %s\n(Guardado en la USB; no se envía a Power Automate.)" % (
                   "\n".join(lineas), os.path.basename(ruta)), 18, 100)
    return global_


# =====================================================================================
#  Certificado
# =====================================================================================

PLANTILLA = r"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Certificado de Borrado Seguro - {{SERIE}}</title>
<style>
@page { size: Letter; margin: 13mm 14mm 15mm 14mm;
  @bottom-right { content: "Página " counter(page) " de " counter(pages); font-size: 7.5pt; color: #7B8794;
  font-family: 'Liberation Sans', 'DejaVu Sans', Arial, sans-serif; } }
* { box-sizing: border-box; }
body { font-family: 'Liberation Sans', 'DejaVu Sans', Arial, sans-serif; color: #1F2933; font-size: 9.5pt; margin: 0; }
.header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #1F3A5F; padding-bottom: 10px; }
.logo-img { height: 46px; }
.marca-texto { font-size: 16pt; font-weight: 700; color: #1F3A5F; }
.folio { text-align: right; font-size: 8.5pt; color: #5B6B7C; }
.folio strong { display: block; color: #1F3A5F; font-size: 11pt; }
.titulo { margin: 12px 0 3px; font-size: 14pt; font-weight: 700; }
.lead { color: #5B6B7C; margin: 0 0 6px; }
h2 { font-size: 10.5pt; color: #1F3A5F; margin: 12px 0 5px; padding-bottom: 3px; border-bottom: 1px solid #D9E0E7; text-transform: uppercase; letter-spacing: .4px; }
h3 { font-size: 10pt; margin: 0 0 5px; color: #1F3A5F; display: flex; justify-content: space-between; }
table { width: 100%; border-collapse: collapse; }
.datos td { padding: 4px 8px; border: 1px solid #E3E8EE; vertical-align: top; }
.datos td.k { width: 19%; background: #F5F7FA; color: #5B6B7C; font-weight: 700; }
.lista th { background: #1F3A5F; color: #fff; text-align: left; padding: 5px 7px; font-size: 8.5pt; }
.lista td { padding: 5px 7px; border-bottom: 1px solid #E3E8EE; vertical-align: top; font-size: 8.5pt; }
.mono { font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace; font-size: 8pt; word-break: break-all; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 9px; font-size: 8pt; font-weight: 700; white-space: nowrap; }
.ok { background: #E6F4EA; color: #1E7B34; border: 1px solid #B7DFC2; }
.err { background: #FCE8E6; color: #B3261E; border: 1px solid #F4C7C3; }
.warn { background: #FDEBD8; color: #9A4A00; border: 1px solid #F2C9A0; }
.sim { background: #FFF4E5; color: #8A5300; border: 1px solid #F5D9A8; }
.neutral { background: #EEF1F5; color: #4A5868; border: 1px solid #D9E0E7; }
.kpis { display: flex; margin: 4px -4px 0; }
.kpi { flex: 1; margin: 0 4px; border: 1px solid #E3E8EE; border-radius: 6px; padding: 8px 10px; }
.kpi .v { font-size: 14pt; font-weight: 700; color: #1F3A5F; }
.kpi .l { font-size: 8pt; color: #5B6B7C; }
.disco { border: 1px solid #D9E0E7; border-radius: 6px; padding: 8px 10px; margin-top: 8px; page-break-inside: avoid; }
.nota { font-size: 8pt; color: #5B6B7C; margin-top: 4px; }
.aviso { margin-top: 8px; padding: 6px 12px; background: #FFF4E5; border: 1px solid #F5D9A8; color: #8A5300; font-weight: 700; border-radius: 6px; text-align: center; }
.metodologia { font-size: 8pt; color: #5B6B7C; line-height: 1.35; }
.cierre { page-break-inside: avoid; }
.firmas { display: flex; justify-content: space-around; margin-top: 36px; }
.firma { width: 40%; text-align: center; border-top: 1px solid #1F2933; padding-top: 5px; font-size: 8.5pt; color: #5B6B7C; }
.footer { margin-top: 14px; padding-top: 6px; border-top: 1px solid #D9E0E7; font-size: 7.5pt; color: #7B8794; }
</style></head><body>
<div class="header"><div>{{LOGO}}</div><div class="folio">Folio<strong>{{FOLIO_CORTO}}</strong>{{FECHA}}</div></div>
{{BANNER}}
<div class="titulo">Certificado de Borrado Seguro de Datos</div>
<p class="lead">Se hace constar que los medios de almacenamiento del equipo descrito fueron sanitizados desde un
entorno de arranque independiente del sistema operativo, conforme a la guía NIST SP 800-88 Rev. 1
(Guidelines for Media Sanitization). Resultado global: {{ESTADO_GLOBAL}}</p>

<h2>Datos del equipo</h2>
<table class="datos">
<tr><td class="k">Fabricante</td><td>{{FABRICANTE}}</td><td class="k">Modelo</td><td>{{MODELO}}</td></tr>
<tr><td class="k">Número de serie</td><td class="mono">{{SERIE}}</td><td class="k">SKU / Activo</td><td>{{SKU}}</td></tr>
<tr><td class="k">Procesador</td><td>{{CPU}}</td><td class="k">Memoria RAM</td><td>{{RAM}}</td></tr>
<tr><td class="k">BIOS</td><td>{{BIOS}}</td><td class="k">Secure Boot</td><td>{{SECURE_BOOT}}</td></tr>
<tr><td class="k">Inicio</td><td>{{FECHA}}</td><td class="k">Fin</td><td>{{FECHA_FIN}} <span class="nota">(hora NTP: {{NTP}})</span></td></tr>
</table>

<h2>Resumen</h2>
<div class="kpis">
<div class="kpi"><div class="v">{{N_TOTAL}}</div><div class="l">Discos procesados</div></div>
<div class="kpi"><div class="v" style="color:#1E7B34">{{N_OK}}</div><div class="l">Sanitizados y verificados</div></div>
<div class="kpi"><div class="v" style="color:#9A4A00">{{N_PARCIAL}}</div><div class="l">Parciales</div></div>
<div class="kpi"><div class="v" style="color:#B3261E">{{N_FALLA}}</div><div class="l">Con falla</div></div>
</div>

<h2>Detalle por medio de almacenamiento</h2>
{{DISCOS}}
{{EXCLUIDOS}}

<h2>Metodología</h2>
<div class="metodologia">
Cada disco se identifica por modelo y número de serie (SMART). Se aplica el método de sanitización por firmware más
fuerte que el dispositivo soporta (NVMe Sanitize / ATA Sanitize / Security Erase), con métodos de respaldo en
cascada; la sobrescritura con ceros solo se usa en discos mecánicos (NIST <i>Clear</i>) o cuando se habilita
expresamente. Antes del borrado se toman {{MUESTRAS}} muestras de 64 KiB en posiciones aleatorias (incluido el
inicio, la mitad y el final del disco) y se calcula su hash SHA-256; después del borrado se vuelven a leer sin caché
y se confirma que ninguna muestra con datos conserva su contenido. La huella de integridad del pie se calcula sobre
los datos completos de este certificado (archivo JSON adjunto) y se registra en SharePoint al momento del envío.
</div>

<div class="cierre">
<div class="firmas"><div class="firma">Nombre y firma del responsable del borrado</div>
<div class="firma">Nombre y firma de Vo. Bo. TI</div></div>
<div class="footer">ID de transacción: <span class="mono">{{FOLIO}}</span><br>
{{ETIQUETA_HUELLA}}: <span class="mono">{{HUELLA}}</span><br>
alamo_wipe.py v{{VERSION}} &middot; Debian Live &middot; {{SERIE}}</div>
</div>
</body></html>
"""


def esc(v):
    return html.escape("" if v is None else str(v))


def badge(estado):
    clase = {"Exitoso": "ok", "Aprobada": "ok", "Correcto": "ok", "Fallido": "err", "Fallida": "err",
             "Falló": "err", "Parcial": "warn", "No concluyente": "warn", "Simulación": "sim"}.get(estado, "neutral")
    return '<span class="badge %s">%s</span>' % (clase, esc(estado))


def html_disco(i, r):
    v = r.get("verificacion", {})
    intentos = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (esc(t["metodo"]), badge(t["resultado"]),
                                                                       esc(t["detalle"])) for t in r["intentos"])
    notas = "".join('<div class="nota">&#9888; %s</div>' % esc(n) for n in r.get("notas", []))
    verif = esc(v.get("texto", ""))
    if v.get("patron_posterior"):
        verif += '<div class="nota">Lectura posterior: %s. Errores de lectura: %s.</div>' % (
            esc(v["patron_posterior"]), esc(v.get("errores_lectura", 0)))
    return """
<div class="disco"><h3><span>Disco %d &middot; <span class="mono">%s</span> &middot; %s</span>%s</h3>
<table class="datos">
<tr><td class="k">Modelo</td><td>%s</td><td class="k">Número de serie</td><td class="mono">%s</td></tr>
<tr><td class="k">Capacidad</td><td>%s</td><td class="k">Firmware</td><td>%s</td></tr>
<tr><td class="k">Salud SMART</td><td>%s</td><td class="k">Horas de uso</td><td>%s</td></tr>
<tr><td class="k">Método aplicado</td><td>%s</td><td class="k">Nivel NIST</td><td>%s</td></tr>
<tr><td class="k">Inicio / Fin</td><td>%s &rarr; %s</td><td class="k">Duración</td><td>%s</td></tr>
<tr><td class="k">Verificación</td><td colspan="3">%s %s</td></tr>
<tr><td class="k">Comando</td><td colspan="3" class="mono">%s</td></tr>
</table>
<table class="lista" style="margin-top:5px"><thead><tr><th style="width:38%%">Intento</th><th style="width:12%%">Resultado</th><th>Detalle</th></tr></thead>
<tbody>%s</tbody></table>%s</div>""" % (
        i, esc(r["ruta"]), esc(r["clase"]), badge(r["estado"]), esc(r["modelo"] or "N/D"), esc(r["serie"] or "N/D"),
        esc(tam_legible(r["tam"])), esc(r["firmware"] or "N/D"), esc(r["salud"]), esc(r["horas"]),
        esc(r["metodo"] or "Ninguno"), esc(r["nivel"] or "N/A"), esc(r["inicio"]), esc(r.get("fin", "")),
        esc(r.get("duracion", "")), badge(v.get("estado", "N/A")), verif, esc(r.get("comando") or "N/A"),
        intentos or '<tr><td colspan="3">Sin intentos.</td></tr>', notas)


def html_excluidos(excluidos):
    if not excluidos:
        return ""
    filas = "".join('<tr><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td>%s</td></tr>' % (
        esc(e["ruta"]), esc(e["modelo"] or "N/D"), esc(e["serie"] or "N/D"), esc(e["motivo"])) for e in excluidos)
    return ('<h2>Dispositivos no procesados</h2><table class="lista"><thead><tr><th>Dispositivo</th><th>Modelo</th>'
            '<th>Serie</th><th>Motivo</th></tr></thead><tbody>%s</tbody></table>' % filas)


def logo_html(raiz, empresa):
    for ruta in (os.path.join(raiz, "logo.png"), os.path.join(DIR_APP, "logo.png")):
        if os.path.isfile(ruta):
            with open(ruta, "rb") as f:
                return '<img class="logo-img" src="data:image/png;base64,%s" alt="%s">' % (
                    base64.b64encode(f.read()).decode(), esc(empresa))
    return '<span class="marca-texto">%s</span>' % esc(empresa)


def estado_global(resultados, simulacion):
    if simulacion:
        return "Simulación"
    if not resultados:
        return "Fallido"
    estados = {r["estado"] for r in resultados}
    if estados == {"Exitoso"}:
        return "Exitoso"
    if "Fallido" in estados:
        return "Fallido"
    return "Parcial"


def huella(datos, clave_hmac):
    canon = json.dumps(datos, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if clave_hmac:
        return "HMAC-SHA256", hmac.new(clave_hmac.encode("utf-8"), canon, hashlib.sha256).hexdigest()
    return "SHA-256", hashlib.sha256(canon).hexdigest()


def generar_certificado(raiz, conf, equipo, resultados, excluidos, simulacion):
    global_ = estado_global(resultados, simulacion)
    equipo["fecha_fin"] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    datos = {"version": VERSION, "tipo": "BorradoSeguro", "simulacion": simulacion, "resultado": global_,
             "equipo": equipo, "discos": resultados,
             "excluidos": [{k: e[k] for k in ("ruta", "modelo", "serie", "motivo")} for e in excluidos]}
    etiqueta, valor = huella(datos, conf.get("clave_hmac", ""))
    datos["huella"] = {"algoritmo": etiqueta, "valor": valor}

    sku = " / ".join(x for x in (equipo.get("sku"), equipo.get("activo")) if x) or "N/D"
    valores = {
        "{{LOGO}}": logo_html(raiz, conf["empresa"]),
        "{{BANNER}}": ('<div class="aviso">DOCUMENTO DE SIMULACIÓN &mdash; No se borró ningún disco. '
                       'Sin validez como certificado.</div>' if simulacion else ""),
        "{{ESTADO_GLOBAL}}": badge(global_),
        "{{FOLIO}}": esc(equipo["folio"]), "{{FOLIO_CORTO}}": esc(equipo["folio"][:8]),
        "{{FECHA}}": esc(equipo["fecha_inicio"]), "{{FECHA_FIN}}": esc(equipo["fecha_fin"]),
        "{{NTP}}": esc(equipo.get("ntp", "N/D")),
        "{{FABRICANTE}}": esc(equipo["fabricante"]), "{{MODELO}}": esc(equipo["modelo"]),
        "{{SERIE}}": esc(equipo["serie"]), "{{SKU}}": esc(sku), "{{CPU}}": esc(equipo["cpu"]),
        "{{RAM}}": esc(equipo["ram"]), "{{BIOS}}": esc(equipo.get("bios") or "N/D"),
        "{{SECURE_BOOT}}": esc(equipo["secure_boot"]),
        "{{N_TOTAL}}": str(len(resultados)),
        "{{N_OK}}": str(sum(1 for r in resultados if r["estado"] == "Exitoso")),
        "{{N_PARCIAL}}": str(sum(1 for r in resultados if r["estado"] == "Parcial")),
        "{{N_FALLA}}": str(sum(1 for r in resultados if r["estado"] == "Fallido")),
        "{{MUESTRAS}}": esc(conf.get("muestras_verificacion", "32")),
        "{{ETIQUETA_HUELLA}}": "Huella de integridad (%s)" % esc(etiqueta), "{{HUELLA}}": esc(valor),
        "{{VERSION}}": VERSION,
        "{{EXCLUIDOS}}": html_excluidos(excluidos),
        "{{DISCOS}}": "".join(html_disco(i + 1, r) for i, r in enumerate(resultados)),
    }
    doc = PLANTILLA
    for k, v in valores.items():
        doc = doc.replace(k, v)

    serie_arch = re.sub(r"[^A-Za-z0-9_-]", "", equipo["serie"]) or "SINSERIE"
    base = "Certificado_BorradoSeguro_%s_%s%s" % (serie_arch, equipo["fecha_archivo"], "_SIMULACION" if simulacion else "")
    carpeta = os.path.join(raiz, CARPETA_REPORTES)
    os.makedirs(carpeta, exist_ok=True)
    ruta_pdf = os.path.join(carpeta, base + ".pdf")
    ruta_json = os.path.join(carpeta, base + "_datos.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    try:
        from weasyprint import HTML
        HTML(string=doc, base_url=carpeta).write_pdf(ruta_pdf)
    except Exception as e:   # noqa: BLE001 - se informa y se guarda el HTML como respaldo
        LOG.err("No se pudo generar el PDF (%s). Se guarda HTML." % e)
        ruta_pdf = os.path.join(carpeta, base + ".html")
        with open(ruta_pdf, "w", encoding="utf-8") as f:
            f.write(doc)
    sincronizar_usb()
    return ruta_pdf, ruta_json, datos, global_


# =====================================================================================
#  Red y Power Automate
# =====================================================================================

def host_webhook(conf):
    url = conf.get("webhook_url", "").strip()
    return urllib.parse.urlparse(url).hostname if url else ""


def hay_red(conf):
    url = urllib.parse.urlparse(conf.get("webhook_url", "").strip())
    host = url.hostname or "login.microsoftonline.com"
    puerto = url.port or (80 if url.scheme == "http" else 443)
    try:
        socket.create_connection((host, puerto), timeout=5).close()
        return True
    except OSError:
        return False


def esperar_red(conf, segundos):
    limite = time.time() + segundos
    while time.time() < limite:
        if hay_red(conf):
            return True
        time.sleep(2)
    return False


def enviar_webhook(conf, payload):
    url = conf.get("webhook_url", "").strip()
    if not url:
        return False, "webhook_url vacío en alamo-wipe.conf"
    cuerpo = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    intentos = max(1, int(conf.get("reintentos_webhook", "3") or 3))
    ultimo = ""
    for i in range(1, intentos + 1):
        try:
            req = urllib.request.Request(url, data=cuerpo, method="POST",
                                         headers={"Content-Type": "application/json; charset=utf-8"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                if 200 <= resp.status < 300:
                    return True, "HTTP %d (intento %d)" % (resp.status, i)
                ultimo = "HTTP %d" % resp.status
        except urllib.error.HTTPError as e:
            ultimo = "HTTP %d" % e.code
            if 400 <= e.code < 500 and e.code not in (408, 429):
                break
        except (urllib.error.URLError, OSError) as e:
            ultimo = str(getattr(e, "reason", e))
        if i < intentos:
            time.sleep(5 * i)
    return False, ultimo


def armar_payload(conf, datos, ruta_pdf):
    with open(ruta_pdf, "rb") as f:
        contenido = f.read()
    eq = datos["equipo"]
    resumen = " | ".join("%s %s S/N %s: %s (%s)" % (r["ruta"], r["modelo"] or "?", r["serie"] or "?", r["estado"],
                                                   r["metodo"] or "sin método") for r in datos["discos"])
    return {
        "hostname": conf.get("etiqueta_hostname", "BORRADO-SEGURO"),
        "serie": eq["serie"],
        "modelo": ("%s %s" % (eq["fabricante"], eq["modelo"])).strip(),
        "tecnico": "-",
        "usuarios": resumen or "Sin discos procesados",
        "fecha": eq["fecha_fin"],
        "nombreArchivo": os.path.basename(ruta_pdf),
        "archivoBase64": base64.b64encode(contenido).decode(),
        "tipo": "BorradoSeguro",
        "resultado": datos["resultado"],
        "folio": eq["folio"],
        "huella": datos["huella"]["valor"],
        "hashPdf": hashlib.sha256(contenido).hexdigest(),
    }


def encolar(raiz, payload):
    carpeta = os.path.join(raiz, CARPETA_PENDIENTES)
    os.makedirs(carpeta, exist_ok=True)
    ruta = os.path.join(carpeta, os.path.splitext(payload["nombreArchivo"])[0] + ".json")
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    sincronizar_usb()
    return ruta


def enviar_pendientes(raiz, conf):
    carpeta = os.path.join(raiz, CARPETA_PENDIENTES)
    if not os.path.isdir(carpeta) or not conf.get("webhook_url", "").strip():
        return 0, 0
    enviados = fallidos = 0
    for nombre in sorted(os.listdir(carpeta)):
        if not nombre.endswith(".json"):
            continue
        ruta = os.path.join(carpeta, nombre)
        try:
            with open(ruta, encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, ValueError):
            continue
        ok, det = enviar_webhook(conf, payload)
        if ok:
            os.makedirs(os.path.join(carpeta, "enviados"), exist_ok=True)
            shutil.move(ruta, os.path.join(carpeta, "enviados", nombre))
            enviados += 1
            LOG.ok("Pendiente enviado: %s" % nombre)
        else:
            fallidos += 1
            LOG.aviso("Pendiente no enviado (%s): %s" % (det, nombre))
    sincronizar_usb()
    return enviados, fallidos


def contar_pendientes(raiz):
    carpeta = os.path.join(raiz, CARPETA_PENDIENTES)
    return len([n for n in os.listdir(carpeta) if n.endswith(".json")]) if os.path.isdir(carpeta) else 0


# =====================================================================================
#  Energia
# =====================================================================================

def en_corriente():
    base = "/sys/class/power_supply"
    if not os.path.isdir(base):
        return True
    hay_bateria = False
    for n in os.listdir(base):
        tipo = leer(os.path.join(base, n, "type"))
        if tipo == "Battery":
            hay_bateria = True
        elif tipo in ("Mains", "USB") and leer(os.path.join(base, n, "online")) == "1":
            return True
    return not hay_bateria


# =====================================================================================
#  Pantallas
# =====================================================================================

def describir(d):
    metodo = NIVEL_METODO[d["propuesto"]][1] if d.get("propuesto") else "SIN MÉTODO DISPONIBLE"
    return "%s | %s | S/N %s | %s -> %s" % (d["clase"], (d["modelo"] or "?")[:22], (d["serie"] or "?")[:16],
                                            tam_legible(d["tam"]), metodo)


def _campos_nmcli(linea):
    """Separa una linea de 'nmcli -t' respetando los ':' escapados como '\\:' (p. ej. en el nombre de la red)."""
    campos = re.split(r"(?<!\\):", linea)
    return [c.replace("\\:", ":").replace("\\\\", "\\") for c in campos]


def interfaces_wifi():
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
    return [c[0] for c in (_campos_nmcli(l) for l in out.splitlines()) if len(c) >= 2 and c[1] == "wifi"]


def conectar_wifi(ui):
    """Asistente de Wi-Fi con whiptail + nmcli: buscar redes, elegir, pedir clave y conectar."""
    run(["rfkill", "unblock", "wifi"])
    run(["nmcli", "radio", "wifi", "on"])
    time.sleep(2)
    if not interfaces_wifi():
        ui.mensaje("Wi-Fi", "No se detectó una tarjeta Wi-Fi utilizable.\n\nPuede faltar el driver o firmware "
                   "de este modelo, o el Wi-Fi estar apagado en la BIOS. Use cable de red o un adaptador "
                   "USB-Ethernet.", 12)
        return False
    while True:
        print("Buscando redes Wi-Fi...")
        rc, out, err = run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "--rescan", "yes"],
                           timeout=45)
        redes = {}
        for linea in out.splitlines():
            c = _campos_nmcli(linea)
            if len(c) < 3 or not c[0].strip():
                continue
            ssid, senal, seg = c[0], int(c[1] or 0) if c[1].isdigit() else 0, c[2].strip()
            if ssid not in redes or senal > redes[ssid][0]:
                redes[ssid] = (senal, seg)
        if not redes:
            if not ui.si_no("Wi-Fi", "No se encontraron redes Wi-Fi.\n\n%s" % (err.strip()[:200] or ""),
                            si="Buscar de nuevo", no="Volver", alto=11):
                return False
            continue
        orden = sorted(redes.items(), key=lambda x: -x[1][0])[:30]
        opciones = [(str(i + 1), "%-32s %3d%%  %s" % (s[:32], v[0], v[1] or "abierta"))
                    for i, (s, v) in enumerate(orden)]
        opciones.append(("R", "Buscar de nuevo"))
        op = ui.menu("Redes Wi-Fi", "Seleccione la red:", opciones, 22, 78)
        if op is None:
            return False
        if op == "R":
            continue
        ssid, (senal, seg) = orden[int(op) - 1]
        if "802.1X" in seg or "EAP" in seg.upper():
            ui.mensaje("Wi-Fi", "La red '%s' usa autenticación empresarial (802.1X, usuario y contraseña).\n\n"
                       "Este asistente solo admite redes con clave compartida (WPA/WPA2/WPA3 Personal) o "
                       "abiertas. Use una red de invitados o el hotspot de un celular." % ssid, 13)
            continue
        cmd = ["nmcli", "device", "wifi", "connect", ssid]
        if seg and seg != "--":
            clave = ui.clave("Wi-Fi: %s" % ssid, "Contraseña de la red '%s':" % ssid)
            if clave is None:
                continue
            cmd += ["password", clave]
        print("Conectando a %s..." % ssid)
        rc, out, err = run(cmd, timeout=60)
        if rc == 0:
            LOG.ok("Conectado a Wi-Fi: %s" % ssid)
            return True
        LOG.aviso("No se pudo conectar a %s: %s" % (ssid, (err or out).strip()[:200]))
        run(["nmcli", "connection", "delete", "id", ssid])   # no dejar un perfil con clave equivocada
        if not ui.si_no("Wi-Fi", "No se pudo conectar a '%s'.\n\n%s\n\nVerifique la contraseña." % (
                ssid, (err or out).strip()[:180]), si="Intentar otra vez", no="Volver", alto=13):
            return False


def pantalla_red(ui, raiz, conf):
    if not conf.get("webhook_url", "").strip():
        ui.mensaje("Red", "No hay webhook_url en alamo-wipe.conf.\n\nLos certificados se guardarán solo en la USB.", 10)
        return False
    LOG.info("Comprobando conexión con %s..." % host_webhook(conf))
    if esperar_red(conf, 12):
        return True
    while True:
        op = ui.menu("Conexión a la red",
                     "No hay conexión con Power Automate (%s).\nConecte el cable de red o configure Wi-Fi." % host_webhook(conf),
                     [("1", "Reintentar (cable Ethernet conectado)"), ("2", "Conectar a Wi-Fi"),
                      ("3", "Continuar sin red (el envío queda pendiente en la USB)")], 14)
        if op == "1":
            print("Esperando conexión...")
            if esperar_red(conf, 20):
                return True
        elif op == "2":
            if conectar_wifi(ui):
                print("Esperando conexión con Power Automate...")
                if esperar_red(conf, 20):
                    return True
                ui.mensaje("Wi-Fi", "Conectado a la red Wi-Fi, pero no hay salida a Internet hacia "
                           "Power Automate.\n\nLa red puede requerir inicio de sesión en navegador (portal "
                           "cautivo) o bloquear ese servicio. Pruebe otra red o un hotspot del celular.", 13)
        else:
            return False


def pantalla_corriente(ui, conf):
    if conf.get("requerir_corriente", "si").lower() not in ("si", "sí", "yes"):
        return True
    while not en_corriente():
        if not ui.si_no("Energía", "El equipo está funcionando con BATERÍA.\n\nConecte el cargador antes de "
                        "borrar: una interrupción a mitad del borrado puede dejar el disco inutilizable.",
                        si="Reintentar", no="Cancelar", alto=12):
            return False
    return True


def diagnostico(ui, raiz, conf, equipo):
    discos, excluidos = listar_discos(conf)
    lineas = ["DIAGNÓSTICO DE HARDWARE - %s" % dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              "Equipo   : %s %s  S/N %s  BIOS %s" % (equipo["fabricante"], equipo["modelo"], equipo["serie"], equipo["bios"]),
              "SecureBoot: %s   Suspensión: %s" % (equipo["secure_boot"], leer("/sys/power/mem_sleep") or "N/D"),
              "Kernel   : %s" % os.uname().release, ""]
    raid = controlador_raid()
    lineas.append("Controladoras RAID/VMD: %s" % ("; ".join(raid) if raid else "ninguna"))
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
    lineas.append("Red: %s" % ("; ".join(" ".join(_campos_nmcli(l)) for l in out.splitlines()) or "sin datos de NetworkManager"))
    lineas.append("Wi-Fi: %s" % (", ".join(interfaces_wifi()) or "NO DETECTADO (driver/firmware o apagado en BIOS)"))
    lineas.append("")
    for d in discos:
        lineas += ["[%s] %s  %s  S/N %s  FW %s  %s" % (d["ruta"], d["clase"], d["modelo"], d["serie"], d["firmware"],
                                                      tam_legible(d["tam"])),
                   "   Salud SMART: %s   Horas: %s" % (d["salud"], d["horas"]),
                   "   Capacidades: %s" % (", ".join(d["capacidades"]) or "ninguna"),
                   "   Métodos (orden): %s" % (" > ".join(d["metodos"]) or "NINGUNO")]
        if d.get("ata"):
            lineas.append("   Seguridad ATA: %s" % d["ata"].get("texto", ""))
        if "sanicap" in d:
            lineas.append("   NVMe sanicap=0x%X fna=0x%X oacs=0x%X ctrl=%s nsid=%s" % (
                d["sanicap"], d["fna"], d["oacs"], d["ctrl"], d["nsid"]))
        lineas += ["   Nota: %s" % n for n in d["notas"]] + [""]
    for e in excluidos:
        lineas.append("[%s] EXCLUIDO: %s (%s)" % (e["ruta"], e["motivo"], e["modelo"]))
    if not discos:
        lineas.append("No se detectaron discos internos. Si el equipo es Dell, revise en BIOS (F2) > Storage que "
                      "el modo sea AHCI/NVMe y no 'RAID On'.")
    serie = re.sub(r"[^A-Za-z0-9_-]", "", equipo["serie"]) or "SINSERIE"
    ruta = os.path.join(raiz, CARPETA_REPORTES, "Diagnostico_%s_%s.txt" % (serie, dt.datetime.now().strftime("%Y%m%d_%H%M%S")))
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")
    sincronizar_usb()
    ui.archivo("Diagnóstico (guardado en la USB)", ruta)
    if not ui.interactiva:
        print("\n".join(lineas))
    return ruta


def flujo_borrado(ui, raiz, es_usb, conf, equipo, simulacion, discos_cli=None, confirmar_cli=False, prueba_cli=None):
    discos, excluidos = listar_discos(conf)
    if not discos:
        raid = controlador_raid()
        ui.mensaje("Sin discos", "No se detectaron discos internos para borrar.\n\n" +
                   ("Se detectó una controladora en modo RAID/VMD:\n%s\n\n" % raid[0][:150] if raid else "") +
                   "En equipos Dell: BIOS (F2) > Storage > SATA/NVMe Operation = AHCI/NVMe.", 16)
        return
    if discos_cli:
        seleccion = [d for d in discos if d["ruta"] in discos_cli or d["nombre"] in discos_cli]
    else:
        claves = ui.lista("Selección de discos" + (" (SIMULACIÓN)" if simulacion else ""),
                          "Marque con ESPACIO los discos a borrar y presione Enter.\nLa USB de arranque no aparece.",
                          [(d["nombre"], describir(d), len(discos) == 1) for d in discos], alto=20, ancho=110)
        if not claves:
            return
        seleccion = [d for d in discos if d["nombre"] in claves]
    if not seleccion:
        ui.mensaje("Sin selección", "No se seleccionó ningún disco.")
        return
    no_seleccionados = [dict(d, motivo="No seleccionado por el operador") for d in discos if d not in seleccion]

    resumen = "\n".join("  %s  %s  S/N %s  (%s)" % (d["ruta"], d["modelo"], d["serie"], tam_legible(d["tam"]))
                        for d in seleccion)
    if not simulacion:
        if not pantalla_corriente(ui, conf):
            return
        if not confirmar_cli:
            texto = ui.entrada("PELIGRO: DESTRUCCIÓN PERMANENTE DE DATOS",
                               "Se borrarán de forma IRRECUPERABLE:\n%s\n\nEquipo: %s %s  S/N %s\n\n"
                               "Para confirmar escriba BORRAR en mayúsculas:" % (
                                   resumen, equipo["fabricante"], equipo["modelo"], equipo["serie"]), 18, 100)
            if texto != "BORRAR":
                ui.mensaje("Cancelado", "Confirmación incorrecta. No se modificó ningún disco.", 8)
                return

    os.system("clear")
    print("=" * 78)
    print("  %s - %s" % ("SIMULACIÓN (no se borra nada)" if simulacion else "BORRADO SEGURO NIST SP 800-88",
                         equipo["serie"]))
    print("=" * 78)
    run(["dmesg", "-n", "1"])
    resultados = [borrar_disco(d, conf, simulacion) for d in seleccion]

    red = hay_red(conf)
    equipo["ntp"] = "sí" if hora_sincronizada() else "no"
    LOG.paso("Generando certificado...")
    ruta_pdf, ruta_json, datos, global_ = generar_certificado(raiz, conf, equipo, resultados,
                                                              excluidos + no_seleccionados, simulacion)
    LOG.ok("Certificado: %s" % ruta_pdf)

    envio = "No aplica (simulación)"
    if not simulacion and ruta_pdf.endswith(".pdf"):
        payload = armar_payload(conf, datos, ruta_pdf)
        if not conf.get("webhook_url", "").strip():
            envio = "Sin webhook configurado (solo USB)"
        elif red:
            ok, det = enviar_webhook(conf, payload)
            if ok:
                envio = "Enviado a Power Automate (%s)" % det
            else:
                encolar(raiz, payload)
                envio = "Falló el envío (%s); quedó pendiente en la USB" % det
        else:
            encolar(raiz, payload)
            envio = "Sin red: quedó pendiente en la USB (se envía en el próximo arranque con red)"
        (LOG.ok if envio.startswith("Enviado") else LOG.aviso)(envio)

    serie = re.sub(r"[^A-Za-z0-9_-]", "", equipo["serie"]) or "SINSERIE"
    try:
        shutil.copy(LOG.ruta, os.path.join(raiz, CARPETA_REPORTES, "Log_%s_%s.txt" % (serie, equipo["fecha_archivo"])))
        sincronizar_usb()
    except OSError:
        pass

    lineas = ["%s  %s  ->  %s" % (r["ruta"], r["modelo"] or "?", r["estado"]) for r in resultados]
    ui.pausa("Proceso terminado. Presione Enter para ver el resumen...")
    ui.mensaje("Resultado: %s" % global_,
               "%s\n\nCertificado: %s\nEnvío: %s%s" % ("\n".join(lineas), os.path.basename(ruta_pdf), envio,
                                                      "" if es_usb else "\n\n¡ATENCIÓN! No hay USB escribible: el "
                                                      "certificado se perderá al apagar."), 18, 90)
    # Prueba de recuperacion opcional: evidencia aparte, solo sobre discos donde se aplico un metodo.
    folio_cert = equipo["folio"]
    equipo["ultimo_folio_cert"] = folio_cert
    borrados = [d for d, r in zip(seleccion, resultados) if r.get("metodo_id")]
    if not simulacion and borrados:
        tipo = prueba_cli or (menu_prueba(ui, borrados) if ui.interactiva else None)
        if tipo:
            flujo_prueba(ui, raiz, conf, equipo, borrados, tipo, folio_cert)
    # Nueva transaccion para el siguiente proceso en el mismo arranque.
    equipo.update({k: v for k, v in info_equipo().items() if k in ("folio", "fecha_inicio", "fecha_archivo")})
    return global_


def prueba_desde_menu(ui, raiz, conf, equipo):
    discos, _ = listar_discos(conf)
    if not discos:
        ui.mensaje("Sin discos", "No se detectaron discos internos.", 8)
        return
    claves = ui.lista("Prueba de recuperación", "Marque con ESPACIO los discos a analizar (solo lectura):",
                      [(d["nombre"], "%s | %s | S/N %s | %s" % (d["clase"], (d["modelo"] or "?")[:24],
                                                               (d["serie"] or "?")[:16], tam_legible(d["tam"])),
                        len(discos) == 1) for d in discos], alto=18, ancho=100)
    sel = [d for d in discos if d["nombre"] in (claves or [])]
    if not sel:
        return
    tipo = menu_prueba(ui, sel, permitir_omitir=False)
    if tipo:
        flujo_prueba(ui, raiz, conf, equipo, sel, tipo,
                     equipo.get("ultimo_folio_cert") or "N/D (prueba independiente del borrado)")


def menu_principal(ui, raiz, es_usb, conf):
    equipo = info_equipo()
    run(["setterm", "--blank", "0", "--powerdown", "0"])
    run(["dmesg", "-n", "1"])
    ui.mensaje("Bienvenido",
               "Sistema de borrado seguro y certificación (NIST SP 800-88).\n\n"
               "Equipo: %s %s\nServicio / Serie: %s\nSecure Boot: %s\n\nUSB de reportes: %s" % (
                   equipo["fabricante"], equipo["modelo"], equipo["serie"], equipo["secure_boot"],
                   "OK" if es_usb else "NO DISPONIBLE (solo memoria)"), 15)
    if pantalla_red(ui, raiz, conf):
        n = contar_pendientes(raiz)
        if n:
            env, fal = enviar_pendientes(raiz, conf)
            ui.mensaje("Envíos pendientes", "Se enviaron %d certificado(s) pendiente(s). Fallidos: %d." % (env, fal), 9)
    while True:
        pend = contar_pendientes(raiz)
        op = ui.menu("Menú principal", "Equipo %s %s  |  S/N %s%s" % (
            equipo["fabricante"], equipo["modelo"], equipo["serie"],
            "\nCertificados pendientes de envío: %d" % pend if pend else ""),
            [("1", "Borrado seguro de discos"),
             ("2", "Modo prueba / simulación (no borra)"),
             ("3", "Prueba de recuperación (evidencia, solo lectura)"),
             ("4", "Diagnóstico de hardware (no borra)"),
             ("5", "Red y reenvío de certificados pendientes"),
             ("6", "Consola de soporte (TI)"),
             ("7", "Apagar el equipo"),
             ("8", "Reiniciar el equipo")], 19)
        if op == "1":
            flujo_borrado(ui, raiz, es_usb, conf, equipo, simulacion=False)
        elif op == "2":
            flujo_borrado(ui, raiz, es_usb, conf, equipo, simulacion=True)
        elif op == "3":
            prueba_desde_menu(ui, raiz, conf, equipo)
        elif op == "4":
            diagnostico(ui, raiz, conf, equipo)
        elif op == "5":
            if pantalla_red(ui, raiz, conf):
                env, fal = enviar_pendientes(raiz, conf)
                ui.mensaje("Red", "Conectado.\nPendientes enviados: %d  |  Fallidos: %d" % (env, fal), 9)
        elif op == "6":
            os.system("clear")
            print("Consola de soporte. Escriba 'exit' para volver al menú.\n")
            subprocess.run(["/bin/bash", "--login"])
        elif op == "7":
            sincronizar_usb()
            subprocess.run(["systemctl", "poweroff"])
            return
        elif op == "8":
            sincronizar_usb()
            subprocess.run(["systemctl", "reboot"])
            return


def main():
    ap = argparse.ArgumentParser(description="Álamo Seguros - borrado seguro NIST 800-88")
    ap.add_argument("--simulacion", action="store_true", help="no borra; certificado marcado")
    ap.add_argument("--diagnostico", action="store_true", help="solo reporta capacidades de los discos")
    ap.add_argument("--disco", action="append", help="disco a procesar sin menú (p. ej. /dev/nvme0n1)")
    ap.add_argument("--confirmar", default="", help="escriba BORRAR para borrado no interactivo")
    ap.add_argument("--destino", help="carpeta raíz para reportes (pruebas)")
    ap.add_argument("--prueba", choices=("rapida", "completa", "ambas"),
                    help="prueba de recuperación; con --confirmar BORRAR se hace después del borrado")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Debe ejecutarse como root.")
        return 1
    if args.destino:
        raiz, es_usb = args.destino, True
        os.makedirs(os.path.join(raiz, CARPETA_REPORTES), exist_ok=True)
    else:
        raiz, es_usb = preparar_destino()
    conf = leer_conf(raiz)
    LOG.info("alamo_wipe v%s | destino: %s" % (VERSION, raiz), consola=False)

    no_interactivo = bool(args.disco or args.diagnostico)
    ui = UI(interactiva=not no_interactivo)
    equipo = info_equipo()
    if args.diagnostico:
        diagnostico(ui, raiz, conf, equipo)
        return 0
    if args.disco and args.prueba and args.confirmar != "BORRAR" and not args.simulacion:
        discos, _ = listar_discos(conf)
        sel = [d for d in discos if d["ruta"] in args.disco or d["nombre"] in args.disco]
        if not sel:
            print("Disco no encontrado o excluido: %s" % ", ".join(args.disco))
            return 2
        r = flujo_prueba(ui, raiz, conf, equipo, sel, args.prueba, "N/D (prueba independiente del borrado)")
        return 0 if r == "Aprobada" else 3
    if args.disco:
        if not args.simulacion and args.confirmar != "BORRAR":
            print("Para borrar sin menú agregue --confirmar BORRAR")
            return 2
        r = flujo_borrado(ui, raiz, es_usb, conf, equipo, args.simulacion, discos_cli=args.disco,
                          confirmar_cli=True, prueba_cli=args.prueba)
        return 0 if r in ("Exitoso", "Simulación") else 3
    menu_principal(ui, raiz, es_usb, conf)
    return 0


def main_protegido():
    """Si algo falla, muestra el error y espera (evita el reinicio en bucle del servicio) y lo guarda en la USB."""
    try:
        return main()
    except KeyboardInterrupt:
        return 130
    except Exception:   # noqa: BLE001
        import traceback
        detalle = traceback.format_exc()
        LOG.err("Error inesperado:\n" + detalle)
        for raiz in (MEDIO_LIVE, "/root"):
            try:
                if raiz == MEDIO_LIVE:
                    run(["mount", "-o", "remount,rw", MEDIO_LIVE])
                ruta = os.path.join(raiz, "Error_alamo_wipe_%s.txt" % dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
                with open(ruta, "w", encoding="utf-8") as f:
                    f.write("alamo_wipe v%s\n\n%s\n\n%s\n" % (VERSION, detalle, "\n".join(LOG.lineas)))
                run(["sync"])
                print("\nEl detalle se guardó en: %s" % ruta)
                break
            except OSError:
                continue
        print("\nOcurrió un error. Tome una foto de esta pantalla y envíela a TI.")
        try:
            input("Presione Enter para reiniciar la aplicación...")
        except EOFError:
            time.sleep(60)
        return 1


if __name__ == "__main__":
    sys.exit(main_protegido())
