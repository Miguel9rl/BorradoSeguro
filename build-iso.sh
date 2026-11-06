#!/bin/bash
# Construye la ISO "Alamo Borrado Seguro".
# Requisitos: Debian 13 (trixie) o un contenedor debian:trixie con --privileged, como root.
#   Linux/VM :  sudo ./build-iso.sh
#   Docker   :  docker run --rm --privileged -v "$PWD":/work -w /work debian:trixie ./build-iso.sh
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
[ "$(id -u)" -eq 0 ] || { echo "Ejecute como root (sudo)."; exit 1; }

echo "==> Instalando live-build..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq live-build debootstrap squashfs-tools xorriso mtools dosfstools \
    grub-efi-amd64-bin grub-pc-bin syslinux-common isolinux ca-certificates >/dev/null

echo "==> Preparando carpeta de construccion..."
rm -rf build && mkdir build
cp -a auto config build/
cd build

# Nombres de paquete que cambian entre versiones de Debian: se agrega el que exista.
agregar_si_existe() { for p in "$@"; do if apt-cache show "$p" >/dev/null 2>&1; then echo "$p" >> config/package-lists/alamo.list.chroot; echo "    + $p"; return 0; fi; done; echo "    ! ninguno de: $*"; }
sed -i 's/^Components: main$/Components: main contrib non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
apt-get update -qq
echo "==> Paquetes variables:"
agregar_si_existe weasyprint python3-weasyprint
agregar_si_existe network-manager-tui          # nmtui (en versiones recientes es paquete aparte)

# Logo opcional: coloque logo.png junto a este script.
[ -f ../logo.png ] && cp ../logo.png config/includes.chroot/opt/alamo/logo.png && echo "==> Logo incluido"

echo "==> lb config / lb build (20-40 min)..."
lb config
lb build

ISO=$(ls -1 *.iso | head -1)
SALIDA="$(cd .. && pwd)/salida"
mkdir -p "$SALIDA"
NOMBRE="alamo-borrado-seguro-$(date +%Y%m%d).iso"
mv "$ISO" "$SALIDA/$NOMBRE"
cp build.log "$SALIDA/" 2>/dev/null || true
cd "$SALIDA"
sha256sum "$NOMBRE" | tee "$NOMBRE.sha256"
ls -lh "$NOMBRE"
echo "==> ISO lista: salida/$NOMBRE"
