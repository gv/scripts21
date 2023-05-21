#!/bin/bash
if [ $# == 0 ]; then
  echo "Boot a Linux disk image or block device in qemu"
  echo "Usage: $0 DRIVE [DRIVE...] [QEMU_OPTIONS...]"
  exit 1
fi
flags=
while [ $# != 0 ]; do
  case "$1" in
	*.iso|*.dmg)
	  # Warning:
	  # GRUB on Almalinux 8.4 DVD can't find kernel on if=virtio
	  flags="$flags -drive file=$1,media=cdrom,if=virtio"
	  ;;
	/dev/*)
	  flags="$flags -drive file=$1,format=raw,if=virtio"
	  set -xe
	  diskutil unmountDisk force $1
	  sudo chown $(whoami) $1
	  diskutil unmountDisk force $1
	  ;;
	-*)
	  break
	  ;;
	*)
	  echo "'$1': expected drive image, block device or an option (-*)"
	  exit 1
  esac
  shift
done
# OVMF.fd0 = all boot options deleted in "Boot Options Manager"
# setup submenu
ovmf=$(dirname "$0")/../src/OVMF.fd0
set -xe
cp $ovmf $ovmf.tmp
stty intr "^]"
nice caffeinate\
	 ${QEMU-~/src/build.qemu6/qemu-system-x86_64}\
	 -m 2.5G\
	 -display default,show-cursor=on -accel hvf -smp 2\
	 $flags\
	 -nic user,model=virtio-net-pci,hostfwd=tcp::3073-:73\
	 -serial stdio\
	 -parallel none\
	 -device virtio-tablet-pci\
	 -pflash $ovmf.tmp "$@"
stty intr "^C"
