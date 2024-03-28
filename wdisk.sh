#!/bin/bash
if [ $# == 0 ]; then
  echo "Boot a Linux disk image or block device in qemu"
  echo "Usage: $0 DRIVE [DRIVE...] [QEMU_OPTIONS...]"
  exit 1
fi
# OVMF.fd0 = all boot options deleted in "Boot Options Manager"
# setup submenu
ovmf=$(dirname "$0")/../src/OVMF.fd0
flags=
interface="if=virtio"
efi="-pflash $ovmf.tmp"
while [ $# != 0 ]; do
  case "$1" in
	*.iso|*.dmg)
	  # Warning:
	  # GRUB on Almalinux 8.4 DVD can't find kernel on if=virtio
	  flags="$flags -drive file=$1,media=cdrom,$interface"
	  ;;
	*.hc)
	  flags="$flags -drive file=$1,format=raw,$interface"
	  ;;
	*.qcow2)
	  flags="$flags -drive file=$1,format=qcow2,$interface"
	  ;;
	/dev/*)
	  flags="$flags -drive file=$1,format=raw,$interface"
	  set -xe
	  diskutil unmountDisk force $1
	  sudo chown $(whoami) $1
	  diskutil unmountDisk force $1
	  ;;
	+usb1)
	  # TODO Only 1 usb stick supported 
	  flags="$flags -usb"
	  interface="if=none,id=stick1 -device usb-storage,drive=stick1"
	  ;;
	+usb2)
	  flags="$flags -device usb-ehci,id=ehci"
	  interface="if=none,id=stick2 -device usb-storage,drive=stick2"
	  ;;
	path=*)
	  echo "Mount command:"
	  echo "mount -t 9p -o trans=virtio,version=9p2000.L t1 PATH"
	  flags="$flags -virtfs local,$1,mount_tag=t1,security_model=none"
	  ;;
	+noefi)
	  efi=
	  ;;
	+sd)
	  interface="if=ide"
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
	 $efi "$@"
stty intr "^C"
