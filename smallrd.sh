#!/bin/sh
kv=$1
if [ -z "$kv" ]; then
  echo "Build small (22MB) initramfs to boot GPD Pocket 2"
  echo "USAGE: $0 KERNEL_VER | MODULES_DIR | INITRAMFS_PATH [DRACUT_OPTS]"
  exit 1
fi
shift
rootfs=$(findmnt -n -o FSTYPE /)
kv=$(basename "$kv")
kv=${kv#initramfs-}
set -xe
# TODO:
#  Prune dracut modules
#  Add a 16x24 console font (part of "i18n")
# Q: why drm*.ko get installed
exec dracut -vv --force --kver "${kv%.img}"\
	 --hostonly --drivers "usb_storage ahci sd_mod"\
	 --omit "i18n openssl plymouth tpm2-tss nss-softokn"\
	 --filesystems $rootfs\
	 --fscks "fsck.$rootfs" "$@"
