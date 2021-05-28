#!/bin/bash
path=$1
dvd=$2
if [ "" == "$path" ]; then
   echo "USAGE: $0 PATH_TO_DRIVE [PATH_TO_DVD_IMAGE]" && exit 1
fi

name="$(basename "$path")"
ctrl="sata.$0.$(date)"
vd=~/"$name.vmdk"

set -xe
VBoxManage unregistervm --delete "$name" || true
rm -vf "$vd"
sudo chown "$(whoami)" "$path"
diskutil unmountDisk force "$path"
VBoxManage internalcommands createrawvmdk\
		   -filename "$vd" -rawdisk "$path"
# The last command causes partitions to be mounted back...
diskutil unmountDisk force "$path"
VBoxManage createvm --register --name "$name" 
VBoxManage storagectl "$name" --name "$ctrl" --add sata
VBoxManage storageattach "$name" --storagectl "$ctrl"\
		   --port 0 --device 0 --type hdd --medium "$vd"
# '--groups' removed cause it didn't clean up old VM files properly
VBoxManage modifyvm "$name"\
		   --firmware efi\
		   --memory 2048 --acpi on --boot1 dvd\
		   --audio none --nic1 null --nictype1 virtio --mouse usbtablet\
		   --cableconnected1 on\
		   --ioapic on\
		   --description "Updated by $0 on $(date)"
test "" == "$dvd" ||\
	VBoxManage storageattach "$name" --storagectl "$ctrl"\
			   --port 1 --device 0 --type dvddrive --medium "$dvd"
VBoxManage startvm "$name"
