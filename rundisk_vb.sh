#!/bin/bash
path=$1
if [ "" == "$path" ]; then
   echo "USAGE: $0 PATH_TO_DRIVE" && exit 1
fi

name="$(basename "$path")"
ctrl="sata.$0.$(date)"
vd=~/"$name.vmdk"

set -xe
VBoxManage unregistervm --delete "$name" || true
rm -vf "$vd"
#sudo chmod g+rw "$path"
sudo chown "$(whoami)" "$path"
VBoxManage internalcommands createrawvmdk\
		   -filename "$vd" -rawdisk "$path"
VBoxManage createvm --register --name "$name" 
VBoxManage storagectl "$name" --name "$ctrl" --add sata
VBoxManage storageattach "$name" --storagectl "$ctrl"\
		   --port 0 --device 0 --type hdd --medium "$vd"
# --groups removed cause it didn't clean up VM files properly
VBoxManage modifyvm "$name"\
		   --firmware efi\
		   --memory 2048 --acpi on --boot1 disk\
		   --audio none --nic1 null --nictype1 virtio --mouse usbtablet\
		   --cableconnected1 on\
		   --ioapic on\
		   --description "Updated by $0 on $(date)"
VBoxManage startvm "$name"
