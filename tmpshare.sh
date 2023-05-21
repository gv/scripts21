#!/bin/bash -e
if [ $# == 0 ]; then
  echo "Share a directory using smbd"
  echo "USAGE: $0 DIR [PORT [PASSWORD [SMBD_FLAGS...]]]"
  exit 1
fi
root=$1
port=${2-445}
password=${3-0000}
shift 3 || true
name=$(basename "$root")
user=$(whoami)
tmpdir=/tmp/smb$port
conf=$tmpdir/$user.conf
share_config="
path = $root
# guest ok = yes
writable = yes
force create mode = 774
force user = $user
"
set -xe
rm -fv /tmp/smbd-smb.conf.pid
mkdir -p $tmpdir
rm -rfv $tmpdir/*

echo "
[global]
security = user
smbd:backgroundqueue = no
lock dir = $tmpdir
private dir = $tmpdir
pid directory = $tmpdir
state directory = $tmpdir
ncalrpc dir = $tmpdir/ncalrpc
cache directory = $tmpdir/smbdcache
client min protocol = NT1
server min protocol = NT1
bind interfaces only = yes
# interfaces = lo vboxnet0
# unix extensions = no
follow symlinks = yes
map to guest = Bad User
[t]
$share_config
[$name]
$share_config
" > $conf

if [[ "$SAMBASRC" == *4*11* ]]; then
	f="--log-stdout --debuglevel=2"
else
	f="--debug-stdout --debuglevel=2"
fi
if [ "$SAMBASRC" == "" ]; then
  pdbedit=pdbedit
  smbd=smbd
else
  smbd=smbd/smbd
  pdbedit=utils/pdbedit
  cd "$SAMBASRC/bin/default/source3"
fi
echo "$password
$password"| tee /dev/stderr| $pdbedit -D4 -s "$conf" -t -a -u $user 
ulimit -n 2048
$smbd -p $port --foreground --no-process-group $f\
   --configfile="$conf" "$@"
