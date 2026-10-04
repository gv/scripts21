#!/bin/sh
while [ $# != 0 ]; do
  case "$1" in
	-sound)
	  sound=$2
	  shift 2
	  ;;
	-subs)
	  subs=$2
	  shift 2
	  ;;
	-white)
	  # Fix if the DVD has a broken palette
	  palette="-palette 0d00ee,eeeeee,101010,eaeaea,0ce60b,eceeed,\
ebff0b,0d617a,7b7b7b,d1d1d1,7b8080,0d950c,0f007b,cfcfec,cfcfcf,7c7c7b"
	  shift
	  ;;
	*)
	  break
	  ;;
  esac
done
	  

if [ $# != 1 ]; then
  echo "USAGE: $0 [OPTIONS] VIDEO_TS"
  exit 1
fi
if [ -z "$sound" ]; then
  echo '`-sound` value must be a stream id (PID in MPEG-TS)'
  exit 1
fi
if [ -z "$subs" ]; then
  echo '`-subs` value must be a stream id (PID in MPEG-TS)'
  exit 1
fi
dir=$1

set -xe
rm -vf $dir/list.txt
for inp in $dir/VTS_01_[1-9].VOB; do
  out=$inp.sound=$sound.subs=$subs.mkv
  ffmpeg -y $palette -probesize 100000000 -analyzeduration 1000M -i $inp\
		 -map "0:#$sound"\
		 -filter_complex "[0:v][0:#$subs]overlay[v]"\
		 -map "[v]" $out
  printf "file '%s'\n" "$(basename $out)"| tee -a $dir/list.txt
done

exec ffmpeg -y -safe 0 -f concat -i $dir/list.txt\
	 $dir/Movie.sound=$sound.subs=$subs.mkv
