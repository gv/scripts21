#!/bin/bash
if [ $# != 2 ]; then
  echo "Sync 2 folders using git. Auto merge all .org files"
  echo "(with '>>>>>>' markers)."
  echo "Repos must be already initialized in both."
  echo "Usage: $0 ONE OTHER"
  exit 1
fi

set -o pipefail
commit='
	git reset --mixed @
	rm -fv *~ *#
	chmod 755 *
	git add -v .
	find . -type f|grep -v ^./.git|grep -v /._|\
		xargs git update-index --chmod +x 
	git commit -m "Update $(pwd)" || true
'

pull='
  cmd=merge
  git fetch "$1" +master:tmp
  git tag -f vgSyncRemote tmp
  if ! git $cmd -Xignore-space-change -Xignore-all-space\
	   -Xignore-space-at-eol\
	   tmp ; then
	git add *.org && git commit || true
	while ! git $cmd tmp ; do
	  PS1="merge:\h:\W.\u\$ " bash || true
	done
  fi
'

main() {
  (cd "$a" && bash -ecx "$commit")
  if [ "$access" != "$remotepath" ]; then
	ssh "$access" "cd $remotepath && $commit"
  else
	(cd "$b" && bash -ecx "$commit")
  fi
  (cd "$a" && bash -ecx "$pull" _pull_script "$b" &&\
	 git bundle create /tmp/vgSync.bundle vgSyncRemote..@)
  # Will fail and stop if no local changes
  # Remote changes will have been already pulled in this case 
  git bundle list-heads /tmp/vgSync.bundle
  pbundle=$(echo "$pull"|sed s,'$1',/tmp/vgSync.bundle,g)
  if [ "$access" != "$remotepath" ]; then
	rsync -aP /tmp/vgSync.bundle "$access:/tmp/vgSync.bundle"
	ssh "$access" "cd $remotepath && $pbundle"
  else
	(cd "$b" && bash -ecx "$pbundle")
  fi
}

# Second folder can be ssh, like "glums.local:/scripts"
access=${2%:*}
remotepath=${2#*:}
set -xe
a=$(cd "$1" && pwd)
if [ "$access" != "$remotepath" ]; then
  b=$2
else
  b=$(cd "$2" && pwd)
fi
# guard against script changes, thanks
# https://unix.stackexchange.com/questions/331837/how-to-read-the-whole-shell-script-before-executing-it
main; exit
