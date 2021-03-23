#!/bin/bash -e
if [ $# != 2 ]; then
	echo "\
rebase-outside: rebase a branch using out of place working copy
USAGE: $0 BRANCH BASE"
	exit 1
fi
project=$(basename $(pwd))
src=$(pwd)
name=$1
base=$2
work=../work.$project
set -xe
test -d "$work" ||\
	(git clone . "$work.tmp" -b "$name" --depth 1 && mv "$work.tmp" "$work")
# Go into "detached head" so we can fetch into any branch name
(cd "$work" && git checkout @^ &&\
	 git fetch -v "$src" "+$name:$name" &&\
	 git fetch -v "$src" "+$base:$base" &&\
	 git checkout "$name" &&\
	 git rebase "$base")
git fetch -v "$work" "+$name:last"
git fetch -v "$work" "+$name:$name"

