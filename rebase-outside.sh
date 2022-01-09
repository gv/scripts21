#!/bin/bash -e
if [ $# == 0 -o $# == 1 ]; then
	echo "\
rebase-outside: rebase a branch using out of place working copy
USAGE: $0 BRANCH BASE [REBASE_OPTIONS]"
	exit 1
fi
project=$(basename $(pwd))
src=$(pwd)
name=$1
base=$2
shift
shift
work=../work.$project
set -xe
test -d "$work" ||\
	(git worktree add "$work.tmp" "$name" && mv "$work.tmp" "$work")
(cd "$work" && git rebase --abort || true;\
	 git checkout "$name" &&\
	 git rebase "$base" "$@" &&\
	 # Cannot check out in the main dir when it's checked out in here
	 git checkout --detach)
