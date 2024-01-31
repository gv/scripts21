#!/bin/bash -e
set -o pipefail
here=$(cd "$(dirname "$0")"; pwd)
export GREP_OPTIONS=
set -x
rm -fv TAGS
if [ $# == 0 ]; then
	git ls-files --recurse-submodules\
		"*.cc" "*.cpp" "*.[chsm]" "*.java" "*.php" "*.py" "*.ks" "*.rb"\
		"*.in" "*.tcl" "*.sh" "*.cxx" "*.hxx" "*.js"
else
  # Doesn't work bc `*` is substituted too soon
  #
  # find "$@" '(' -false\
	#	 $(echo -or\ -iname\ *.{cc,cpp,c,h,java,php,py,ks,pl,pm,in})\
	#	 ')'
  # -E is required for Mac for extended regexp
  pat=".+[.](cc|cpp|c|h|s|m|java|php|py|ks|pl|pm|in)$"
  find -E "$@" -iregex "$pat" || find "$@" -regextype egrep -iregex "$pat"
fi| grep -v unittest| egrep -v "\\btests?\\b|testsuite"|\
	grep -v benchmark|\
	time nice xargs -n100 -t etags -a
# "$here/../tools/afsctool/afsctool" -cvvv TAGS
emacsclient=emacsclient
x=$here/Linux.emacs/lib-src/emacsclient
test -f "$x" && emacsclient=$x
$emacsclient\
  --eval "(progn (tags-reset-tags-tables)(visit-tags-table \"TAGS\"))"
