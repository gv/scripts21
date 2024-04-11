#!/bin/bash -e
set -o pipefail
list() {
  if [ $# == 0 ]; then
	git ls-files --recurse-submodules\
		"*.cc" "*.cpp" "*.[chsm]" "*.java" "*.php" "*.py" "*.ks" "*.rb"\
		"*.in" "*.tcl" "*.sh" "*.cxx" "*.hxx" "*.inc" "*.js"
  else
	# Doesn't work bc `*` is substituted too soon
	#
	# find "$@" '(' -false\
	  #	 $(echo -or\ -iname\ *.{cc,cpp,c,h,java,php,py,ks,pl,pm,in})\
	  #	 ')'
	# -E is required for Mac for extended regexp
	pat=".+[.](cc|cpp|c|h|s|m|java|php|py|ks|pl|pm|in)$"
	find -E "$@" -iregex "$pat" || find "$@" -regextype egrep -iregex "$pat"
  fi
}

tests="\\btests?\\b|testsuite|unittest|benchmark"
here=$(cd "$(dirname "$0")"; pwd)
export GREP_OPTIONS=
set -x
rm -fv TAGS TAGS.xz
list "$@"| egrep -v $tests|\
  time nice xargs -n100 -t etags -a --regex '/JS_GLOBAL_FN(.+)/\1/'\
	   --regex '/JS_STATIC_CLASS_EX[^,]+\(.+\)/\1/'\
	   --regex '/JSO_DEFINE_EX[^,]+\(.+\)/\1/'
# Add only file names for tests
list "$@"| egrep $tests| time nice xargs -n999 -t etags -a --language=none
# "$here/../tools/afsctool/afsctool" -cvvv TAGS
# xz doesn't work on Mac. Also, mb better results:
#  -rw-r--r--    1 vg  staff   347K Mar 25 22:12 TAGS.bz2
#  -rw-rw-r--    1 vg  staff   375K Mar  9 01:59 TAGS.xz
bzip2 -vf TAGS # This removes the source file
ls -l TAGS.bz2
emacsclient=$(echo $EDITOR|grep emacsclient || echo emacsclient)
x=$here/Linux.emacs/lib-src/emacsclient
test -f "$x" && emacsclient=$x
$emacsclient --eval "(progn
  		 (require 'etags)
		 (tags-reset-tags-tables)
		 (visit-tags-table \"TAGS.bz2\"))"
