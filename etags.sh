#!/bin/bash -e
# Run etags on all sources in directory + load tags into emacs
# Indexing is done in small portions so we know it didn't freeze
#
set -o pipefail
list() {
  if [ $# == 0 ]; then
	git ls-files --recurse-submodules\
		"*.cc" "*.cpp" "*.[chsm]" "*.java" "*.php" "*.py" "*.ks"\
		"*.rb" "*.in" "*.tcl" "*.sh" "*.cxx" "*.hxx" "*.inc" "*.js"\
		"*.rs" "*.pl"
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
etags=$here/build.ctags/etags
roptc=--regex-c++
roptj=--regex-javascript
# global_opts=--guess-language-eagerly
global_opts="--langmap=JavaScript:.js.jsx.mjs.ks"
if ! [ -f "$etags" ]; then
  etags=etags
  roptc=--regex
  roptj=--regex
  global_opts=
fi
export GREP_OPTIONS=
set -x
rm -fv TAGS TAGS.xz
# \(\) = subexpression, () = content. Match from the start
list "$@"| egrep -v $tests|\
  time nice xargs -n100 -t $etags -a $global_opts\
	   $roptc='/JS_GLOBAL_FN(.+)/\1/'\
	   $roptc='/JS_STATIC_CLASS_EX[^,]+\(.+\)/\1/'\
	   $roptc='/JSO_DEFINE_EX[^,]+\(.+\)/\1/'\
	   $roptc='/.*[. ]\(\w+\) = function/\1/'\
	   $roptc='/.*\(\w+\) *: function/\1/'
# Add only file paths for tests (might be empty)
list "$@"| egrep $tests| time nice xargs -n999 -t $etags -a --language=none || true
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
		 (let ((previous tags-file-name))
		 (tags-reset-tags-tables)
		 (visit-tags-table \"TAGS.bz2\")
		 previous))"
