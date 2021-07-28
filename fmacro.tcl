#!/usr/bin/env tclsh
proc usage {} {
	puts "Find a particular macro definitions in a C++ translation unit"
	puts "USAGE: $::argv0 MACRO_NAME_PART G++_ARGUMENTS ..."
	puts "   or: make CXX=\"$::argv0 MACRO_NAME_PART \[ADDITIONAL_CXXFLAGS\]\""
}

namespace eval fm {}

proc fm::run {} {
	if {[llength $::argv] < 2} {
		return [usage]
	}
	set name [lindex $::argv 0]
	set command {g++ -E -o-}
	set skip 0
	foreach f [lrange $::argv 1 end] {
		if $skip {
			incr skip -1
			continue
		}
		if {$f eq "-o"} {
			set skip 1
			continue
		}
		lappend command $f
	}
	puts ---
	# Need a subshell here to suppress error code if grep finds nothing
	exec >@ stdout {*}$command | egrep "# \[0-9\]|$name" |\
		sh -c "grep -B1 $name || echo $name not found!"
	puts ---
}

fm::run
exit 123
