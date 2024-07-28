#!/usr/bin/env python3
"""
Adjust g++ command line to produce link map for every link.
Equivalent automake: make 'CXXLD=g++ -Wl,-Map,$@.map'
"""
import os, sys

args = sys.argv[1:]
if not args or args == ["-h"] or args == ["--help"]:
    print("%s: %s" % (__file__, __doc__))
    print("USAGE: cmake -D CMAKE_CXX_COMPILER='%s'" % __file__)
    sys.exit(1)

if not "-c" in sys.argv:
    try:
        m = "-Wl,-Map=%s.map" % args[args.index("-o") + 1]
        sys.stderr.write("Added %s\n" % m)
        sys.stderr.flush()
        args.append(m)
    except ValueError:
        pass
os.execvp("g++", ["g++", "-H"] + args)
