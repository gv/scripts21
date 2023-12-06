#!/usr/bin/env python3.9
import shlex, json, os, subprocess, sys
emacsclient = os.path.join(
    os.path.dirname(__file__),
    "Linux.emacs", "lib-src", "emacsclient")
cmd = sys.argv[1:]
if len(cmd) == 1 and cmd[0].endswith("/"):
	os.execvp(emacsclient, [emacsclient, cmd[0]])
lisp = "(compile %s)"
if cmd[0] == "man":
    lisp = "(man %s)"
    cmd = cmd[1:]
subprocess.check_call([
    emacsclient, "--eval", lisp % json.dumps(shlex.join(cmd))])
sys.exit(0)
