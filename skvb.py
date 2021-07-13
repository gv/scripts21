#!/usr/bin/env python
from __future__ import print_function
"Send keys to VirtualBox VM"
import sys, subprocess, argparse, os, re, time

class Row:
    def __init__(self, base, lower, upper):
        self.base = base
        self.lower = lower
        self.upper = upper

class Modifier:
    def __init__(self, code):
        self.code = code
        self.on = False

rows = [
    Row(2, "1234567890-=", "!@#$%^&*()_+"),
    Row(16, "qwertyuiop[]\n", "QWERTYUIOP{}"),
    Row(30, "asdfghjkl;'", "ASDFGHJKL:\""),
    Row(43, "\\zxcvbnm,./", "|ZXCVBNM<>?"),
    Row(57, " ", ""),
]

class VbKeys:
    def __init__(self, args):
        self.args = args
        self.vmName = self.args.machine
        self.shift = Modifier(42)

    def sendCode(self, code):
        subprocess.check_output([
            "VBoxManage", "controlvm", self.vmName, "keyboardputscancode",
            "%02X" % code])
        time.sleep(0.01)

    def setModifier(self, mod, target):
        if mod.on != target:
            sys.stdout.write(target and u'\u2191' or u'\u2193')
            self.sendCode(target and mod.code or (mod.code + 128))
            mod.on = target
        return self

    def run(self):
        if not self.vmName and not self.args.qemu:
            rvms = subprocess.check_output([
                "VBoxManage", "list", "runningvms"]).strip().split("\n")
            if len(rvms) != 1:
                raise Exception("rvms=%s" % rvms)
            self.vmName = re.match("\"(.+)\"", rvms[0]).group(1)
        inp = " ".join(self.args.INPUT) + "\n"
        for m in re.finditer(r".", inp, re.DOTALL):
            self.sendChar(m.group(0))
        self.setModifier(self.shift, False)

    def findInRowAndSend(self, row, line, shiftValue, c):
        try:
            i = line.index(c)
        except ValueError:
            return False
        self.setModifier(self.shift, shiftValue)
        sys.stdout.write(c)
        self.sendCode(row.base + i)
        self.sendCode(row.base + i + 128)
        return True

    def sendChar(self, c):
        for row in rows:
            if self.findInRowAndSend(row, row.lower, False, c) or\
               self.findInRowAndSend(row, row.upper, True, c):
                return
        raise Exception("Character '%s' not found" % c)

class QemuCommands(VbKeys):
	# TODO incomplete
	names = {
		"\n": "ret",
		"=": "equal",
		" ": "spc",
		".": "dot",
		",": "comma",
		"/": "slash",
		"-": "minus",
		":": "shift-semicolon",
		"\\": "backslash"
	}
		
	def __init__(self, args):
		self.args = args
		self.vmName = self.shift = None

	def sendChar(self, c):
		if c.lower() != c:
			print("sendkey shift-%s" % c.lower())
		else:
			print("sendkey %s" % self.names.get(c, c))

	def setModifier(self, mod, target):
		pass

def Tool(args):
	if args.qemu:
		return QemuCommands(args)
	return VbKeys(args)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("-m", "--machine", help="Target machine")
parser.add_argument(
	"-q", "--qemu", action="store_true", help="Print QEMU commands instead")
parser.add_argument("INPUT", nargs="+")
Tool(parser.parse_args()).run()
