#!/usr/bin/env python
"Parse GCC output & add 'override' modifiers to sources under cwd"
import os, sys, re, argparse

class Count:
	def __init__(self):
		self.discovered = 0
		self.done = 0
		self.error = 0
		self.skipped = 0

class File:
	def __init__(self, path):
		self.path = path
		self.numbers = set()
		self.count = Count()

	def load(self):
		# No splitlines() because '\r's must remain untouched
		self.lines = open(self.path, "r").read().split("\n")
		return self

	def edit(self):
		for n in self.numbers:
			self.count.replacedInLine = 0
			line = self.lines[n]
			line = re.sub("{", self.replace, line)
			if self.count.replacedInLine == 0:
				line = re.sub(";", self.replace, line)
			if self.count.replacedInLine == 0:
				line = re.sub("[)]\s*(const)", self.replace, line)
			if self.count.replacedInLine == 0:
				line = re.sub("[)]([^)]*)$", self.replace, line)
			if self.count.replacedInLine == 0:
				print("\r%s:%d: Can't find place to insert in '%s'" % (
					self.path, n + 1, self.lines[n]))
				self.count.error += 1;
			elif self.count.replacedInLine == 1:
				self.count.done += 1
			else:
				print("\r%s:%d: too many insertions in '%s'" % (
					self.path, n + 1, self.lines[n]))
				self.count.done += 1
				self.count.error += 1
			# if self.count.replacedInLine == 0:
			#	continue
			self.lines[n] = re.sub("virtual\s+", "", line)
		return self

	def replace(self, src):
		self.count.replacedInLine += 1
		str = src.group(0);
		if ";" == str:
			return " override;";
		if "{" == str:
			return "override {";
		if src.group(1) == "const":
			return ") const override";
		return ") override" + str[1:];

	def save(self):
		# Not bothering with temp files, if the script does mess
		# all up, restore from git
		open(self.path, "w").write("\n".join(self.lines))
		return self

	def addNumber(self, number):
		self.numbers.add(number)
		return self

	def hasNumber(self, number):
		return number in self.numbers

class Tool:
	def __init__(self, args):
		self.args = args
		self.files = {}
		self.count = Count()
		self.base = os.path.realpath(os.getcwd())
		
	def run(self):
		for inp in self.args.INPUT:
			self.load(inp)
		for f in self.files.values():
			if not f.path.startswith(self.base):
				self.count.skipped += len(f.numbers)
				continue
			sys.stderr.write("\r%4d/%4d Editing %s..." % (
				self.count.done, self.count.discovered, f.path))
			f.load().edit().save()
			self.count.error += f.count.error
			self.count.done += f.count.done
		sys.stderr.write("\n")
		print("Done %d files, %d lines, %d skipped, %d errors" % (
			len(self.files), self.count.done, self.count.skipped,
			self.count.error))

	def load(self, inp):
		for m in re.finditer(
				r"([^\s\n:]+):(\d+):.+can be marked override",
				open(inp, "r").read(),
				re.MULTILINE):
			# print(m.group(0))
			path = os.path.realpath(m.group(1))
			num = int(m.group(2)) - 1
			f = self.files.get(path, File(path))
			if f.hasNumber(num):
				continue
			self.files[path] = f.addNumber(num)
			self.count.discovered += 1
		
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("INPUT", help="Build log file", nargs="+")
Tool(parser.parse_args()).run()
