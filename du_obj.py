#!/usr/bin/env python
from __future__ import print_function
"Analyze debug info and report .text size contribution per directory/file/line"
import argparse, os, re, subprocess, sys, datetime
try:
	import lldb
except ImportError:
	if sys.platform.startswith("linux"):
		sys.path.append(
			"/usr/lib/python2.7/dist-packages/lldb-3.8")
	else:
		sys.path.append("\
/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/\
Resources/Python")
import lldb

# print("pid %d" % os.getpid())
# sys.stdin.read(1)

def nn(n):
	return ",".join(re.findall(r"\d{1,3}", str(n)[::-1]))[::-1]

class Count:
	def __init__(self, value):
		self.name = value
		self.size = 0

class Input:
	def __init__(self, path, args):
		self.path = path
		self.args = args
		self.error = lldb.SBError()
		self.cs = None
		self.sectionsDumped = False
		d = lldb.SBDebugger.Create()
		if self.args.verbose:
			d.EnableLog("lldb", ["symbol"])
		self.target = self.check(
			d.CreateTarget(self.path, None, None, False, self.error))
		self.module = self.target.GetModuleAtIndex(0)
		pdb = re.sub("[.](dll|exe)$", ".pdb", self.path)
		if pdb != self.path:
			d.HandleCommand("target symbols add %s" % pdb)
			if os.path.realpath(self.module.GetSymbolFileSpec().fullpath) !=\
			   os.path.realpath(pdb):
				raise Exception("Symbol file path must be '%s' but is '%s'" % (
					pdb, self.module.GetSymbolFileSpec().fullpath))
		sys.stderr.write("Module='%s' symbols='%s' %d CUs\n" % (
			self.module.GetFileSpec(), self.module.GetSymbolFileSpec(),
			self.module.GetNumCompileUnits()))
		# HACK & WORKAROUND!
		# Without reading compile_units GetOrCreateCompiland doesn't get called
		# and all the returned LineEntries are invalid on Windows targets!
		for u in self.module.compile_units:
			if 0 and self.args.verbose and u.file.IsValid():
				print("CU path=%s" % (u.file.fullpath))
		if self.args.verbose:
			self.dumpSections()

	def check(self, result):
		if self.error.fail:
			raise Exception(str(self.error))
		return result

	def dumpSections(self):
		if self.sectionsDumped:
			return
		for i in range(self.module.GetNumSections()):
		   	sec = self.module.GetSectionAtIndex(i)
		   	self.printSec(sec)
		self.sectionsDumped = True

	def getCodeSection(self):
		if self.cs:
			return self.cs
		# "for sec in self.module.section" yields None sometimes
		for i in range(self.module.GetNumSections()):
			sec = self.module.GetSectionAtIndex(i)
			if sec.name == ".text" or sec.name == "__TEXT" or (
					sec.name == "PT_LOAD[0]" and sec.GetPermissions() & 4):
				if self.cs:
					self.printSec(sec)
					self.printSec(self.cs)
					raise KeyError("Too many .text sections!")
				self.cs = sec
		if not self.cs:
			self.dumpSections()
			raise KeyError("No .text section!")
		return self.cs

	def getCodeSize(self):
		return self.getCodeSection().GetFileByteSize()

	def getFileSize(self):
		return os.stat(self.path).st_size

	def printSec(self, sec):
		sys.stderr.write(
			"%s: '%s' GetPermissions()=%X GetFileByteSize()=%s\n" % (
				os.path.basename(self.path), sec.GetName(), sec.GetPermissions(),
				nn(sec.GetFileByteSize())))

	def run(self, up):
		# GetStartAddress()/GetEndAddress() can be .o section addresses
		# before link, so only their difference is useful
		text = self.getCodeSection()
		addr = lldb.SBAddress(text, 0)
		while addr.GetOffset() < text.GetFileByteSize():
			c = addr.GetSymbolContext(lldb.eSymbolContextLineEntry)
			e = c.GetLineEntry()
			if 0:
				print("%016X %s:%d" % (
					addr.GetOffset(), e.GetFileSpec(), e.GetLine()))
			size = 1
			if e.IsValid() and not self.args.thorough:
				size = e.GetEndAddress().GetOffset() -\
					e.GetStartAddress().GetOffset()
			up.processEntry(e, size, self, addr)
			addr.OffsetAddress(size)
			up.progress(size)
		sys.stderr.write(" " * 40 + "\r")
		return self

	def run2(self, up):
		for u in self.module.compile_unit:
			for e in u:
				if not e.IsValid():
					raise ValueError("not e.IsValid()")
				size = e.GetEndAddress().GetOffset() -\
					e.GetStartAddress().GetOffset()
				up.processEntry(e, size, self, None)
				up.progress(size)

	def descAddr(self, addr):
		return "%s:%016X" % (addr.GetSection().GetName(), addr.GetOffset())

	def dumpEntry(self, e, addr):
		sys.stderr.write(
			"Entry at %016X: %s-%016X (%d bytes) %s:%d\n" % (
			addr.GetOffset(), self.descAddr(e.GetStartAddress()),
			e.GetEndAddress().GetOffset(),
			e.GetEndAddress().GetOffset() - e.GetStartAddress().GetOffset(),
			e.GetFileSpec(), e.GetLine()))

class FileSpecAndPrefixes:
	def __init__(self):
		self.spec = self.prefixes = None
		
class Context:
	def __init__(self, args):
		self.args = args
		self.other = Count("<other>")
		self.unknown = Count("<unknown>")
		self.accounted = Count("<accounted>")
		self.allCode = Count("<all code>")
		self.allFiles = Count("<all files>")
		self.badSymbols = Count("<bad symbols>")
		self.processedBytes = 0
		self.progressNext = 0
		basePath = self.args.output and\
			os.path.dirname(self.args.output) or os.getcwd()
		self.base = basePath.split(os.sep)[-1]
		if self.args.verbose:
			print("LLDB version = '%s'" % lldb.SBDebugger.GetVersionString())

	def progress(self, size):
		self.processedBytes += size
		if self.processedBytes > self.progressNext:
			sys.stderr.write(
				"	%16s / %16s (%3d%%) other=%16s unknown=%16s\r" % (
				nn(self.processedBytes), nn(self.allCode.size),
				self.processedBytes * 100 / self.allCode.size,
				nn(self.other.size), nn(self.unknown.size)))
			self.progressNext += 2048

	def prepare(self, inputs):
		self.prefixes = []
		self.index = {}
		self.last = FileSpecAndPrefixes()
		for p in self.args.PREFIX:
			parts = self.getParts(p)
			c = Count("/".join(parts))
			self.prefixes += [c]
			for key in self.getPrefixStrings(parts):
				self.index[key] = c

	def getPrefixStrings(self, parts):
		if not parts:
			return
		s = parts[0]
		yield s
		for p in parts[1:]:
			s += "/" + p
			yield s
	
	def run(self):
		if not self.args.input:
			sys.stderr.write("No input files\n")
			sys.exit(1)
		inputs = [Input(p, self.args) for p in self.args.input]
		for input in inputs:
			self.allFiles.size += input.getFileSize()
			self.allCode.size += input.getCodeSize()
		self.prepare(inputs)
		for input in inputs:
			input.run(self)
		self.report()

	def processEntry(self, e, size, input, addr):
		if not e.IsValid():
			self.unknown.size += size
			return
		if self.last.spec == e.file:
			prefixes = self.last.prefixes
		else:
			prefixes = []
			for key in self.getPrefixStrings(self.getParts(e.file.fullpath)):
				try:
					prefixes += [self.index[key]]
				except KeyError:
					pass
			self.last.spec = e.file
			self.last.prefixes = prefixes
		for p in prefixes or [self.other]:
			p.size += size
		self.accounted.size += size

	def report(self):
		self.reportCounts(self.prefixes + self.getCounts())

	def getCounts(self):
		return [
			self.unknown, self.other, self.accounted,
			self.allCode, self.allFiles, self.badSymbols]

	def reportCounts(self, counts):
		for count in counts:
			if True or count.size:
				print(" %16d %s" % (count.size, count.name))

	def getParts(self, path):
		parts = re.split(r"[/\\]+", path)
		# Apparently lldb gets rid of ".."s in LineEntries
		try:
			parts = parts[parts.index(self.base) + 1:]
		except ValueError:
			pass
		return [p.lower() for p in parts]

	def normalizePath(self, path):
		return "/".join(self.getParts(path))

class InstructionSpan:
	def __init__(self, ilist, finished):
		self.ilist, self.finished = ilist, finished

	def print(self, output):
		for i in self.ilist:
			output.print("  %s: %s" % (i.addr.module.file.basename, i))
		if not self.finished:
			output.print("  %s: ..." % i.addr.module.file.basename)
		return self

class SourceLine:
	def __init__(self, text, number):
		self.text = text
		self.number = number
		self.codeSize = 0
		self.instructionSpans = []

class SourceFile:
	def __init__(self, path, name, args):
		self.path = path
		self.name = name
		self.args = args
		# python2:
		# lines = open(self.path).read().decode("windows-1251").splitlines()
		lines = open(self.path, encoding="utf-8").read().splitlines()
		self.lines = [SourceLine(s, i) for i, s in enumerate(lines)]

	def printLines(self, output):
		for line in self.lines:
			m = "%s:%d: %2d %s" % (
				self.name, line.number, line.codeSize, line.text)
			if sys.version_info < (3, 0):
				m = m.encode("utf-8")
			output.print(m)
			if self.args.instructions:
				for s in line.instructionSpans:
					s.print(output)

class Lines(Context):
	def prepare(self, inputs):
		self.files = {}
		self.output = self.args.output and open(self.args.output, "wt") or\
			sys.stdout
		for path in self.args.PREFIX:
			np = self.normalizePath(path)
			self.files[np] = SourceFile(path, np, self.args)

	def report(self):
		for file in self.files.values():
			file.printLines(self)
		self.reportCounts(self.getCounts())

	def print(self, s):
		self.output.write(s + "\n")

	def processEntry(self, e, size, input, addr):
		if not e.IsValid():
			self.unknown.size += size
			return
		f = self.files.get(self.normalizePath(e.file.fullpath))
		if not f:
			self.other.size += size
			return
		self.accounted.size += size
		try:
			if e.line - 1 >= len(f.lines):
				self.badSymbols.size += size
				return
			f.lines[e.line - 1].codeSize += size
			if not self.args.instructions:
				return
			icount = 0
			finished = False
			while icount < 100 and not finished:
				icount += 1
				instrs = input.target.ReadInstructions(addr, icount)
				finished = (instrs.GetSize() >= size)
			f.lines[e.line - 1].instructionSpans += [
				InstructionSpan(instrs, finished)]
		except Exception:
			sys.stderr.write("path='%s' line=%d\n" % (
				e.file.fullpath, e.line))
			raise
		

take_off = datetime.datetime.now()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
	"--input", "-i", action='append', help="Input executable file")
parser.add_argument(
	"--output", "-o", help="Output file")
parser.add_argument(
	"--thorough", action='store_true',
	help="Disregard line entry sizes, resolve every single byte!")
parser.add_argument(
	"--verbose", "-v", action='store_true', help='Verbose')
parser.add_argument(
	"--file", "-f", action='store_true',
	help="""\
Line mode: print annotated contents of every file 
(unnamed args must be file paths""")
parser.add_argument(
	"--instructions", "-g", action="store_true",
	help="Print disassembled instructions under each line (implies -f)")
parser.add_argument(
	"PREFIX", nargs="*",
	help="Dir or file paths to count the code size for each")
args = parser.parse_args()
if args.instructions:
	args.file = True
(args.file and Lines or Context)(args).run() 
sys.stderr.write("%s done in %s\n" % (
	__file__, datetime.datetime.now() - take_off))
