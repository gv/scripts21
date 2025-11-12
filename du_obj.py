#!/usr/bin/env python3
from __future__ import print_function
"Analyze debug info and report .text size contribution per directory/file/line"
import argparse, os, re, subprocess, sys, datetime

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
(unnamed args must be file paths)
Use --git to get file list from git
""")
parser.add_argument(
	"--instructions", "-g", action="store_true",
	help="Print disassembled instructions under each line (implies -f)")
parser.add_argument(
	"--unknown", action="store_true",
	help="Try to resolve symbols for unresolvable locations")
parser.add_argument(
	"--map", "-m", action="append", help="Parse link map")
parser.add_argument(
	"--bydest", action="store_true", help="By destination section")
parser.add_argument(
	"--idebug", action="store_true", help="Include debug sections")
parser.add_argument(
	"--expand", "-x", action="append",
	help="Hanlde object/lib names containing substring as separate sources")
parser.add_argument(
	"--git", help="Get file list + contents from REVISION (-f)")
parser.add_argument(
	"--calls", action="store_true", help="Get function calls (non virtual)")
parser.add_argument(
	"--ctms", help="Call target maximum size")
parser.add_argument(
	"--functions", action="store_true",
	help="Get function symbol sizes and repeat counts")
parser.add_argument(
	"--all", action="store_true", help="Print symbol data")
parser.add_argument(
	"--data", action="store_true", help="Print non code symbols")
parser.add_argument("--ds", action="store_true", help="Dump symbols")
parser.add_argument(
	"--sfp", action="store_true",
	help="Print function that use push bp/mov bp, sp")
parser.add_argument(
	"--types", "-T", action="store_true", help="Print type member layout")
parser.add_argument(
	"--longtype", "-L", action="store_true",
	help="Print type member layout as path expressions")
parser.add_argument(
	"--onlybases", action="store_true", help="Print only bases")
parser.add_argument(
	"--containing", "-I", action="store_true",
	help="List all types whose names contain PREFIX")
parser.add_argument(
	"--derived", "-d", action="store_true",
	help="List all classes derived from PREFIX (1 arg)")
parser.add_argument(
	"--md", action="store_true",
	help="List all classes multiply derived from PREFIX (1 arg)")
parser.add_argument(
	"--target", "-t", action="store_true",
	help="TODO Find paths to targets in a call graph")
parser.add_argument(
	"--show", action="store_true",
	help="Print as much as possible debug info re: given line")
parser.add_argument(
	"--diff", action="store_true", help="Compare section sizes (2 args)")
parser.add_argument(
	"--info", action="store_true",
	help="Print some data about debuginfo files")
parser.add_argument(
	"--match", help="match debuginfo files to this file")
parser.add_argument(
	"--lldb", "-P", help="Path to lldb")
parser.add_argument(
	"PREFIX", nargs="*",
	help="Dir or file paths to count the code size for each")
args = parser.parse_args()

if args.lldb:
	dir = subprocess.check_output([args.lldb, "-P"]).strip().decode()
	print("Adding '%s'..." % dir)
	sys.path.append(dir)
	
try:
	import lldb
	# SBError = lldb.SBError
	from lldb import SBError
except ImportError:
	if sys.platform.startswith("linux"):
		importDirs = [
			"/usr/lib/llvm-18/lib/python3.12/site-packages",
			"/usr/lib/python2.7/dist-packages/lldb-3.8"]
	else:
		importDirs = ["\
/Library/Developer/CommandLineTools/Library/PrivateFrameworks/\
LLDB.framework/Resources/Python"]
	print("Adding %s..." % (importDirs))
	sys.path += importDirs
	
import lldb
from lldb import SBError

def nn(n):
	return ",".join(re.findall(r"\d{1,3}", str(n)[::-1]))[::-1]

def xx(n):
	n = "%X" % n
	return ",".join(re.findall(r"[0-9a-fA-F]{1,4}", n[::-1]))[::-1]

def printComparison(s1, s2, name):
	print(" %24s  %s" % (
		"%s(%s%s)" % (
			nn(s1), (s2 > s1) and "+" or "-", nn(s2-s1)), name))

class Count:
	__slots__ = ("name", "size", "occurences")
	
	def __init__(self, value):
		self.name = value
		self.occurences = self.size = 0

	def __lt__(self, other):
		return self.size < other.size

class EntryFromBlock:
	def __init__(self, block):
		self.file = block.GetInlinedCallSiteFile()
		self.line = block.GetInlinedCallSiteLine()

	def IsValid(self):
		return True

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
		pdb = self.path + ".pdb"
		if not os.path.isfile(pdb):
			pdb = re.sub("[.](dll|exe)$", ".pdb", self.path)
		if pdb != self.path:
			d.HandleCommand("target symbols add %s" % pdb)
			if os.path.realpath(self.module.GetSymbolFileSpec().fullpath) !=\
			   os.path.realpath(pdb):
				raise Exception("Symbol file path must be '%s' but is '%s'" % (
					pdb, self.module.GetSymbolFileSpec().fullpath))
		sys.stderr.write("Module='%s' %d symbols in '%s' %d CUs\n" % (
			self.module.GetFileSpec(),
			self.module.GetNumSymbols(),
			self.module.GetSymbolFileSpec(),
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

	def getSubSections(self, sec):
		for i in range(sec.GetNumSubSections()):
			yield sec.GetSubSectionAtIndex(i)
			for t in self.getSubSections(sec.GetSubSectionAtIndex(i)):
				yield t

	def getAllSections(self):
		# "for sec in self.module.section" yields None sometimes
		for i in range(self.module.GetNumSections()):
			yield self.module.GetSectionAtIndex(i)
			for u in self.getSubSections(self.module.GetSectionAtIndex(i)):
				yield u

	def dumpSections(self):
		if self.sectionsDumped:
			return
		for sec in self.getAllSections():
			self.printSec(sec)
		self.sectionsDumped = True

	def compareSections(self, other):
		map1, map2 = {}, {}
		names = []
		for sec in self.getAllSections():
			map1[sec.name] = sec
			if sec.name in names:
				print("Duplicate section '%s'" % sec.name)
			names.append(sec.name)
		for sec in other.getAllSections():
			map2[sec.name] = sec
			if sec.name in names:
				continue
			names.append(sec.name)
		for name in names:
			s1, s2 = (
				m.get(name) and m.get(name).GetFileByteSize() or 0 for
				m in (map1, map2))
			printComparison(s1, s2, name)

	def getCodeSection(self):
		if self.cs:
			return self.cs
		for sec in self.getAllSections():
			if sec.name == ".text" or sec.name == "__TEXT":
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
				os.path.basename(self.path), sec.GetName(),
				sec.GetPermissions(),
				nn(sec.GetFileByteSize())))

	def run(self, up):
		if self.args.containing or self.args.derived or self.args.md or\
			 self.args.longtype or self.args.onlybases:
			self.args.types = True
		if self.args.types:
			return self.printTypes(self.args.PREFIX)
		# GetStartAddress()/GetEndAddress() can be .o section addresses
		# before link, so only their difference is useful
		text = self.getCodeSection()
		addr = lldb.SBAddress(text, 0)
		while addr.GetOffset() < text.GetFileByteSize():
			c = addr.GetSymbolContext(
				lldb.eSymbolContextLineEntry | lldb.eSymbolContextBlock |
				lldb.eSymbolContextCompUnit)
			e = c.GetLineEntry()
			if 0:
				print("%016X %s:%d" % (
					addr.GetOffset(), e.GetFileSpec(), e.GetLine()))
			size = 1
			if e.IsValid() and not self.args.thorough:
				size = e.GetEndAddress().GetOffset() -\
					e.GetStartAddress().GetOffset()
			# if c.comp_unit.IsValid():
			#	pass
			if e.IsValid():
				up.processEntry(e, size, self, addr)
				up.entries.size += 1
			else:
				up.unknown.size += size
				if self.args.unknown:
					up.processUnknown(addr, size)
			block = c.block
			while block.IsValid():
				if block.GetInlinedCallSiteFile().IsValid():
					up.processEntry(EntryFromBlock(block), size, self, addr)
					up.inlineEntries.size += 1
				block = block.GetParent()
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

	def printFields(self, prefix, deriveds, offset, type):
		bases = [
			type.GetDirectBaseClassAtIndex(i)
			for i in range(type.GetNumberOfDirectBaseClasses())]
		# Location of virtual base is determined by most derived class,
		# virtual bases of bases are not present in final layout.
		# If we have a virtual base, all derived classes contain it too
		# TODO:
		# The class that declares ": public virtual" has the base in
		# the direct bases for some reason - although the offsets are
		# used by other fields in bases. Need to filter that out
		fields = []
		if not self.args.onlybases:
			for i in range(type.num_fields):
				fl = type.GetFieldAtIndex(i)
				fl.isVirt = ""
				fl.deriveds = []
				fields.append(fl)
		if not deriveds:
			for i in range(type.GetNumberOfVirtualBaseClasses()):
				vb = type.GetVirtualBaseClassAtIndex(i)
				vb.isVirt = "(v)";
				vb.deriveds = []
				fields.append(vb)
		for fl in bases:
			fl.isVirt = "";
			fl.deriveds = deriveds + [type]
		for fl in sorted(fields + bases, key=lldb.SBTypeMember.GetOffsetInBytes):
			self.printOneField(prefix, fl.deriveds, offset, fl)

	def printOneField(self, prefix, nds, offset, fl):
		name = fl.name
		ft = fl.GetType().GetCanonicalType()
		if ft.name and name and name != ft.name:
			name = "%s %s" % (ft.name, name)
		if name:
			name += fl.isVirt
		start = offset + fl.GetOffsetInBytes()
		if self.args.longtype:
			prefix = "%s.%s" % (prefix, name)
			print("%d-%d %s" % (start, start + ft.size, prefix))
			self.printFields(prefix, nds, start, ft)
			return
		print("%s%-8s %s" % (
			prefix, "%d-%d" % (start, start + ft.size), name))
		self.printFields(prefix + "-", nds, start, ft)

	def getDerivationPath(self, type, baseName, includeVirt=True):
		# Include type itself so we see if the name can't be found
		if type.name == baseName:
			return [type]
		for i in range(type.GetNumberOfDirectBaseClasses()):
			bt = type.GetDirectBaseClassAtIndex(i).GetType().GetCanonicalType()
			dp = self.getDerivationPath(bt, baseName)
			if dp:
				return dp + [type]
		if not includeVirt:
			return
		for i in range(type.GetNumberOfVirtualBaseClasses()):
			bt = type.GetVirtualBaseClassAtIndex(i).GetType().GetCanonicalType()
			if bt.name == baseName:
				return [bt, type]

	def getForkedDerivationPaths(self, type, baseName):
		if type.name == baseName:
			return [[type]]
		for i in range(type.GetNumberOfDirectBaseClasses()):
			bt = type.GetDirectBaseClassAtIndex(i).GetType().GetCanonicalType()
			p = self.getDerivationPath(bt, baseName, includeVirt=False)
			if p:
				yield p
				
	def printTypes(self, strings):
		if self.args.derived and len(strings) != 1:
			raise Exception("Only 1 class name supported for --derived")
		if self.args.md and len(strings) != 1:
			raise Exception("Only 1 class name supported for --md")
		printed = set()
		if not (self.args.containing or self.args.derived or self.args.md):
			for name in strings:
				for t in self.module.FindTypes(name):
					self.printOneType(t, printed, needFields=True)
			return
		for i in range(self.module.GetNumCompileUnits()):
			u = self.module.GetCompileUnitAtIndex(i)
			sys.stdout.write("\rCU %d/%d..." % (
				i, self.module.GetNumCompileUnits()))
			sys.stdout.flush()
			for t in u.GetTypes():
				if t.IsPointerType() or t.IsReferenceType() or t.size == 0:
					continue
				# Go from typedef name to real name
				t = t.GetCanonicalType()
				if self.args.derived:
					dp = self.getDerivationPath(t, strings[0])
					if dp:
						self.printOneType(t, printed, dp=dp[:-1])
					continue
				if self.args.md:
					dp = list(self.getForkedDerivationPaths(t, strings[0]))
					if len(dp) > 1:
						self.printOneType(t, printed, dps=dp)
					continue
				for st in strings:
					found = st in t.name
					if found:
						self.printOneType(t, printed, needFields=True)
						break

	def wasTypePrinted(self, t, printed):
		k = "%d:%s" % (t.size, t.name)
		if k in printed:
			return True
		printed.add(k)
		return False
	
	def printOneType(self, t, printed, dp=[], needFields=False, dps=[]):
		if self.wasTypePrinted(t, printed):
			return
		dpNames = "".join([(y.name + "/") for y in dp])
		print("\rsize=%4d %s%s" % (t.size, dpNames, t.name))
		for dp in dps:
			print("  " + "".join([(y.name + "/") for y in dp]))
		if needFields:
			self.printFields("+", [], 0, t)

	def descAddr(self, addr):
		return "%s:%016X" % (
				addr.GetSection().GetName(), addr.GetOffset())

	def dumpEntry(self, e, addr):
		sys.stderr.write(
			"Entry at %016X: %s-%016X (%d bytes) %s:%d\n" % (
			addr.GetOffset(), self.descAddr(e.GetStartAddress()),
			e.GetEndAddress().GetOffset(),
			e.GetEndAddress().GetOffset() - e.GetStartAddress().GetOffset(),
			e.GetFileSpec(), e.GetLine()))

	def getSymbols(self, context):
		for s in self.module.symbols:
			context.symbols.size += 1
			if s.GetStartAddress().IsValid():
				isFunc = int(s.GetStartAddress().GetSection().name == ".text")
				context.functions.size += isFunc
				if self.args.data:
					if not isFunc:
						context.processSymbol(s)
				elif self.args.all or isFunc:
					context.processSymbol(s)
			else:
				context.noAddress.size += 1

	def getInstructions(self, context):
		text = self.getCodeSection()
		addr = lldb.SBAddress(text, 0)
		while addr.GetOffset() < text.GetFileByteSize():
			size = 0
			code = self.target.ReadInstructions(addr, 100)
			for ins in code:
				context.processInstruction(ins, self)
				size += ins.GetByteSize()
			if size == 0:
				size = 1 # idk?
			addr.OffsetAddress(size);
			context.progress(size)

	def printContent(self, path, line):
		for i in range(self.module.GetNumCompileUnits()):
			cu = self.module.GetCompileUnitAtIndex(i)
			if not path:
				print(cu.GetFileSpec())
				continue
			# A CU has its path but it can contain line entries
			# from other paths
			# pp = str(cu.GetFileSpec()).split("/@/")[0]
			self.printCu(cu, path, line)

	def printCu(self, cu, path, line):
		cuDataPrinted = False
		if not line:
			print("CU %s %s line entries" % (
				cu.GetFileSpec(), cu.GetNumLineEntries()))
		blocks = {}
		for jj in range(cu.GetNumLineEntries()):
			ee = cu.GetLineEntryAtIndex(jj)
			if (str(ee.GetFileSpec()).endswith(path)) and\
			   (ee.GetLine() == line or line is None):
				start = ee.GetStartAddress()
				end = ee.GetEndAddress()
				if line and not cuDataPrinted:
					print("CU %s %s line entries" % (
						cu.GetFileSpec(), cu.GetNumLineEntries()))
					cuDataPrinted = True
				print("LE %s-%s at %s:%s" % (
					start.offset, end.offset,
					ee.GetFileSpec(), ee.GetLine()))
				bb = self.check(self.target.ReadMemory(
					start, end.offset - start.offset, self.error))
				ii = self.target.GetInstructions(start, bb)
				for inn in ii:
					print(inn)
				blocks[describeBlock(start.block)] = start.block
		for bl in blocks.values():
			self.printBlock(bl)

	def printBlock(self, bl):
		level = 0
		pb = bl.parent
		# pb = bl.GetContainingInlinedBlock()
		if pb.IsValid():
			level = self.printBlock(pb) + 1
		print("%sblock %s '%s'" % (
			" " * level, describeBlock(bl), bl.GetInlinedName()))
		return level
		

def describeBlock(bl):
	return " ".join("%s-%s" % (
		bl.GetRangeStartAddress(i).offset,
		bl.GetRangeEndAddress(i).offset) for
					i in range(bl.GetNumRanges()))

class FileSpecAndPrefixes:
	def __init__(self):
		self.spec = self.prefixes = None

class KeyFromSpec:
	def __init__(self, context, spec):
		self.context = context
		self.spec = spec

	def getPath(self):
		return "%s/%s" % (
			self.context.normalizePath(self.spec.GetDirectory()),
			self.spec.GetFilename())
		
class Context:
	__slots__ = (
		"args", "other", "unknown", "accounted", "allCode", "allFiles",
		"badSymbols", "processedBytes", "progressNext", "base",
		"noSymbols", "symbols", "entries", "inlineEntries",
		"prefixes", "index", "last", "output")
	
	def __init__(self, args):
		self.args = args
		self.other = Count("<other>")
		self.unknown = Count("<unknown>")
		self.accounted = Count("<accounted>")
		self.allCode = Count("<all code>")
		self.allFiles = Count("<all files>")
		self.badSymbols = Count("<bad symbols>")
		self.output = None
		self.processedBytes = 0
		self.progressNext = 0
		basePath = self.args.output and\
			os.path.dirname(self.args.output) or os.getcwd()
		self.base = basePath.split(os.sep)[-1]
		self.noSymbols = Count("<no symbols>")
		self.symbols = {}
		self.entries = Count("<entries>")
		self.inlineEntries = Count("<inline>")
		if self.args.verbose:
			print("LLDB version = '%s'" % lldb.SBDebugger.GetVersionString())

	def progress(self, size):
		self.processedBytes += size
		if self.processedBytes <= self.progressNext:
			return
		sys.stderr.write("	%16s / %16s (%3d%%)" % (
			nn(self.processedBytes), nn(self.allCode.size),
			self.processedBytes * 100 / self.allCode.size))
		if not self.args.calls:
			sys.stderr.write(" %s=%16s" % (
			self.args.unknown and "no symbols" or "other",
			self.args.unknown and nn(self.noSymbols.size) or\
			nn(self.other.size)))
		sys.stderr.write(" unknown=%16s\r" % nn(self.unknown.size))
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
		if self.last.spec and self.last.spec == e.file:
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
		if not self.args.types:
			self.reportCounts(self.prefixes + self.getCounts())

	def getCounts(self):
		counts = [
			self.unknown, self.other, self.accounted,
			self.allCode, self.allFiles, self.badSymbols]
		if not self.args.unknown:
			return counts
		return list(self.symbols.values()) + [self.noSymbols] + counts

	def reportCounts(self, counts):
		for count in counts:
			print(" %16s %s" % (nn(count.size), count.name))
			if self.output:
				self.output.write(" %16s %s\n" % (
					nn(count.size), count.name))

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

	def processUnknown2(self, addr, size):
		c = addr.GetSymbolContext(lldb.eSymbolContextSymbol)
		if c.symbol.IsValid():
			s = self.symbols.get(c.symbol.name, Count(c.symbol.name))
			s.size += size
			self.symbols[c.symbol.name] = s
		else:
			self.noSymbols.size += size

	def processUnknown(self, addr, size):
		return self.processUnknown2(addr, size)
		# eSymbolContextSymbol/c.symbol give us only exports which is no use
		c = addr.GetSymbolContext(lldb.eSymbolContextFunction)
		if c.function.IsValid():
			s = self.symbols.get(c.function.name, Count(c.function.name))
			s.size += size
			self.symbols[c.function.name] = s
		else:
			self.noSymbols.size += size

class InstructionSpan:
	def __init__(self, ilist, finished):
		self.ilist, self.finished = ilist, finished

	def print(self, output):
		for i in self.ilist:
			output.print("	%s: %s" % (i.addr.module.file.basename, i))
		if not self.finished:
			output.print("	%s: ..." % i.addr.module.file.basename)
		return self

class SourceLine:
	__slots__ = ("text", "number", "codeSize", "instructionSpans")
	
	def __init__(self, text, number):
		self.text = text
		self.number = number
		self.codeSize = 0
		self.instructionSpans = []

class SourceFile:
	__slots__ = (
		"path", "name", "args", "lines", "lastHash", "lastDirHash",
		"lastSpec", "gitId")
	
	def __init__(self, path, name, args):
		self.path = path
		self.name = name
		self.args = args
		self.gitId = None

	def load(self):
		# python2:
		# lines = open(self.path).read().decode("windows-1251").splitlines()
		if self.gitId:
			lines = subprocess.check_output(
				["git", "cat-file", "blob", self.gitId])
			if lines.decode:
				lines = lines.decode("utf-8")
			lines = lines.splitlines()
		else:
			lines = open(self.path, encoding="utf-8").read().splitlines()
		self.lines = [SourceLine(s, i) for i, s in enumerate(lines)]
		return self

	def printLines(self, output):
		output.print("%s:0: New file -----------------------------" % 
			self.name)
		for line in self.lines:
			m = "%03d %s" % (
				line.codeSize, line.text)
			if line.number != 0 and line.number % 10 == 0:
				m += " // at %s:%d" % (self.name, line.number)
			if sys.version_info < (3, 0):
				m = m.encode("utf-8")
			output.print(m)
			if self.args.instructions:
				for s in line.instructionSpans:
					s.print(output)

class Lines(Context):
	__slots__ = ("files", "lastFile", "nameMap", "lookups")
	
	def prepare(self, inputs):
		self.files = {}
		self.lastFile = None
		self.nameMap = {}
		output = self.args.output or self.args.git and\
			"%s-du.txt" % self.args.git[:8]
		if output:
			self.output = open(output, "wt")
			self.output.write(" -*- mode: compilation -*-\n")
			self.output.write(" (highlight-regexp \"000\" 'hi-green)\n")
		else:
			raise Exception("Must have output file")
		if self.args.git:
			lines = subprocess.check_output([
				"git", "ls-tree", "-r", self.args.git]).splitlines();
			for line in lines:
				if not line:
					break
				if line.decode:
					line = line.decode("utf-8")
				params, path = line.split("\t", 2)
				_, _, id = params.split(" ")
				if re.match(r".+[.](c|cc|cpp|h|H|C|qx)$", path):
					self.addPath(path, gitId=id)
					if self.args.verbose:
						sys.stderr.write("Added '%s'\n" % path)
		for path in self.args.PREFIX:
			self.addPath(path)
		if len(self.files) == 0:
			raise Exception("No source files")
		self.lookups = [0, 0, 0]

	def addPath(self, path, gitId=None):
		np = self.normalizePath(path)
		self.files[np] = SourceFile(path, np, self.args)
		self.files[np].gitId = gitId
		self.files[np].load()

	def report(self):
		for file in set(self.files.values()):
			if file:
				file.printLines(self)
		self.reportCounts(self.getCounts() + [
			self.entries, self.inlineEntries])
		sys.stderr.write("lookups=%s " % " ".join(
			[nn(x) for x in self.lookups]))

	def print(self, s):
		self.output.write(s + "\n")

	def processEntry(self, e, size, input, addr):
		# Optimization
		cache = self
		f = cache.lastFile
		h = hash(e.file.GetFilename())
		d = hash(e.file.GetDirectory())
		if f:
			if f.lastHash != h or\
			   f.lastSpec.basename != e.file.basename or\
			   f.lastSpec.dirname != e.file.dirname:
				f = None
		if not f:
			self.lookups[1] += 1
			f = cache.nameMap.get(e.file.GetFilename())
			if not f or f.lastDirHash != d or\
			   f.lastSpec.GetDirectory() != e.file.GetDirectory():
				self.lookups[2] += 1
				f = self.files.get(self.normalizePath(e.file.fullpath))
				if not f:
					self.other.size += size
					return
				cache.nameMap[e.file.GetFilename()] = f
		f.lastHash = h
		f.lastDirHash = d
		f.lastSpec = e.file
		cache.lastFile = f
		# End of optimization
		self.accounted.size += size
		try:
			try:
				f.lines[e.line - 1].codeSize += size
			except IndexError:
				self.badSymbols.size += size
				return
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

class SymbolStat:
	tpl1 = re.compile(r"<(\w+)>")
	def __init__(self, symbol, args):
		self.name = symbol.name
		if 1:
			id = "A"
			map = {}
			for m in self.tpl1.finditer(self.name):
				arg = m.group(1)
				if not arg in map:
					map[arg] = id
			for arg in map.keys():
				self.name = self.name.replace(arg, map[arg])
		self.size = Calls.getSize(None, symbol)
		self.count = 0

	def getCumulativeSize(self):
		return self.count * self.size

	def getCount(self):
		return self.count

class Calls(Context):
	def prepare(self, inputs):
		self.targets = []
		if self.args.PREFIX:
			for px in self.args.PREFIX:
				self.targets.append(Count(px))
		self.callTargetMaxSize = 0
		if self.args.ctms:
			self.callTargetMaxSize = int(self.args.ctms)
		self.symbolInfo = {}
		self.unknown = self.unknownSrc = Count("<unknown source>")
		self.unknownTgt = Count("<unknown target>")
		self.calls = Count("<call instructions>")
		self.instructions = Count("<total instructions>")
		self.noName = Count("<no name>")
		self.symbols = Count("<symbols>")
		self.noAddress = Count("<no address>")
		self.functions = Count("<functions>")
		self.endbr = Count("<endbr>")
		self.sfp = Count("<stack frame used>")
		for input in inputs:
			if self.args.functions or self.args.all or\
				 self.args.ds or self.args.sfp or self.args.data:
				input.run = input.getSymbols
			else:
				input.run = input.getInstructions
				sec = input.getCodeSection()
				input.target.SetSectionLoadAddress(sec, sec.GetFileAddress())

	def dumpSymbol(self, s):
		addr = s.GetStartAddress()
		print("%6d %s+%s %2d %s%s loc='%s'" % (
			self.getSize(s),
			addr.section.name, xx(addr.GetOffset()),
			s.GetType(), s.name, s.IsSynthetic() and " synthetic" or "",
			self.getLocation(addr, "%s:%d")))

	def processSymbol(self, s):
		if not s.name:
			self.noName.size += 1
			return
		if self.args.ds:
			self.dumpSymbol(s)
			return
		if self.args.PREFIX:
			found = None
			for str in self.args.PREFIX:
				if str in s.name:
					found = str
					break
			if not found:
				return
		ss = SymbolStat(s, self.args)
		key = "%d %s" % (self.getSize(s), ss.name)
		t = self.symbolInfo.get(key)
		if not t:
			self.symbolInfo[key] = t = ss
		t.count += 1
		# Look for endbr and stack frame prologue
		addr = s.GetStartAddress()
		if addr.section.name != ".text":
			return
		err = lldb.SBError()
		bytes = addr.section.GetSectionData().ReadRawData(
			err, addr.offset, 8)
		if err.fail:
			self.unreadable.size += 1
			return
		if bytes[0:4] == b"\xF3\x0F\x1E\xFA":
			self.endbr.size += 1
			bytes = bytes[4:]
		if bytes == b"\x55\x48\x89\xE5":
			if self.args.sfp:
				self.dumpSymbol(s)
			self.sfp.size += 1

	def printCall(self, src, ins, arg):
		target = self.getLocation(arg, " at %s:%d")
		if not target:
			target = ""
		print("%s %s -> %s%s" % (
			src, ins.addr.symbol.name, arg.symbol.name, target))
		sys.stdout.flush()

	def processInstruction(self, ins, input):
		self.instructions.size += 1
		command = ins.GetMnemonic(input.target)
		if command != "callq":
			return
		right = ins.GetOperands(input.target)
		if "%" in right:
			return
		self.calls.size += 1
		v = int(right, 16)
		arg = lldb.SBAddress(v, input.target)
		src = self.getLocation(ins.addr, "%s:%d:")
		if not src:
			self.unknownSrc.size += 1
			src = ins.addr.symbol.name or "<unknown>"
		if not arg.symbol.name:
			self.unknownTgt.size += 1
		if not self.targets and not self.callTargetMaxSize:
			self.printCall(src, ins, arg)
			return
		if arg.symbol.name:
			if self.callTargetMaxSize:
				if self.getSize(arg.symbol) <= self.callTargetMaxSize:
					found = False
					for count in self.targets:
						if count.name in arg.symbol.name:
							found = True
							break
					if not found:
						self.targets.append(Count(arg.symbol.name))
			for count in self.targets:
				if count.name in arg.symbol.name:
					self.printCall(src, ins, arg)
					count.size += 1
					break

	def getLocation(self, addr, fmt):
		le = addr.line_entry
		if not le.IsValid():
			return None
		return fmt % (
			KeyFromSpec(self, le.GetFileSpec()).getPath(), le.GetLine())
		
	def report(self):
		if not (
				self.args.functions or self.args.all or
				self.args.sfp or self.args.data):
			self.reportCounts([
				self.unknownSrc, self.unknownTgt, self.calls,
				self.instructions] + self.targets)
			return
		functions = self.symbolInfo.values()
		if not self.args.sfp:
			sys.stdout.write("Sorting %d functions...\n" % len(functions))
			for s in sorted(functions, key=SymbolStat.getCumulativeSize):
				print("%10s %s" % (
					"%d*%d" % (s.size, s.count), s.name))
		self.reportCounts([
			self.symbols, self.functions, self.noAddress, self.noName,
			self.endbr, self.sfp])

	def getSize(self, s):
		return s.GetEndAddress().GetOffset() -\
			s.GetStartAddress().GetOffset()

		
class Maps(Context):
	secPattern = r"([.][^\s]+) +0x([0-9a-f]{8,16}) +0x([0-9a-f]+)"
		 
	class Section:
		def __init__(self):
			pass
		
	class ParseState:
		def __init__(self):
			self.destName = None
			self.srcName = None
			
	def __init__(self, args):
		self.output = None
		self.args = args
		self.sources = {}
		self.accounted = Count("<accounted>")
		

	def run(self):
		if self.args.input:
			raise Exception(
				"Can't have binary input together with link maps")
		if self.args.PREFIX:
			raise Exception(
				"Map parse doesn't take PREFIX arguments")
		for path in self.args.map:
			self.processMap(path)
		self.report()

	def processMap(self, path):
		state = self.ParseState()
		dest = None
		startedMemoryMap = False
		for line in open(path, "r"):
			line = line.rstrip()
			if not startedMemoryMap:
				if line == "Linker script and memory map":
					startedMemoryMap = True
				continue
			m = re.match(self.secPattern, line)
			if m:
				dest = self.Section()
				dest.name, dest.start, dest.size = m.group(1, 2, 3)
				if self.args.idebug or not dest.name.startswith(".debug"):
					c = Count(dest.name)
					c.size = int(dest.size, 16)
					# self.sources[dest.name] = c
				continue
			if dest and dest.name.startswith(".debug") and not self.args.idebug:
				continue
			m = re.match(r" ([.][^\s]+)$", line)
			if m:
				state.srcName = m.group(1)
				continue
			m = re.match(" " + self.secPattern + " (.+)", line)
			m2 = m or re.match(
				r" {16}0x([0-9a-f]{8,16}) +0x([0-9a-f]+) (.+)", line)
			if m2:
				if not dest:
					sys.stderr.write(
						"Warning: memory outside section '%s'\n" % line)
					continue
				if m:
					fullSource = m.group(4)
					size = int(m.group(3), 16)
				else: # m2 != None
					if not state.srcName:
						sys.stderr.write(
							"Warning: memory without source section '%s'\n" % line)
						# Still usable
					fullSource = m2.group(3)
					size = int(m2.group(2), 16)
				self.accounted.size += size
				source = None
				if self.args.expand:
					for x in self.args.expand:
						if x in fullSource:
							source = fullSource
							break
				if not source:
					p = fullSource.split("(")
					if len(p) == 1:
						source = "<other>"
					else:
						source = p[0]
				if self.args.bydest:
					source += " -> %s" % dest.name
				count = self.sources.get(source, Count(source))
				count.size += size
				self.sources[source] = count

	def report(self):
		self.reportCounts(
			list(sorted(self.sources.values())) + [
				self.accounted])

class CallGraph:
	def __init__(self, args):
		self.args = args
		self.path = None

	def run(self):
		import pydot
		targets = []
		for arg in self.args.PREFIX:
			if arg.endswith(".dot") or arg.endswith(".gv"):
				if self.path:
					raise Exception("Only 1 graph path allowed")
				self.path = arg
				continue
			targets.append(arg)
		cg = pydot.graph_from_dot_file(self.path)

class Show:
	def __init__(self, args):
		self.args = args

	def run(self):
		self.inputs = [Input(p, self.args) for p in self.args.input or []]
		target = self.args.PREFIX.pop()
		for path in self.args.PREFIX:
			self.inputs.append(Input(path, args))
		line = None
		pp = target.split(":")
		path = pp[0]
		if len(pp) > 1:
			line = int(pp[1])
		for input in self.inputs:
			input.printContent(path, line)

class Info:
	def __init__(self, args):
		self.args = args

	def run(self):
		match = self.args.match and \
			lldb.SBModuleSpecList.GetModuleSpecifications(self.args.match)
		for path in self.args.PREFIX:
			specs = lldb.SBModuleSpecList.GetModuleSpecifications(path)
			print(specs)
			if match:
				matched = specs.FindMatchingSpecs(match.GetSpecAtIndex(0))
				if matched.GetSize():
					print("Matched = %s" % matched)

class Diff(Calls):
	def run(self):
		if len(self.args.PREFIX) != 2:
			raise Exception("Must have 2 arguments")
		self.i1, self.i2 = inputs =\
			[Input(x, self.args) for x in self.args.PREFIX]
		self.prepare([])
		self.i1.compareSections(self.i2)
		fileSizes = [i.getFileSize() for i in inputs]
		printComparison(fileSizes[0], fileSizes[1], "File size")
		print("---------")
		self.map1 = self.map = {}
		self.i1.allMap = self.allMap = {}
		self.i1.getSymbols(self)
		self.map2 = self.map = {}
		self.i2.allMap = self.allMap = {}
		self.i2.getSymbols(self)
		self.report()

	def report(self):
		for name, l2 in self.map2.items():
			if l1 := self.map1.get(name, 0):
				del self.map1[name]
			if l1 == l2:
				continue
			printComparison(l1, l2, name)
			self.printInstructionsIfNeeded(name)
		for name, l1 in self.map1.items():
			printComparison(l1, 0, name)
			self.printInstructionsIfNeeded(name)

	def printInstructionsIfNeeded(self, name):
		if not self.args.instructions:
			return
		for inp in [self.i1, self.i2]:
			ss = inp.allMap[name]
			for sym in ss:
				ii = sym.GetInstructions(inp.target)
				print("%d instructions for %s" % (ii.GetSize(), sym))
				print(ii)

	def processSymbol(self, s):
		self.map[s.name] = self.map.get(s.name, 0) + self.getSize(s)
		ss = self.allMap.get(s.name)
		if not ss:
			ss = self.allMap[s.name] = []
		ss.append(s)

if sum(int(not not x) for x in (
		args.target, args.show, args.diff, args.file, args.calls, args.map)) > 1:
	print("Can have only 1 of --target --show --diff --file --calls --map")
	sys.exit(1)
if args.git:
	args.file = True
if args.diff:
	Diff(args).run()
elif args.target:
	r = CallGraph(args).run()
elif args.show:
	r = Show(args).run()
elif args.info:
	r = Info(args).run()
else:	
	((args.all or args.calls or args.functions or args.ds or
		args.sfp or args.data) and Calls or\
	 args.map and Maps or args.file and Lines or Context)(args).run() 
sys.stderr.write("%s done in %s\n" % (
	__file__, datetime.datetime.now() - take_off))
