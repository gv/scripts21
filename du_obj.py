#!/usr/bin/env python3
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
	"--git", help="Get file list + contents form REVISION (-f)")
parser.add_argument(
	"--calls", action="store_true", help="Get function calls (non virtual)")
parser.add_argument(
	"--symbols", action="store_true", help="Get symbol sizes and repeat counts")
parser.add_argument(
	"--all", action="store_true", help="Print symbol data")
parser.add_argument(
	"--types", action="store_true", help="List types & exit")
parser.add_argument(
	"--containing", "-I", action="store_true",
	help="List all types whose names contain PREFIX")
parser.add_argument(
	"--recurse", "-r", action="store_true", help="List fields in pointer types")
parser.add_argument(
	"PREFIX", nargs="*",
	help="Dir or file paths to count the code size for each")
args = parser.parse_args()

# print("pid %d" % os.getpid())
# sys.stdin.read(1)

def nn(n):
	return ",".join(re.findall(r"\d{1,3}", str(n)[::-1]))[::-1]

class Count:
	__slots__ = ("name", "size")
	
	def __init__(self, value):
		self.name = value
		self.size = 0

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

	def getAllSections(self):
		def getSubSections(sec):
			yield sec
			if sec.GetNumSubSections() == 0:
				return
			for i in range(sec.GetNumSubSections()):
				for t in getSubSections(sec.GetSubSectionAtIndex(i)):
					yield t
		# "for sec in self.module.section" yields None sometimes
		for i in range(self.module.GetNumSections()):
			for u in getSubSections(self.module.GetSectionAtIndex(i)):
				yield u

	def dumpSections(self):
		if self.sectionsDumped:
			return
		for sec in self.getAllSections():
			self.printSec(sec)
		self.sectionsDumped = True

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

	def printFields(self, prefix, type, printed):
		printed.add(type.name)
		allFields = [
			type.GetDirectBaseClassAtIndex(i)
			for i in range(type.num_bases)] + [
			type.GetFieldAtIndex(i)
			for i in range(type.num_fields)]
		for fl in allFields:
			name = fl.name
			ft = fl.GetType().GetCanonicalType()
			if ft.name and name and name != ft.name:
				name += " " + ft.name
			print("%s%s %s" % (
				prefix, "%d-%d" % (
					fl.GetOffsetInBytes(),
					fl.GetOffsetInBytes() + ft.size), name))
			self.printFields(prefix + " ", ft, printed)
			if self.args.recurse and ft.IsPointerType():
				if ft.GetPointeeType().name in printed:
					continue
				self.printFields(prefix + " ", ft.GetPointeeType(), printed)
				

	def printTypes(self, strings):
		printed = set()
		if not self.args.containing:
			for name in strings:
				for t in self.module.FindTypes(name):
					self.printOneType(t)
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
				found = False
				for st in strings:
					found = st in t.name
					if found:
						break
				if not found:
					continue
				k = "%d:%s" % (t.size, t.name)
				if k in printed:
					continue
				printed.add(k)
				self.printOneType(t)

	def printOneType(self, t):
		print("\rsize=%d name=%s" % (t.size, t.name))
		self.printFields(" ", t, set())

	def descAddr(self, addr):
		return "%s:%016X" % (addr.GetSection().GetName(), addr.GetOffset())

	def dumpEntry(self, e, addr):
		sys.stderr.write(
			"Entry at %016X: %s-%016X (%d bytes) %s:%d\n" % (
			addr.GetOffset(), self.descAddr(e.GetStartAddress()),
			e.GetEndAddress().GetOffset(),
			e.GetEndAddress().GetOffset() - e.GetStartAddress().GetOffset(),
			e.GetFileSpec(), e.GetLine()))

	def getFunctions(self, context):
		for s in self.module.symbols:
			if s.GetStartAddress().IsValid():
				if self.args.all or\
				   s.GetStartAddress().GetSection().name == ".text":
					context.processSymbol(s)

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

	def getTotalSize(self):
		return self.count * self.size

	def getCount(self):
		return self.count

class Calls(Context):
	def prepare(self, inputs):
		self.symbolInfo = {}
		self.unknown = self.unknownSrc = Count("<unknown source>")
		self.unknownTgt = Count("<unknown target>")
		self.calls = Count("<call instructions>")
		self.instructions = Count("<total instructions>")
		for input in inputs:
			if self.args.symbols or self.args.all:
				input.run = input.getFunctions
			else:
				input.run = input.getInstructions
				sec = input.getCodeSection()
				input.target.SetSectionLoadAddress(sec, sec.GetFileAddress())

	def processSymbol(self, s):
		if self.args.PREFIX:
			if not s.name:
				return
			found = None
			for str in self.args.PREFIX:
				if str in s.name:
					found = str
					break
			if not found:
				return
		if self.args.all:
			if not s.name:
				return
			print("%016X %6d %2d %s%s loc='%s'" % (
				s.GetStartAddress().GetOffset(), self.getSize(s),
				s.GetType(), s.name, s.IsSynthetic() and " synthetic" or "",
				self.getLocation(s.GetStartAddress(), "%s:%d")))
			return
		if not s.name:
			return
		ss = SymbolStat(s, self.args)
		key = "%d %s" % (self.getSize(s), ss.name)
		t = self.symbolInfo.get(key)
		if not t:
			self.symbolInfo[key] = t = ss
		t.count += 1

	def processInstruction(self, ins, input):
		self.instructions.size += 1
		command = ins.GetMnemonic(input.target)
		if command != "callq":
			return
		right = ins.GetOperands(input.target)
		if "%" in right:
			return
		v = int(right, 16)
		arg = lldb.SBAddress(v, input.target)
		src = self.getLocation(ins.addr, "%s:%d:")
		target = self.getLocation(arg, " at %s:%d")
		if not target:
			self.unknownTgt.size += 1
			target = ""
		if src:
			print("%s %s -> %s%s" % (
				src, ins.addr.symbol.name, arg.symbol.name, target))
		else:
			self.unknownSrc.size += 1

	def getLocation(self, addr, fmt):
		le = addr.line_entry
		if not le.IsValid():
			return None
		return fmt % (
			KeyFromSpec(self, le.GetFileSpec()).getPath(), le.GetLine())
		
	def report(self):
		if not self.args.symbols:
			self.reportCounts([
				self.unknownSrc, self.unknownTgt, self.calls,
				self.instructions])
			return
		functions = self.symbolInfo.values()
		if self.args.verbose:
			sys.stderr.write("Sorting %d functions...\n" % len(functions))
		for s in sorted(functions, key=SymbolStat.getCount):
			print("%10s %s" % (
				"%d*%d" % (s.size, s.count), s.name))

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
					
if args.instructions or args.git:
	args.file = True
((args.all or args.calls) and Calls or\
 args.map and Maps or args.file and Lines or Context)(args).run() 
sys.stderr.write("%s done in %s\n" % (
	__file__, datetime.datetime.now() - take_off))
