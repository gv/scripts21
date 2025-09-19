#!/usr/bin/env python3
from __future__ import print_function
"LLDB commands to get stuff from crash dumps"
import argparse, re, os, sys, time, subprocess, struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("DMPFILE", help="Path to core file", nargs="*")
parser.add_argument(
	"-b", "--base", help="Prefix to strip from paths")
parser.add_argument(
	"-r", "--storage", help="Path to binary archive")
parser.add_argument(
	"-m", "--modules", action="store_true", help="List binaries")
parser.add_argument(
	"-a", "--absent", action="store_true",
	help="List binaries not in storage")
parser.add_argument(
	"-s", "--stat", action="store_true",
	help="Print a line of numbers for every file")
parser.add_argument(
	"-d", "--download",
	help="Symbol server URL to download symbols from")
parser.add_argument(
	"-u", "--unchecked", action="store_true",
	help="Allow binaries not in archive")
parser.add_argument(
	"-n", "--attachname", help="Attach to a live process by name")
parser.add_argument(
	"-t", "--threadf", action="store_true",
	help="Print frames decoded by lldb (crashed thread)")
parser.add_argument(
		"--threads", action="store_true",
		help="Print frames decoded by lldb (each thread)")
parser.add_argument(
	"-T", "--telescope", action="store_true",
	help="Recursively resolve words from stack (crashed)")
parser.add_argument(
	"-B", "--bt", action="store_true",
	help="Print stack of crashed thread")
parser.add_argument(
	"-x", "--thread", action="store_true", 
	help="Unwind stack by counting PUSH/SUB *,SP instructions in code")
parser.add_argument(
	"-z", "--callsites", action="store_true", 
	help="""
Print all stack words from crashed thread pointing to code after
call instructions
""")
parser.add_argument(
	"-y", "--threadn", help="Print all words from stack N")
parser.add_argument(
	"-X", "--fa", action="store_true", 
	help=""""
Print all words from crashed thread using `memory read -fA` (aka x/a)
""")
parser.add_argument(
	"-H", "--hex", action="store_true", help="Hex dump stack of crashed thread")
parser.add_argument(
	"-Y", "--threadm",
	help="Print all words from stack N using `memory read -fA`")
parser.add_argument(
	"-D", "--disassembly", action="store_true",
	help="Show disassembly of functions in the stack")
parser.add_argument(
	"-S", "--scan", help="Search memory for the contents of file")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument(
	"-w", "--dverbose", action="store_true",
	help="LLDB verbose output")
parser.add_argument(
	"-l", "--long", action="store_true", help="Not abbrev build ids")

try:
	import lldb
except ImportError:
	if sys.platform.startswith("linux"):
		sys.path.append(
			"/usr/lib64/python3.6/site-packages")
#			"/usr/lib/python2.7/dist-packages/lldb-3.8")
	else:
		sys.path.append("\
/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/\
Resources/Python")
import lldb

def check(error):
	if error.fail:
		raise Exception(str(error))

def cut(s, limit):
	return len(s) > (limit+3) and "%s..." % s[:limit] or s

def getId(m, long=False):
	s = m.GetUUIDString()
	if not s:
		return s
	s = "".join(s.split("-")).upper() # + "0"
	if long:
		return s
	return s[0:8]

def justifyId(m, long=False):
	return (long and "%40s" or "%8s") % getId(m, long)

def nn(n):
	n = str(int(n))
	return ",".join(re.findall(r"\d{1,3}", n[::-1]))[::-1]

def xx(n):
	n = "%X" % n
	return ",".join(re.findall(r"[0-9a-fA-F]{1,4}", n[::-1]))[::-1]

def xr(start, end):
	sx = xx(start)
	ex = xx(end)
	prefix = ""
	if len(sx) == len(ex):
		for p in range(len(ex)):
			if sx[p] != ex[p]:
				break
			prefix += sx[p]
	return "%s[%s-%s]" % (prefix, sx[len(prefix):], ex[len(prefix):])

def hexDumpMem(process, start, end, error):
	lsize = 16
	while start < end:
		if lsize > end - start:
			lsize = end - start
		st = process.ReadMemory(start, lsize, error)
		if error.fail:
			raise Exception(str(error))
		sys.stdout.write(" %X " % start)
		sys.stdout.write(
			("%02X " * lsize) % tuple(bytearray(st)))
		for c in st:
			if type(c) == int:
				sys.stdout.write(c < 32 and "." or chr(c))
				continue
			sys.stdout.write(ord(c) < 32 and "." or c)
		sys.stdout.write("\n")
		start += lsize

def printSize(count, name):
	print("%20s %s" % (nn(getattr(count, name.lower())), name))

def abbreviate_identifiers(code: str) -> str:
	"""
	Replaces repeated identifiers in a string with abbreviations.
	First occurrence stays intact, subsequent ones get replaced.
	Abbreviations are first letter + '.' (e.g., 'count' -> 'c.')
	"""
	identifier_pattern = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
		
	seen = {}

	def replacer(match):
		identifier = match.group(0)
		if identifier not in seen:
			seen[identifier] = identifier[0] + "."
			return identifier	 # keep the first occurrence
		else:
			return seen[identifier]

	return identifier_pattern.sub(replacer, code)

ptrSize = 8

class Count:
	def __init__(self):
		self.absent = 0
		self.modules = 0
		self.other = 0
		self.system = 0
		self.store = 0

class WorkCount:
	def __init__(self, todo=0):
		self.done = 0
		self.total = todo

class DebuggerError(Exception):
	pass

class Util:
	def verb(self, message):
		if not self.args.verbose:
			return
		self.print(message)

	def print(self, message, count=None):
		count = count or hasattr(self, "count") and self.count
		if count:
			sys.stderr.write("\r[%s / %s] " % (
				nn(count.done), nn(count.total)))
		sys.stderr.write(message)
		sys.stderr.flush()

	def setVar(self, name, value):
		old = lldb.SBDebugger.GetInternalVariableValue(
			name, self.debugger.GetInstanceName())
		check(lldb.SBDebugger.SetInternalVariable(
			name, value, self.debugger.GetInstanceName()))
		self.verb("Variable '%s' was set to '%s' (was '%s')\n" % (
			name, value, " ".join(old)))

	def check(self, result):
		if self.error.fail:
			raise DebuggerError(str(self.error))
		return result

	def describeAddr(self, addr):
		ptr = addr.GetLoadAddress(self.sbt)
		return CallSite(self).describePointer(ptr, addr)
	
	def getRegion(self, ptr):
		reg = lldb.SBMemoryRegionInfo()
		check(self.process.GetMemoryRegionInfo(ptr, reg))
		return reg.IsMapped() and reg or None

	def readPtr(self, ptr):
		return self.check(
			self.sbt.process.ReadPointerFromMemory(ptr, self.error))
		
class SymbolNotOnServer(Exception):
	pass

class CallSite(Util):
	"""
	An object tracking a saved caller PC on stack. 
	TODO: Transform this class into more general pointer classifier
	"""
	def __init__(self, target):
		self.error = target.error
		self.sbt = target.sbt
		self.sbp = target.process
		self.args = target.args
		self.target = target
		self.reg = None
		class Count:
			def __init__(self):
				self.words = self.calls = self.destinations = 0
				self.pointers = self.readable = 0
		self.count = Count()
		self.stack = self.sp = self.pos = None

	def describePointer(self, ptr, addr=None):
		self.callerInstrs = []
		self.ra0 = ptr
		# TODO:
		# Move describeAddr here
		# Detect pointers to another threads stack bc it's probably
		# some kind of anomaly
		# Also, detect pointers that point down the stack - can't be
		# good too
		if not self.stack is None: 
			if ptr >= self.sp and ptr <= self.stack.GetRegionEnd():
				return "Same stack +%s" % (nn(ptr-self.pos))
		self.reg = self.target.getRegion(ptr)
		if not self.reg:
			return "Unmapped"
		if self.target.getThreadWithStackInRegion(self.reg):
			return "Other stack" if self.stack else "Stack"
		self.pa = addr or lldb.SBAddress(ptr, self.sbt)
		if not self.pa.section.IsValid():
			return "Heap or mmap"
		desc = "Indescribable"
		if self.pa.function.IsValid():
			off = self.pa.offset - self.pa.function.addr.offset
			desc = "%s+%d" % ( self.pa.function.name, off)
		elif self.pa.symbol.IsValid():
			off = self.pa.offset - self.pa.symbol.addr.offset
			desc = "%s+%d" % ( self.pa.symbol.name, off)
		elif self.pa.section.IsValid():
			desc = "%s%s+%s" % (
				self.pa.module.GetFileSpec().basename, self.pa.section.name,
				xx(self.pa.offset))
			if ".module_image" == self.pa.section.name:
				desc += " (buildId=%s)" % getId(self.pa.module, self.args.long)
		elif self.pa.module.IsValid():
			desc = self.pa.module.name
		# Try to load caller instructions regardles if it is code
		# section or not
		self.loadCallInstrFromAddress(ptr, self.pa)
		return desc

	def loadCallInstr(self, pretaddrl):
		ra0 = self.target.check(self.sbp.ReadPointerFromMemory(
			pretaddrl, self.sbt.error))
		msg = self.loadCallInstrGetMessage(ra0)
		if msg:
			print("%s: %s %s" % (xx(pretaddrl), xx(self.ra0), msg))
		else:
			return self.call

	def loadCallInstrGetMessage(self, ra0):
		self.ra0 = ra0
		self.ra = ra = lldb.SBAddress(ra0, self.sbt)
		if not ra.section.IsValid():
			return "no sec"
		self.count.pointers += 1
		return self.loadCallInstrFromAddress(ra0, ra)

	def loadCallInstrFromAddress(self, ra0, ra):
		self.callerInstrs = []
		if ra.section.file_size == 0:
			return "no image"
		self.count.readable += 1
		if ra.offset == 0:
			return
		ibufoff = max(ra.offset - 100, 0)
		# If that's a real return address, there must be call
		# instruction before that. It can be 5, 3 or 2 bytes.
		bytes = ra.section.GetSectionData().ReadRawData(
			self.error, ibufoff, ra.offset - ibufoff)
		ibuf = lldb.SBAddress(ra.section, ibufoff)
		if self.error.fail:
			raise Exception("%s @ %s %s %s section size = %s" % (
				self.error, self.target.getName(ra.module),
				xx(self.sbt.GetLoadAddress(ibuf)),
				self.describeAddr(ibuf), ra.section.file_size))
		self.call = call = self.getCall(bytes, ra0)
		if call:
			cia = lldb.SBAddress(ra0 - len(call.ibs), self.sbt)
			self.callerInstrs = self.sbt.GetInstructions(cia, call.ibs)
		
	def getCall(self, bytes, end, verbose=False):
		class Call:
			def __init__(self, ibs):
				self.ibs = ibs
		if len(bytes) >= 5 and bytes[-5] == 0xe8:
			call = Call(bytes[-5:])
			call.destination = struct.unpack("i", bytes[-4:])[0] + end
			return call
		if len(bytes) >= 3	and bytes[-3] == 0xff:
			call = Call(bytes[-3:])
			call.destination = None
			return call
		if verbose:
			print("	 Unknown instr %x %x %x %x %x" % bytes[-5:-1])
		return False


class UnwindFrame(CallSite):
	def loadTopOfStack(self, thread, stack):
		self.stack = stack
		self.pc = thread.frames[0].pc
		self.sp = thread.frames[0].sp
		self.source = "PC"
		return self
	
	def loadReturnAddress(self, loc, stack):
		# After call SP points at return address
		# We need SP before call
		self.stack = stack
		self.source = self.descStackPtr(loc)
		self.pc = self.target.check(
			self.sbp.ReadPointerFromMemory(loc, self.error))
		self.sp = loc + ptrSize
		return self

	def descStackPtr(self, ptr):
		return "S-%x" % (self.stack.GetRegionEnd() - ptr)

	def calculateFrameSize(self):
		self.pushCount = self.popCount = self.spDecrement = 0
		for ii in self.insns:
			mn = ii.GetMnemonic(self.sbt)
			if "pushq" == mn:
				self.pushCount += 1
			elif "popq" == mn:
				self.popCount += 1
			elif "subq" == mn:
				ops = ii.GetOperands(self.sbt).split(", %rsp")
				if len(ops) == 2:
					if self.spDecrement:
						sys.stdout.write(
							"Extra sub SP instruction (1st sub=%X): " % self.spDecrement)
						self.target.printInstruction(ii)
					elif not ops[0].startswith("$"):
						sys.stdout.write("Non-constant sub SP: ")
						self.target.printInstruction(ii)
						continue
					self.spDecrement += int(ops[0][1:], base=0)

	def findCaller(self):
		pc = lldb.SBAddress(self.pc, self.sbt)
		self.insns = pc.symbol.IsValid() and\
			self.target.getFuncInstructions(pc, self.pc)
		if self.insns:
			self.calculateFrameSize()
			self.returnAddrLocation = self.sp +\
				(ptrSize*(self.pushCount - self.popCount)) + self.spDecrement
			if self.returnAddrLocation >= self.sp:
				self.loadCallInstr(self.returnAddrLocation)
				return self
			else:
				print("	 popCount=%d pushCount=%d spDecrement=%d, start searching..." % (
					self.popCount, self.pushCount, self.spDecrement))
		else:
			print(
				"	 Instructions unreadable @ %s." % (self.describeAddr(pc))) 
			print(" Starting search for return address...")
		reg = self.target.getRegion(self.sp)
		# If nothing pushed, return address can be located @ sp
		for pretaddrl in range(self.sp, reg.GetRegionEnd(), ptrSize):
			self.count.words += 1
			call = self.loadCallInstr(pretaddrl)
			if not call:
				continue
			self.count.calls += 1
			if not call.destination:
				continue
			self.count.destinations += 1
			# We're looking for the call to an unloaded module
			# Therefore it must be call to .plt
			if call.destination:
				da = self.sbt.ResolveLoadAddress(call.destination)
				if da.section.name == ".text":
					if 0:
						print("Skip:")
						for inn in self.callerInstrs:
							self.target.printInstruction(inn, True)
					self.callerInstrs = None
					continue
			self.returnAddrLocation = pretaddrl
			break
		return self

	def getReturnAddrLoc(self):
		self.findCaller()
		if self.insns:
			if self.args.disassembly:
				for inn in self.insns:
					self.target.printInstruction(inn)
				print(" ==== end of disassembly")
			sys.stdout.write("	%d push, %d pop, %d sub, prev pc @ %s\n" % (
				self.pushCount, self.popCount, self.spDecrement,
				xx(self.returnAddrLocation)))
		else:
			sys.stdout.write(
				"	 Tried %d words, %d -> a section, %d readable, %d calls, %d destinations\n" % (
					self.count.words, self.count.pointers,
					self.count.readable, self.count.calls,
					self.count.destinations))
		for inn in self.callerInstrs:
			self.target.printInstruction(inn, True)
		return self.returnAddrLocation

	def print(self):
		pc = lldb.SBAddress(self.pc, self.sbt)
		# sys.stdout.write("\u2666 %s: %s %s %s\n" % (
		sys.stdout.write("%s: %s %s %s\n" % (
			self.source, xx(self.pc), self.target.getName(pc.module),
			self.target.describeAddr(pc)))
		sys.stdout.flush()

class MemTypeCount:
	def __init__(self):
		self.heap = self.stack = 0

class Target(Util):
	def __init__(self, args, debugger, sbt=None):
		self.args, self.debugger = args, debugger
		self.error = lldb.SBError()
		self.sbt = sbt or self.check(self.debugger.CreateTarget(
			"", "", "", True, self.error))
		# Hack: add mapping to nonexistent files so
		# ModuleList::GetSharedModule gets called first without a real
		# path and finds storage files in target.exec-search-paths
		if self.args.storage\
			and hasattr(self.sbt, "AppendImageSearchPath"):
			self.check(self.sbt.AppendImageSearchPath(
				"/Volumes", self.args.storage, self.error))
			self.check(self.sbt.AppendImageSearchPath(
				"/Applications", self.args.storage, self.error))
		if self.args.download:
			self.setVar("target.preload-symbols", "false")
			
	def load(self, path):
		self.path = path
		if self.args.storage:
			self.storagePath = os.path.abspath(self.args.storage)
		else:
			self.storagePath = os.path.dirname(os.path.abspath(self.path))
		dirs = [self.storagePath] +\
				[os.path.join(self.storagePath, x) for
					x in os.listdir(self.storagePath) if
					not x.startswith(".")]
		# TODO Check spaces in paths
		self.setVar("target.exec-search-paths", " ".join(dirs))
		self.verb("Loading '%s'..." % self.path)
		if sys.version_info[0] < 3:
			self.process = self.sbt.LoadCore(path)
		else:
			self.process = self.check(
				self.sbt.LoadCore(path, self.error))
		for m in self.sbt.modules:
			self.verb("Looking for symbols for '%s'...\n" % (
				m.file.fullpath))
			pdb = m.file.fullpath + ".pdb"
			if not os.path.isfile(pdb):
				self.verb("No symbol file '%s'\n" % pdb)
				pdb = m.file.basename.replace(".exe", "").replace(".dll", "") +\
					".pdb"
				if not os.path.isfile(pdb):
					self.verb("No symbol file '%s'\n" % pdb)
					continue
			if 0 and\
				 not m.file.fullpath.startswith(self.args.storage) and\
				 not m.file.fullpath.startswith(self.storagePath):
				continue
			self.runDebuggerCommand("target symbols add %s" % pdb)
			if os.path.realpath(m.GetSymbolFileSpec().fullpath) !=\
				 os.path.realpath(pdb):
				raise Exception(
					"Symbol file path must be '%s' but is '%s'" % (
					pdb, m.GetSymbolFileSpec().fullpath))
			self.verb("Module='%s' %d symbols in '%s' %d CUs\n" % (
				m.GetFileSpec(),
				m.GetNumSymbols(),
				m.GetSymbolFileSpec(),
				m.GetNumCompileUnits()))
		self.verb("DONE\n")
		return self

	def runDebuggerCommand(self, cmd):
		self.verb("Running '%s'..." % cmd)
		self.debugger.HandleCommand(cmd)

	def attach(self, name):
		self.verb("Attaching '%s'..." % name)
		self.process = self.check(self.sbt.Attach(
			lldb.SBAttachInfo(name, False), self.error))
		self.verb("DONE\n")
		return self

	storageShort = u"\u25A0"
	def getName(self, m):
		if not m.IsValid():
			return "-"
		if self.args.storage and\
			 m.file.fullpath.startswith(self.args.storage):
			return self.storageShort + m.file.fullpath[len(self.args.storage):]
		if self.storagePath and\
			 m.file.fullpath.startswith(self.storagePath):
			return self.storageShort + m.file.fullpath[len(self.storagePath):]
		parts = m.file.fullpath.split(os.sep)
		if len(parts) <= 1:
			return m.file.fullpath
		return "/%s/.../%s" % (parts[1], parts[-1])

	def getSymbolFileName(self, m):
		sfs = m.GetSymbolFileSpec()
		if not sfs.fullpath:
			return sfs
		if sfs == m.file:
			return "-"
		if sfs.dirname and re.match(".+[.]dSYM/", sfs.dirname):
			return "dSYM"
		if sfs.fullpath.startswith(m.file.fullpath):
			return u"\u2026" + sfs.fullpath[len(m.file.fullpath):]
		if self.args.storage and sfs.fullpath.startswith(self.args.storage):
			return self.storageShort + sfs.fullpath[len(self.args.storage):]
		return sfs

	def getSourceLine(self, f):
		if not f.line_entry.IsValid():
			return " "
		cwd = os.getcwd().split(os.sep)[-1]
		parts = f.line_entry.file.fullpath.split(os.sep)
		try:
			path = os.sep.join(parts[parts.index(cwd) + 1:])
		except ValueError:
			path = f.line_entry.file.fullpath
		return "%s:%d" % (path, f.line_entry.line)

	def getPossibleSourceLines(self, addr, template):
		if not addr.line_entry.IsValid():
			return []
		return self.getPossibleSourceLines2(
			addr.line_entry.file, addr.line_entry.line, template)

	def getPossibleSourceLines2(self, filespec, lineNumber, template):
		cwd = os.getcwd().split(os.sep)[-1]
		parts = filespec.fullpath.split(os.sep)[::-1]
		bases = [cwd]
		if self.args.base:
			bases += self.args.base.split(",")
		from itertools import takewhile
		path = os.sep.join(
			list(takewhile(lambda x: x not in bases, parts))[::-1])
		if path == filespec.fullpath:
			found = 0
			if 0:
				for root, dirnames, filenames in os.walk("."):
					if not filespec.basename in filenames:
						continue
					yield template % (
						os.path.join(root, filespec.basename),
						lineNumber)
					found += 1
			if not found:
				yield template % (
					filespec.fullpath, lineNumber)
			return
		yield template % (path, lineNumber)

	def printStacks(self):
		for t in self.process.threads:
			self.printWordsFromStack(t)

	def printStackInfo(self, t):
		sp = t.frames[0].sp
		reg = lldb.SBMemoryRegionInfo()
		error = self.process.GetMemoryRegionInfo(sp, reg)
		if error.fail:
			print("Thread%3d: sp=%s '%s' no region = '%s'" % (
				t.idx, xx(t.frames[0].sp), t.GetStopDescription(80), error))
			return None
		print("Thread%3d: sp=%s in %s-%s (%s/%s words) '%s'" % (
			t.idx, xx(t.frames[0].sp),
			xx(reg.GetRegionBase()), xx(reg.GetRegionEnd()),
			nn((reg.GetRegionEnd() - t.frames[0].sp)/ptrSize),
			nn((reg.GetRegionEnd() - reg.GetRegionBase())/ptrSize),
			t.GetStopDescription(80)))
		return reg
		
	def printDecodedFrames(self, t):
		self.prevVals = {}
		reg = self.printStackInfo(t)
		for f in t.frames:
			print("---- %d" % f.idx)
			self.printFrame(f, reg)

	def printFrame(self, f, reg):
		if 1 or self.args.base:
			printed = 0
			for prefix in self.getPossibleSourceLines(f, "%s:%d: "):
				if printed:
					sys.stdout.write("...\n")
					sys.stdout.write(prefix)
					sys.stdout.flush()
				printed += 1
		print("%s=pc '%s' %s (%s)" % (
			xx(f.pc), f.GetFunctionName(),
			self.getName(f.addr.module),
			self.getSymbolFileName(f.addr.module)))
		if f.IsInlined():
			print("Real function = %s" % (
				f.addr.symbol.name))
		deltaMsg = skippedMsg = ""
		if f.sp != self.prevVals.get("sp"):
			if "sp" in self.prevVals:
				delta = f.sp - self.prevVals["sp"]
				deltaMsg = "prev+%X " % (delta)
				skippedMsg = ", skipped %s" % nn(delta/ptrSize-1)
			print("sp=%s %s(%s words%s)" % (
				xx(f.sp), deltaMsg,
				nn((reg.GetRegionEnd() - f.sp)/ptrSize), skippedMsg))
			self.prevVals["sp"] = f.sp
		if not self.args.disassembly: return
		self.printRegs(f, prevVals)
		print("")
		if f.IsInlined(): return
		insns = self.getFuncInstructions(f)
		if insns:
			for ii in insns:
				self.printInstruction(ii)
		return
		# arguments, locals, statics, in_scope_only
		for v in f.GetVariables(True, True, False, True):
			print("'%s' loc='%s' v='%s' t=%s(%d)" % (
				v.name, v.location, v.value,
				v.type.name, v.type.size))

	def printRegs(self, f, prevVals):
		for rs in f.GetRegisters():
			for v in rs:
				if v.name[0] == "r" and\
					 not v.name in ["rflags", "rip", "rsp"]:
					if prevVals.get(v.name) == v.value:
						continue
					if v.value is None:
						continue
					sys.stdout.write("%s=%s " % (
						v.name, xx(v.GetValueAsUnsigned())))
					prevVals[v.name] = v.value
		print("")

	def printInstruction(self, ii, needCode=False):
		ibs = ""
		data = ii.GetData(self.sbt)
		bytes = self.check(
			data.ReadRawData(self.error, 0, ii.GetByteSize()))
		if needCode:
			for bv in bytes:
				ibs += "%02X " % bv
		comment = ii.GetComment(self.sbt)
		if comment:
			comment = " ; " + comment
		name = ii.GetMnemonic(self.sbt)
		ptr = ii.addr.GetLoadAddress(self.sbt)
		print("	 %s %s%s %s%s" % (
			xx(ptr), ibs, name, ii.GetOperands(self.sbt), comment))
		if "callq" == name:
			call = UnwindFrame.getCall(self, bytes, ptr + len(bytes))
			if call and call.destination:
				da = self.sbt.ResolveLoadAddress(call.destination)
				print("	 => %s %s %s %s" % (
					xx(call.destination), self.getName(da.module),
					UnwindFrame.describeAddr(self, da), da.section.name))
			
	def getFuncInstructions(self, f, pc):
		# Doesn't work
		# insns = f.function.GetInstructions(self.sbt)
		# also: symbol.GetInstructions
		size = f.symbol.end_addr.GetOffset() - f.symbol.addr.GetOffset()
		secBase = pc - f.offset
		#fpos = f.symbol.IsValid() and\
		#	f.symbol.addr.GetLoadAddress(self.sbt)
		fpos = secBase + f.symbol.addr.offset
		if not f.symbol.addr.IsValid():
			print("Addr not valid on %s" % f.symbol)
		if not fpos or not size:
			return
		bytes = f.symbol.addr.section.GetSectionData().\
			ReadRawData(self.error, f.symbol.addr.offset, size)
		if self.error.fail:
			bytes = self.process.ReadMemory(fpos, size, self.error)
			if self.error.fail:
				print("Error reading memory %s size=%s (%s %s(=%s):%s) = '%s'" % (
					xx(fpos), xx(size),
					f.symbol, f.symbol.addr.section.name,
					f.symbol.addr.section.GetLoadAddress(self.sbt),
					xx(f.symbol.addr.offset), self.error))
				return
		return self.sbt.GetInstructions(f.symbol.addr, bytes)

	def printWordsFromStack(self, n):
		if type(n) is int:
			th = self.process.GetThreadByIndexID(n)
			if not th.IsValid():
				raise Exception("No thread %d" % n)
		else:
			th = n
		sp = th.frames[0].sp
		stack = self.printStackInfo(th)
		self.printRegs(th.frames[0], {})
		if self.args.threadm or self.args.fa:
			self.doCmd("memory read --force -fA 0x%X 0x%X" % (
				sp, stack.GetRegionEnd()))
			return
		if self.args.hex:
			self.check(hexDumpMem(
				self.process, sp, stack.GetRegionEnd(), self.error))
			return
		# -x = try to follow call chain
		# -z = trawl stack for everything that can be a caller PC
		if self.args.thread:
			uwf = UnwindFrame(self).loadTopOfStack(th, stack)
			while uwf:
				uwf.print()
				uwf = UnwindFrame(self).loadReturnAddress(
					uwf.getReturnAddrLoc(), stack)
			return
		self.printPointers(sp, stack.GetRegionEnd(), stack)

	def printPointers(self, sp, end, stack):
		"""
		TODO:
		Need more fundamental pointer classification to bins like
		"same stack" (done) "other stack" "heap" "not pointer"
		"code" (done) "code/caller PC" (done) "data" (resolve recursively, done) 
		"""
		cs = CallSite(self)
		cs.stack = stack
		cs.sp = sp
		for pretaddrl in range(sp, stack.GetRegionEnd(), ptrSize):
			# If it points to current stack then it can't be return address
			self.error.Clear()
			ra0 = self.check(self.process.ReadPointerFromMemory(
				pretaddrl, self.error))
			cs.pos = pretaddrl
			msg = cs.describePointer(ra0)
			print("%s: %s %s" % (xx(pretaddrl), xx(ra0), msg))
			for ii in cs.callerInstrs:
				self.printInstruction(ii)
			# Don't follow pointer if in the same region or code
			if cs.callerInstrs or (ra0 >= sp and ra0 <= end):
				continue
			for level in range(1, 32):
				if (cs.reg is None) or cs.pa.function.IsValid():
					break
				# TODO Detect loops
				self.error.Clear()
				ra0 = self.check(self.process.ReadPointerFromMemory(
					ra0, self.error))
				msg = cs.describePointer(ra0)
				print("%s %s %s" % (" "*level, xx(ra0), msg))

	def getAscii(self, pos, size):
		# ReadCStringFromMemory can't specify the code page
		seq = self.process.ReadMemory(pos, size, self.error)
		if self.error.fail:
			return "error: %s" % self.error
		for b in seq:
			if b == 0:
				return ""
		return seq.decode("windows-1251")

	def doCmd(self, cmd):
		self.verb("cmd: '%s'\n" % cmd)
		self.debugger.HandleCommand(cmd)

	def describeName(self, path):
		bn = os.path.basename(path)
		return len(bn) < 32 and bn or bn[:32] + "..."

	def getThreadWithStackInRegion(self, r):
		for th in self.process.threads:
			sp = th.frames[0].sp
			if sp >= r.GetRegionBase() and sp < r.GetRegionEnd():
				return th

	def countMemoryByType(self):
		mc = MemTypeCount()
		regions = self.process.GetMemoryRegions()
		sbr = lldb.SBMemoryRegionInfo()
		for i in range(regions.GetSize()):
			if not regions.GetMemoryRegionAtIndex(i, sbr):
				raise Exception("TODO")
			if not sbr.IsReadable() or not sbr.IsWritable() or sbr.IsExecutable():
				continue
			size = sbr.GetRegionEnd() - sbr.GetRegionBase()
			if self.getThreadWithStackInRegion(sbr):
				mc.stack += size
			else:
				mc.heap += size
		return mc

	def scanForVtables(self):
		mc = self.countMemoryByType()
		raise Exception("TODO")

	def printRegions(self):
		class Count:
			def __init__(self):
				self.scanned = self.total = self.errors = self.readable = 0
		if self.args.scan:
			class Sample():
				def __init__(self, path):
					self.path = path
					self.bs = open(path, "rb").read()
					if 1:
						pp = self.bs.find(b"?")
						if pp >= 0:
							self.bs = self.bs[pp+1:]
			samples = []
			if os.path.isdir(self.args.scan):
				for name in os.listdir(self.args.scan):
					s = Sample(os.path.join(self.args.scan, name))
					if len(s.bs) > 0:
						samples += [s]
			else:
				samples = [Sample(self.args.scan)]
			count = Count()
		regions = self.process.GetMemoryRegions()
		r = lldb.SBMemoryRegionInfo()
		for i in range(regions.GetSize()):
			if not regions.GetMemoryRegionAtIndex(i, r):
				raise Exception("TODO")
			size = r.GetRegionEnd() - r.GetRegionBase()
			name = r.GetName()
			if name:
				name = os.path.basename(name)
			if self.args.scan and not r.IsReadable(): # or r.IsExecutable():
				continue
			th = self.getThreadWithStackInRegion(r)
			# r.GetNumDirtyPages() always returns 0
			print("%s %s%s%s%s %s %s%s" % (
				self.describeName(self.path),
				(r.IsReadable() and "r" or "."),
				(r.IsWritable() and "w" or "."),
				(r.IsExecutable() and "x" or "."),
				(r.IsMapped() and "m" or "."),
				xr(r.GetRegionBase(), r.GetRegionEnd()),
				name and (" '%s'" % name) or "",
				th and (" S%s" % th.GetIndexID()) or ""))
			if self.args.scan:
				count.readable += 1
				# self.error.Clear() doesn't work
				self.error = lldb.SBError()
				all = self.process.ReadMemory(r.GetRegionBase(), size, self.error)
				if self.error.fail or (all is None) or len(all) < size:
					print("Got %s reading %s bytes from %s" % (
						self.error.fail and self.error or (all and nn(len(all))),
						nn(size), xx(r.GetRegionBase())))
					count.errors += 1
				# Error is for sections that don't have PT_LOAD type
				if not self.error.fail:
					count.total += size
				if self.error.fail or all is None:
					continue
				count.scanned += len(all)
				for sample in samples:
					biggerSize = len(sample.bs) + 40
					p = -1
					while True:
						p = all.find(sample.bs, p + 1)
						if p < 0:
							break
						b = self.process.ReadMemory(
							r.GetRegionBase() + p, biggerSize, self.error)
						if self.error.fail:
							print("%s" % self.error)
							continue
						print("%s %s found='%s'" % (
							sample.path, xx(r.GetRegionBase() + p), b))
		if self.args.scan:
			print("Scanned %s/%s, %d errors of %d regions (%d readable)" %
						(nn(count.scanned), nn(count.total),
						 count.errors, regions.GetSize(), count.readable))
		mc = self.countMemoryByType()
		printSize(mc, "Heap")
		printSize(mc, "Stack")
			

	def replaceModuleFromStorage(self, m):
		"""
		Only need to call this if exec-search-paths doesn't pick up the
		image for some reason
		"""
		for ver in ["."] + os.listdir(self.args.storage):
			path = os.path.join(self.args.storage, ver, m.file.basename)
			if not os.path.isfile(path):
				continue
			# path, architecture, UUID, symfile
			new = self.sbt.AddModule(path, None, None, None)
			if not new:
				raise Exception("%s not added" % path)
			if new.uuid != m.uuid:
				self.verb("Skipping %s (%s) for '%s'\n" % (
					new.file.fullpath, new.uuid, m.file.basename))
				self.sbt.RemoveModule(new)
				continue
			if m.num_sections != new.num_sections:
				self.verb(
					"Module %s: num_sections differ,\n%d in %s\n%d in %s" % (
						m.uuid, m.num_sections, m.file.fullpath,
						new.num_sections, new.file.fullpath))
				self.sbt.RemoveModule(new)
				continue
			for i in range(m.num_sections):
				check(self.sbt.SetSectionLoadAddress(
					new.sections[i],
					m.sections[i].GetLoadAddress(self.sbt)))
			self.sbt.RemoveModule(m)
			return 
		msg = ("'%s' (%s) not in storage" % (
			m.file.fullpath, m.uuid))
		if self.args.unchecked:
			self.verb(msg)
		else:
			raise Exception(msg)

	def printModules(self, tool):
		count = Count()
		mtime = time.localtime(os.path.getmtime(self.path))
		if self.args.modules:
			print("\
nsect, all sections size on disk, id, load addr, name, symfile")
		for m in self.sbt.modules:
			path = m.file.fullpath;
			parts = path.split("/")
			if len(parts) > 1:
				if self.args.storage and\
					 m.file.fullpath.startswith(self.args.storage):
					count.store += 1
				elif parts[1] in ["Volumes", "Applications"]:
					count.other += 1
				else:
					count.system += 1
			else:
				count.other += 1
			name = self.getName(m)
			fsize = sum(s.file_size for s in m.sections)
			if fsize == 0:
				count.absent += 1
			if self.args.absent:
				if fsize != 0:
					continue
				print(time.strftime("%Y-%m-%d %H:%M| %%s %%s", mtime) % (
					(self.args.stat and m.uuid or self.path), name))
				continue
			elif self.args.modules:
				print("%2d %08X %s %s '%s' %s" % (
					m.num_sections, fsize, justifyId(m, self.args.long),
					xx(self.getSomeLoadAddress(m)), name,
					self.getSymbolFileName(m)))
				if m.GetUUIDString():
					print(
						"curl -L https://debuginfod.debian.net/buildid/%s/debuginfo	 -o %s.pdb" % (
#						"curl -L https://debuginfod.ubuntu.com/buildid/%s/debuginfo -o %s.pdb" % (
							getId(m, True).lower(), m.file.basename))
				if fsize:
					def printSec(prefix, sec):
						print("%s%s+%s %s" % (
							prefix, xx(sec.GetLoadAddress(self.sbt)),
							xx(sec.GetByteSize()),
							sec.name))
						for i in range(sec.GetNumSubSections()):
							printSec(prefix + " ", sec.GetSubSectionAtIndex(i))
					for sec in m.sections:
						printSec("	", sec)
		if 1:
			print("gdb -ex 'set sysroot %s' %s %s" % (
				os.path.dirname(self.sbt.executable.fullpath),
				self.sbt.executable, self.path))
		if self.args.stat:
			if not hasattr(tool, "statHeaderPrinted"):
				print(" modules: total, system, store, other, absent")
				tool.statHeaderPrinted = True
			print(
				self.getTime() + "%3d %3d %3d %3d %3d %11s %11s %s '%s'" % (
					self.sbt.GetNumModules(),
					count.system, count.store, count.other, 
					count.absent, cut(self.path, 8),
					cut(self.sbt.executable.basename, 8),
					self.process.selected_thread.frames[0].addr,
					self.process.selected_thread.GetStopDescription(80)))

	def getSomeLoadAddress(self, m):
		for s in m.sections:
			for i in range(s.GetNumSubSections()):
				ss = s.GetSubSectionAtIndex(i)
				if ss.GetLoadAddress(self.sbt) != 0xFFFFFFFFFFFFFFFF:
					return s.GetLoadAddress(self.sbt)
				print("Invalid load address for '%s'" % (ss.name))
			if s.GetLoadAddress(self.sbt) != 0xFFFFFFFFFFFFFFFF:
				break
			print("Invalid load address for	 '%s'" % (s.name))
		return s.GetLoadAddress(self.sbt)

	def getTime(self):
		mtime = time.localtime(os.path.getmtime(self.path))
		return time.strftime("%Y-%m-%d %H:%M| ", mtime)

	def queueDownloadSymbols(self, server):
		if not self.args.storage:
			raise Exception("Can't download without storage dir")
		work = []
		for m in self.sbt.modules:
			if not m.file.fullpath.startswith(self.args.storage):
				continue
			self.verb("Full=%s\n" % m.file.fullpath)
			work.append(DownloadTemplate(
				server, "%s/%s/%s.dSYM.tar.bz2", m))
			if 0: # found this in 1 file on gh, but it never worked
				work.append(DownloadTemplate(
					server, "%s/%s/%s.tar.bz2", m))
		return work


class DownloadTemplate:
	def __init__(self, server, tmpl, m):
		self.server = server
		self.template = tmpl
		self.module = m
		
	def run(self, tool):
		m = self.module
		url = self.server.getUrl(self.template % (
			m.file.basename, getId(m, self.args.long), m.file.basename))
		name = url.split("/")[-1].split(".tar.bz2")[0]
		expected = os.path.join(m.file.dirname, name)
		if os.path.isdir(expected):
			tool.verb("Already have %s\n" % expected)
			return
		# Better have private tmp for each version so nothing gets mixed
		tmp = os.path.join(m.file.dirname, "tmp")
		if not os.path.isdir(tmp):
			os.mkdir(tmp)
		try:
			self.server.download(url, tmp, tool, useCurl=True)
		except SymbolNotOnServer:
			print("%s not found" % url)
			return
		self.rename(os.path.join(tmp, name), expected, tool)

	def rename(self, src, dst, tool):
		tool.verb("Renaming %s -> %s" % (src, dst))
		os.rename(src, dst)
		

class Server:
	def __init__(self, args):
		self.args = args
		self.hasResumableDownloads = True
		
	def startCurlWithResumeEnabled(self, url, dir):
		name = url.split(os.sep)[-1]
		curl = subprocess.Popen(
			["curl", "-L", "-C", "-", url, "-o", name],	cwd=dir)
		return (curl, name)

	def shortenFile(self, path, amount):
		with open(path, "+b") as f:
			f.truncate(os.path.getsize(path) - amount)

	def getUrl(self, path):
		prefix = self.args.download
		if not prefix.endswith("/"):
			if not path.startswith("/"):
				prefix += "/"
		return prefix + path

	def download(self, url, dir, tool, useCurl=False, tarBz2=True):
		tool.print("Downloading %s -> %s..." % (url, dir))
		if not tarBz2:
			import bz2
			bz2dec = bz2.BZ2Decompressor()
		count = None
		if useCurl:
			if self.hasResumableDownloads:
				curl, name = self.startCurlWithResumeEnabled(url, dir)
				if curl.wait() == 33:
					# Some servers break if we have full content...
					self.shortenFile(os.path.join(dir, name), 1)
					curl, _ = self.startCurlWithResumeEnabled(url, dir)
				if curl.wait() == 33:
					self.hasResumableDownloads = False
				elif curl.wait() != 0:
					raise Exception("curl.wait() = %d", curl.wait())
				src = open(os.path.join(dir, name), "rb")
				count = WorkCount(os.path.getsize(os.path.join(dir, name)))
			if not self.hasResumableDownloads:
				curl = subprocess.Popen(
					["curl", "-L", url], stdout=subprocess.PIPE)
				src = curl.stdout
		else:
			import urllib.request
			src = urllib.request.urlopen(url)
			if src.getcode() == 404:
				raise SymbolNotOnServer(src.getcode())
			elif src.getcode() != 200:
				raise Exception("src.getcode() = %d" % src.getcode())
		tar = subprocess.Popen(
			["tar", "xv%s" % (tarBz2 and "j" or "")],
			stdin=subprocess.PIPE, cwd=dir)
		while True:
			p = src.read(16384)
			if not p:
				break
			try:
				message = p.decode("utf-8")
			except Exception:
				message = None
			if message == "Symbol Not Found":
				raise SymbolNotOnServer(message)
			if count:
				count.done += len(p)
			tool.print("unpacking...", count)
			if not tarBz2:
				p = bz2dec.decompress(p)
			try:
				tar.stdin.write(p)
			except EOFError:
				pass # tar exited?
		tar.stdin.close()
		if tar.wait() != 0:
			raise Exception("tar.wait() = %d", tar.wait())


class Tool(Util):
	def __init__(self, args, debugger):
		self.args, self.debugger = args, debugger
		self.work = []
		if self.debugger is None:
			self.verb("Starting debugger...")
			self.debugger = lldb.SBDebugger.Create()
			self.verb("DONE name=%s\n" % self.debugger.GetInstanceName())
		# This is faster than replacing modules in fixModulesNotInStorage
		if self.args.storage:
			self.args.storage = self.args.storage.rstrip("/")
		if self.args.dverbose:
			# doesn't check categories
			if not self.debugger.EnableLog("lldb", ["dyld"]):
				raise Exception("Bad log")
		
	def run(self):
		# self.verb("Press ENTER...")
		# sys.stdin.read(1)
		if self.args.attachname:
			self.handleTarget(Target(self.args, self.debugger).attach(
				self.args.attachname))
		if not self.args.DMPFILE:
			parser.print_help()
			print("LLDB version = '%s'" % lldb.SBDebugger.GetVersionString())
		self.args.DMPFILE.sort(key=os.path.getmtime, reverse=True)
		for path in self.args.DMPFILE:
			try:
				t = Target(self.args, self.debugger).load(path)
				self.handleTarget(t)
			except Exception as e:
				if not self.args.stat: raise
				print("%s = %s" % (path, e))
		self.count = WorkCount(len(self.work))
		for task in self.work:
			task.run(self)
			self.count.done += 1

	def handleTarget(self, t):
		if not self.args.stat:
			print("\u2592\n\u2592 \u2770 Crash %s \u2771\n\u2592" % t.path)
			sys.stdout.flush()
			# TODO Storage here is only 1 level, different from
			# in the script above
			cmd = "lldb %s-o 'target create --core %s'" % (
				self.args.storage and (
					"-o 'settings set target.exec-search-paths %s'" %
					self.args.storage) or "", t.path)
			for mo in t.sbt.modules:
				if mo.GetSymbolFileSpec().IsValid():
					if mo.GetSymbolFileSpec() != mo.file:
						cmd += " -o 'target symbols add %s'" % (
							mo.GetSymbolFileSpec().fullpath)
			print(cmd)
		if self.args.download:
			self.work += t.queueDownloadSymbols(Server(self.args))
		elif self.args.threadn or self.args.threadm:
			t.printWordsFromStack(
				int(self.args.threadn or self.args.threadm, 10))
		elif self.args.thread or self.args.fa or self.args.callsites or\
				 self.args.hex or self.args.telescope:
			t.printWordsFromStack(t.process.selected_thread)
		elif self.args.threads:
			t.printStacks()
		elif self.args.bt:
			t.doCmd("bt")
		elif self.args.threadf:
			t.printDecodedFrames(t.process.selected_thread)
		elif self.args.modules or self.args.absent:
			t.printModules(self)
		elif self.args.scan:
			t.printRegions()
		elif not self.args.stat:
			t.printRegions()
		if not (self.args.modules or self.args.absent):
			if self.args.stat:
					t.printModules(self)

def icu(ptr, sbp, err):
	"""
	size=64 name=icu_66::UnicodeString
	+0-8			icu_66::Replaceable
	+-0-8			 icu_66::UObject
	+--0-1			icu_66::UMemory
	+8-64			fUnion icu_66::UnicodeString::StackBufferOrFields
	+-8-64		 fStackFields icu_66::UnicodeString::StackBufferOrFields::unnamed
	+--8-10			fLengthAndFlags short
	+--10-64		fBuffer char16_t[27]
	+-8-32		 fFields icu_66::UnicodeString::StackBufferOrFields::unnamed
	+--8-10			fLengthAndFlags short
	+--12-16		fLength int
	+--16-20		fCapacity int
	+--24-32		fArray char16_t *
	"""
	buf = sbp.ReadMemory(ptr, 64, err)
	if err.fail:
		return
	flags, length2, capacity, start = struct.unpack("HxxiixxxxP", buf[8:32])
	if flags & 0x8000:
		length = length2
	else:
		length = flags>>5
	# print("length=%d"	 % length)
	# Length in 2byte chars
	if flags & 2:
		bb = bytes(buf[10:10+length*2])
	else:
		bb = sbp.ReadMemory(start, length*2, err)
	return err.success and bytes(bb).decode("utf-16", errors="replace")

def icuOrError(a0, sbp):
	err = lldb.SBError()
	us = icu(a0, sbp, err)
	return err.fail and err or repr(us)

class DpcError(Exception):
	pass

class DataPrintoutContext(Util):
	def __init__(self, sbt=None):
		self.error = lldb.SBError()
		self.valName = None
		self.filter = self.negFilter = None
		self.printed = set()
		self.sbt = sbt
		
	def detectTypes(self, a0, sbt):
		# print("self.filter=%s" % self.filter)
		vtb0 = sbt.process.ReadPointerFromMemory(a0, self.error)
		if not self.filter:
			self.check(None)
		if not self.error.fail:
			vtbl = sbt.ResolveLoadAddress(vtb0)
			sc = sbt.GetModuleAtIndex(0).ResolveSymbolContextForAddress(
				vtbl, 255 | lldb.eSymbolContextVariable)
			0 and print("vtb0=%x sc='%s' cu='%s' %s" % (
				vtb0, sc, sc.GetCompileUnit(), sc.symbol))
			pp = str(sc.symbol.name).split(" for ")
			if (len(pp) > 1):
				return self.findTypes1(pp[1], sbt)
		# Sometimes can't resolve vtable - check for desstructor
		dest0 = self.check(sbt.process.ReadPointerFromMemory(vtb0, self.error))
		destr = lldb.SBAddress(dest0, sbt)
		# "function" works with PDB debug info
		name = destr.function.name or destr.symbol.name
		if not name:
			raise DpcError("Head not resolvable %s" % (xx(dest0)))
		if "~" in name:
			return self.findTypes1(name.split("~")[0][:-2], sbt)
		name = name.split("::")[0]
		types = self.findTypes(name, sbt)
		if len(types) == 1:
			return types
		# Heuristics
		name = name.split("<")[-1].split(",")[0]
		return self.findTypes1(name, sbt)
	
	def findTypes(self, typeName, sbt):
		for im in sbt.modules:
			if len(types := im.FindTypes(typeName)):
				break
		return types

	def findTypes1(self, typeName, sbt):
		types = self.findTypes(typeName, sbt)
		if len(types) != 1:
			raise DpcError("%d types '%s'" % (len(types), typeName))
		return types

	def getValue(self, a0, sbt, typeName=None):
		if typeName:
			types = self.findTypes1(typeName, sbt)
		else:
			types = self.detectTypes(a0, sbt)
		typeName = types.GetTypeAtIndex(0).name
		addr = lldb.SBAddress(a0, sbt)
		return sbt.CreateValueFromAddress(
			self.valName or ("*"+typeName), addr, types.GetTypeAtIndex(0))
		
	def printValue(self, val, trail):
		indent=None
		if len(trail) > 40:
			print("%s%s level too big" % (len(trail), val.name))
			return
		type = val.GetType()
		key = "%s-%s" % (val.GetAddress(), type.name)
		if key in self.printed:
			return
		self.printed.add(key)
		if self.negFilter:
			if val.name and re.search(self.negFilter, val.name):
				return
			if type.name and re.search(self.negFilter, type.name):
				return
		if 1 or val.name != type.name:
			trail = trail + [str(val.name).replace("[", "").replace("]", "")]
		prefix = str(val.GetAddress()) + (indent or (" %s " % ".".join(trail)))
		# 'suppress' = no print but still iterate through the children
		suppress = self.filter and not re.search(self.filter, prefix) and\
			not re.search(self.filter, type.name)
		name = "%s" % (val.GetType().name)
		shortTrail = ".".join(trail)
		if len(shortTrail) > 60:
			shortTrail = "..." + shortTrail[-60:]
		# Hack: we don't follow pointers but will follow vector elements
		# if there is a filter just because I need that at the moment
		if self.filter and name.startswith("std::vector"):
			0 and print("vector %s nta=%d of %s" % (
				name, type.GetNumberOfTemplateArguments(),
				type.GetTemplateArgumentType(1)))
			# type.GetTemplateArgumentType() doesn't work on windows
			tan = name.split("<")[1].split(",")[0]
			taTypes = self.findTypes1(tan, self.sbt)
			for ch in self.getVectorElementValues(
					val.GetLoadAddress(), taTypes.GetTypeAtIndex(0)):
				self.printValue(ch, trail)
		summary = val.GetSummary() or val.GetValue()
		nc = 0 if type.IsPointerType() else val.GetNumChildren()
		if 0 == nc:
			if suppress: return
			if not summary:
				err = lldb.SBError()
				num = val.GetValueAsUnsigned(err)
				if type.IsPointerType():
					num = xx(num)
				summary = err.fail and ("error: %s" % err) or num
		if summary:
			print("\r%s%s = %s" % (prefix, name, summary))
			# Can have summary AND children
		# char buffers has contents in the summary
		if nc and not type.name in summaryIsEnoughList and\
			 not type.name.startswith("char[") and\
			 not type.name.startswith("char16_t["):
			if not suppress:
				print("%s%s has %d children" % (prefix, name, nc))
			for ii in range(nc):
				nv = val.GetChildAtIndex(ii)
				self.printValue(nv, trail)

	def getVectorElementValues(self, vecPos, type):
		p0 = self.readPtr(vecPos)
		p1 = self.readPtr(vecPos + ptrSize)
		for num, pos in enumerate(range(p0, p1, type.GetByteSize())):
			yield self.sbt.CreateValueFromAddress(
				str(num), lldb.SBAddress(pos, self.sbt), type)

	def scanForPtrsToType(self, start, end, typeName):
		past = set()
		for pos in range(start, end, ptrSize):
			self.error.Clear()
			a0 = self.check(self.process.ReadPointerFromMemory(
				pos, self.error))
			if a0 in past:
				continue
			past.add(a0)
			try:
				types = self.detectTypes(a0, self.sbt)
			except (DpcError, DebuggerError):
				continue
			if types.GetTypeAtIndex(0).name == typeName:
				yield self.sbt.CreateValueFromAddress(
					"_", lldb.SBAddress(a0, self.sbt), types.GetTypeAtIndex(0))

	def scanStackForPtrsToType(self, thread, typeName):
		self.process = self.sbt.process
		sp  = self.process.GetSelectedThread().frames[0].sp
		reg = self.getRegion(sp)
		return self.scanForPtrsToType(sp, reg.GetRegionEnd(), typeName)

summaryIsEnoughList = ["UnicodeString", "KString"]

def unxx(addrt):
	if "," in addrt:
		return int("".join(addrt.split(",")), 16)
	else:
		return int(addrt, 0)
	
def printType(debugger, command, result, internal_dict):
	"""
	Print TYPE object at ADDR. If TYPE not given or "*", detect it
	by vtable. 
	"""
	commandArguments = re.split(r"\s+", command)
	if not (len(commandArguments) in range(1, 5)):
		print("usage: dt ADDR[-ADDR] [TYPE] [REGEXP] [REGEXP_NEGATIVE]")
		return
	addrt = commandArguments[0]
	if "-" in addrt:
		a0, b0 = (unxx(s) for s in addrt.split("-"))
	else:
		a0, b0 = unxx(addrt), None
	dpc = DataPrintoutContext()
	dpc.filter = (len(commandArguments) >= 3) and re.compile(commandArguments[2])
	dpc.negFilter = (len(commandArguments) >= 4) and\
		re.compile(commandArguments[3])
	if len(commandArguments) == 1:
		typeName = None
	else:
		typeName = commandArguments[1]
		if "*" == typeName:
			typeName = None
	val = dpc.getValue(a0, debugger.GetSelectedTarget(), typeName)
	data = val.GetData()
	print("data=%s" % (data))
	dpc.printValue(val, [])
	if b0:
		tp = val.GetType()
		for p in range(a0 + tp.size, b0, tp.size):
			val = dpc.getValue(p, debugger.GetSelectedTarget(), tp.name)
			dpc.printValue(val, [])

def printIcu(debugger, command, result, internal_dict):
	commandArguments = re.split(r"\s+", command)
	for arg in commandArguments:
		err = lldb.SBError()
		a0 = int(arg, 0)
		us = icu(a0, debugger.GetSelectedTarget().process, err)
		print(" %s %s" % (xx(a0), err.fail and err or repr(us)))

def doScanForPtrsToType(debugger, command, result, internal_dict):
	commandArguments = re.split(r"\s+", command)
	print(commandArguments)
	if not len(commandArguments) in [1,2] or not commandArguments[0]:
		print("USAGE: spt TYPE_NAME [FILTER_REGEXP]")
		return
	dpc = DataPrintoutContext(debugger.GetSelectedTarget())
	if len(commandArguments) >= 2:
		dpc.filter = commandArguments[1]
	for val in dpc.scanStackForPtrsToType(
			dpc.sbt.process.GetSelectedThread(), commandArguments[0]):
		dpc.printValue(val, [])
		
def summaryIcu(val, internal_dict):
	rs = icuOrError(val.GetLoadAddress(), val.GetProcess())
	if len(rs) > 1024:
		rs = "..." + rs[-1024:]
	return rs

class SyntheticVal:
	def __init__(self, val, internal_dict):
		self.val = val
		self.vt = val.GetChildMemberWithName("type").GetValue()
		
	def num_children(self, max):
		if self.vt in ["TYPE_UNDEFINED", "TYPE_NUMBER"]:
			return 0
		return 1
	
	def get_child_at_index(self, index):
		# Doesn't work
		# return self.val.GetValueForExpressionPath(".obj")
		if "TYPE_LOGICAL" == self.vt:
			return self.val.GetChildMemberWithName("logical_")
		if "TYPE_STACK_FUNCT" == self.vt:
			return self.val.GetChildMemberWithName("funInfo").Dereference()
		if "TYPE_NUMBER" == self.vt:
			return self.val.GetChildMemberWithName("value")
		dpc = DataPrintoutContext()
		# objAddr = dpc.check(self.val.GetProcess().ReadPointerFromMemory(
		#	 self.val.GetLoadAddress() + 8, dpc.error))
		objAddr = int(self.val.GetChildMemberWithName("value").GetValue())
		if 0 == objAddr:
			return 0
		try:
			return dpc.getValue(objAddr, self.val.GetTarget())
		except DebuggerError as e:
			return str(e)

class SyntheticFsi:
	def __init__(self, val, internal_dict):
		self.val = val
	
	def num_children(self, max):
		return 1
	
	def get_child_at_index(self, index):
		pcallee = self.val.GetChildMemberWithName("vars").\
			GetChildMemberWithName("callee").\
			GetChildMemberWithName("_ptr").GetValueAsUnsigned()
		dpc = DataPrintoutContext()
		return dpc.getValue(pcallee, self.val.GetTarget())

def summaryVal(val, internal_dict):
	val = val.GetNonSyntheticValue()
	vt = val.GetChildMemberWithName("type")
	if vt.GetValue() == "TYPE_NUMBER":
		vv = val.GetChildMemberWithName("value")
	else:
		return "type=%s" % vt.GetValue()
	return "type=%s v=%s" % (vt.GetValue(), vv.GetValue())

class SyntheticVmv:
	def __init__(self, val, internal_dict):
		self.val = val
	
	def num_children(self, max):
		return 1
	
	def get_child_at_index(self, index):
		pcallee = self.val.\
			GetChildMemberWithName("callee").\
			GetChildMemberWithName("_ptr").GetValueAsUnsigned()
		dpc = DataPrintoutContext()
		dpc.valName = "callee"
		return dpc.getValue(pcallee, self.val.GetTarget())

def emplSpec0(debugger, command, result, internal_dict):
	commandArguments = re.split(r"\s+", command)
	if commandArguments[0]:
		print("USAGE: e0")
	dpc = DataPrintoutContext(debugger.GetSelectedTarget()) 
	for val in dpc.scanStackForPtrsToType(
			dpc.sbt.process.GetSelectedThread(),"SockObj"):
		vec = val.GetChildMemberWithName("input").GetChildMemberWithName("data_")
		print("vec addr %s" % (xx(vec.GetLoadAddress())))
		page0Pos = dpc.readPtr(vec.GetLoadAddress())
		bufPos = dpc.readPtr(page0Pos)
		bufLen = dpc.readPtr(page0Pos + ptrSize)
		postData = dpc.check(
			dpc.sbt.process.ReadMemory(bufPos, bufLen, dpc.error))
		print("curl -b cookies-htgi-dmz.txt -c cookies-htgi-dmz.txt -vL\\")
		print("http://htgi.dmz:9999/docs/text --data\\")
		print("'%s'" % postData.decode())

def __lldb_init_module(debugger, internal_dict):
	"To load: command script import ~/stuff/crashtools.py"
	debugger.HandleCommand(
		"command script add --overwrite -f %s.printType dt" % __name__)
	debugger.HandleCommand(
		"command script add --overwrite -f %s.printIcu icu" % __name__)
	debugger.HandleCommand(
		"command script add --overwrite -f %s.doScanForPtrsToType spt" %
		__name__)
	debugger.HandleCommand(
		"command script add --overwrite -f %s.emplSpec0 e0" % __name__)
	debugger.HandleCommand(
		"type summary add -F %s.summaryIcu KString" % __name__)
	debugger.HandleCommand(
		"type summary add -F %s.summaryIcu icu_66::UnicodeString" % __name__)
	debugger.HandleCommand(
		"type summary add -F %s.summaryVal Val" % __name__)
	debugger.HandleCommand(
		"type synthetic add Val --python-class %s.SyntheticVal" %
		__name__)
	if 0:
		debugger.HandleCommand(
			"type synthetic add FunStackInfo --python-class %s.SyntheticFsi" %
			__name__)
	debugger.HandleCommand(
		"type synthetic add __VMvars --python-class %s.SyntheticVmv" %
		__name__)
	print("%s loaded" % __name__) 

if __name__ == "__main__":
	# This makes my Mac (standard LLDB package) segfault 
	if 0 and sys.version_info[0] < 3:
		import codecs
		sys.stdout = codecs.getwriter("utf-8")(sys.stdout)
	Tool(parser.parse_args(), None).run()

	
