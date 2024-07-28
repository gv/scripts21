#!/usr/bin/env python3
from __future__ import print_function
"LLDB commands to get stuff from crash dumps"
import argparse, re, os, sys, time, subprocess, struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("DMPFILE", help="Path to core file", nargs="*")
parser.add_argument(
	"-b", "--base", help="Print stack of crashed thread")
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
		"-T", "--threads", action="store_true",
		help="Print frames decoded by lldb (each thread)")
parser.add_argument(
	"-B", "--bt", action="store_true",
	help="Print stack of crashed thread")
parser.add_argument(
	"-x", "--thread", action="store_true", 
	help="Unwind stack by counting PUSH/SUB *,SP instructions in code")
parser.add_argument(
	"-C", "--threadC", action="store_true", 
	help="Print all stack words from crashed thread pointing to code")
parser.add_argument(
	"-y", "--threadn", help="Print all words from stack N")
parser.add_argument(
	"-X", "--threadX", action="store_true", 
	help="Print all words from crashed thread using `memory read -fA`")
parser.add_argument(
	"-Y", "--threadm",
	help="Print all words from stack N using `memory read -fA`")
parser.add_argument(
	"-D", "--disassembly", action="store_true",
	help="Show disassembly of functions in the stack")
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

class SymbolNotOnServer(Exception):
	pass

class CallSite:
	def __init__(self, target):
		self.target = target
		self.error = target.error
		self.sbt = target.target
		self.sbp = target.process
		self.args = target.args
		
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

	def findCaller(self):
		class Count:
			def __init__(self):
				self.words = self.calls = self.destinations = 0
				self.pointers = self.readable = 0
		self.count = Count()
		pc = lldb.SBAddress(self.pc, self.sbt)
		self.insns = pc.symbol.IsValid() and\
			self.target.getFuncInstructions(pc)
		if self.insns:
			self.pushCount, self.spDecrement =\
				self.target.getPushCountAndStackDecrement(self.insns)
			self.returnAddrLocation =\
				self.sp + (ptrSize*self.pushCount) + self.spDecrement
			self.loadCallerInstrs(self.returnAddrLocation)
		else:
			print(
				"  Instructions unreadable. Starting search for return address...")
			self.pushCount = self.spDecrement = None
			reg = lldb.SBMemoryRegionInfo()
			check(self.target.process.GetMemoryRegionInfo(self.sp, reg))
			# If nothing pushed, return address can be located @ sp
			for pretaddrl in range(self.sp, reg.GetRegionEnd(), ptrSize):
				self.count.words += 1
				call = self.loadCallerInstrs(pretaddrl)
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
			sys.stdout.write("  %d push, %d sub, prev pc @ %s\n" % (
				self.pushCount, self.spDecrement,
				xx(self.returnAddrLocation)))
		else:
			sys.stdout.write(
				"  Tried %d words, %d -> a section, %d readable, %d calls, %d destinations\n" % (
					self.count.words, self.count.pointers,
					self.count.readable, self.count.calls,
					self.count.destinations))
		for inn in self.callerInstrs:
			self.target.printInstruction(inn, True)
		return self.returnAddrLocation

	def loadCallerInstrs(self, pretaddrl):
		self.callerInstrs = []
		ra0 = self.target.check(self.sbp.ReadPointerFromMemory(
			pretaddrl, self.target.error))
		ra = lldb.SBAddress(ra0, self.sbt)
		if not ra.section.IsValid():
			# print("%s: %s no section" % (xx(pretaddrl), xx(ra0)))
			return
		self.count.pointers += 1
		if ra.section.file_size == 0:
			# print("%s: %s no image" % (xx(pretaddrl), xx(ra0)))
			return
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
		call = self.getCall(bytes, ra0)
		if call:
			cia = lldb.SBAddress(ra0 - len(call.ibs), self.sbt)
			self.callerInstrs = self.sbt.GetInstructions(cia, call.ibs)
		return call
		
	def getCall(self, bytes, end):
		class Call:
			def __init__(self, ibs):
				self.ibs = ibs
		if len(bytes) >= 5 and bytes[-5] == 0xe8:
			call = Call(bytes[-5:])
			call.destination = struct.unpack("i", bytes[-4:])[0] + end
			return call
		if bytes[-3] == 0xff:
			call = Call(bytes[-3:])
			call.destination = None
			return call
		print("  Unknown instr %x %x %x %x %x" % (
			bytes[-5], bytes[-4], bytes[-3], bytes[-2], bytes[-1]))
		return False

	def describeAddr(self, addr):
		off = addr.offset - addr.symbol.addr.offset
		desc = "Indescribable"
		if addr.symbol.IsValid():
			desc = "%s+%d" % ( addr.symbol.name, off)
		elif addr.section.IsValid():
			desc = "sect %s+%s" % (addr.section.name, xx(addr.offset))
			if ".module_image" == addr.section.name:
				desc += " (buildId=%s)" % getId(addr.module, self.args.long)
		elif addr.module.IsValid():
			desc = addr.module.name
		return desc
	
	def print(self):
		pc = lldb.SBAddress(self.pc, self.sbt)
		# sys.stdout.write("\u2666 %s: %s %s %s\n" % (
		sys.stdout.write("%s: %s %s %s\n" % (
			self.source, xx(self.pc), self.target.getName(pc.module),
			self.describeAddr(pc)))
		sys.stdout.flush()


class Target(Util):
	def __init__(self, args, debugger):
		self.args, self.debugger = args, debugger
		self.error = lldb.SBError()
		self.target = self.check(self.debugger.CreateTarget(
			"", "", "", True, self.error))
		# Hack: add mapping to nonexistent files so
		# ModuleList::GetSharedModule gets called first without a real
		# path and finds storage files in target.exec-search-paths
		if self.args.storage\
			and hasattr(self.target, "AppendImageSearchPath"):
			self.check(self.target.AppendImageSearchPath(
				"/Volumes", self.args.storage, self.error))
			self.check(self.target.AppendImageSearchPath(
				"/Applications", self.args.storage, self.error))
		if self.args.download:
			self.setVar("target.preload-symbols", "false")
			
	def load(self, path):
		self.path = path
		if self.args.storage:
			self.storagePath = os.path.abspath(self.args.storage)
		else:
			self.storagePath = os.path.dirname(os.path.abspath(self.path))
		self.verb("storage='%s'" % self.storagePath)
		dirs = [self.storagePath] +\
				[os.path.join(self.storagePath, x) for
					x in os.listdir(self.storagePath) if
					not x.startswith(".")]
		# TODO Check spaces in paths
		self.setVar("target.exec-search-paths", " ".join(dirs))
		self.verb("Loading '%s'..." % self.path)
		if sys.version_info[0] < 3:
			self.process = self.target.LoadCore(path)
		else:
			self.process = self.check(
				self.target.LoadCore(path, self.error))
		for m in self.target.modules:
			self.verb("Looking for symbols for '%s'...\n" % (
				m.file.fullpath))
			pdb = m.file.fullpath + ".pdb"
			if not os.path.isfile(pdb):
				self.verb("No symbol file '%s'" % pdb)
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
		self.process = self.check(self.target.Attach(
			lldb.SBAttachInfo(name, False), self.error))
		self.verb("DONE\n")
		return self

	def check(self, result):
		if self.error.fail:
			raise Exception(str(self.error))
		return result

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
		data = ii.GetData(self.target)
		bytes = self.check(
			data.ReadRawData(self.error, 0, ii.GetByteSize()))
		if needCode:
			for bv in bytes:
				ibs += "%02X " % bv
		comment = ii.GetComment(self.target)
		if comment:
			comment = " ; " + comment
		name = ii.GetMnemonic(self.target)
		ptr = ii.addr.GetLoadAddress(self.target)
		print("  %s %s%s %s%s" % (
			xx(ptr), ibs, name, ii.GetOperands(self.target), comment))
		if "callq" == name:
			call = CallSite.getCall(self, bytes, ptr + len(bytes))
			if call.destination:
				da = self.target.ResolveLoadAddress(call.destination)
				print("  => %s %s %s %s" % (
					xx(call.destination), self.getName(da.module),
					CallSite.describeAddr(self, da), da.section.name))
			
	def getFuncInstructions(self, f):
		# Doesn't work
		# insns = f.function.GetInstructions(self.target)
		# also: symbol.GetInstructions
		size = f.symbol.end_addr.GetOffset() - f.symbol.addr.GetOffset()
		fpos = f.symbol.IsValid() and\
			f.symbol.addr.GetLoadAddress(self.target)
		if not fpos or not size:
			return
		bytes = f.symbol.addr.section.GetSectionData().\
			ReadRawData(self.error, f.symbol.addr.offset, size)
		#bytes = self.process.ReadMemory(fpos, size, self.error)
		if self.error.fail:
			print("Error reading memory %s size=%s (%s:%s) = '%s'" % (
				xx(fpos), xx(size),
				f.symbol.addr.section.name,
				xx(f.symbol.addr.offset), self.error))
			return
		return self.target.GetInstructions(f.symbol.addr, bytes)

	def printWordsFromStack(self, n):
		if type(n) is int:
			t = self.process.GetThreadByIndexID(n)
			if not t.IsValid():
				raise Exception("No thread %d" % n)
		else:
			t = n
		self.printStackInfo(t)
		self.printRegs(t.frames[0], {})
		stack = lldb.SBMemoryRegionInfo()
		cs = CallSite(self).loadTopOfStack(t, stack)
		check(self.process.GetMemoryRegionInfo(cs.sp, stack))
		if self.args.threadm or self.args.threadX:
			self.doCmd("memory read --force -fA 0x%X 0x%X" % (
				sp, stack.GetRegionEnd()))
			return
		while cs:
			cs.print()
			cs = CallSite(self).loadReturnAddress(
				cs.getReturnAddrLoc(), stack)

	def printWordsFromStack0(self, n):
		if type(n) is int:
			t = self.process.GetThreadByIndexID(n)
			if not t.IsValid():
				raise Exception("No thread %d" % n)
		else:
			t = n
		self.printStackInfo(t)
		self.printRegs(t.frames[0], {})
		sp = t.frames[0].sp
		self.lastPos = sp - ptrSize
		self.prevPc = 0
		self.printWord(sp - ptrSize, "pc: ", t.frames[0].pc)
		reg = lldb.SBMemoryRegionInfo()
		check(self.process.GetMemoryRegionInfo(sp, reg))
		if self.args.threadm or self.args.threadX:
			self.doCmd("memory read --force -fA 0x%X 0x%X" % (
				sp, reg.GetRegionEnd()))
			return
		pos = sp
		while pos < reg.GetRegionEnd():
			self.printWordAt(pos, True)
			# To fix hang: move next pos calculation here
			if self.args.threadC:
				pos += ptrSize
			else:
				if self.prevPc == pos or self.prevPc == 0:
					pos += ptrSize
					continue
					# print("%X" % self.prevPc)
					# break
				pos = self.prevPc

	def printWordAt(self, pos, execOnly=False):
		p = self.process.ReadPointerFromMemory(pos, self.error)
		if self.error.fail:
			print("read pos=%X error='%s'" % (pos, self.error))
			return
		if execOnly:
			reg = lldb.SBMemoryRegionInfo()
			check(self.process.GetMemoryRegionInfo(p, reg))
			if not reg.IsExecutable():
				return
		if pos - self.lastPos > ptrSize:
			print("(%d words skipped)" % ((pos-self.lastPos)/ptrSize))
		self.printWord(pos, xx(pos) + ": ", p)
		self.lastPos = pos

	def printWord(self, pos, prefix, p):
		"""
		If we get SP from thread:
		Next frame PC is pointed by it at the start of function.
		If it's valid, we find the call before it.
		SP before that call = found PC address + ptrSize
		"""
		addr = lldb.SBAddress(p, self.target)
		sys.stdout.write("%s%s %s %s" % (
			prefix, xx(p), self.getName(addr.module),
			self.describeAddr(addr)))
		sys.stdout.flush()
		if self.args.base:
			for s in self.getPossibleSourceLines(addr, " at %s:%d"):
				sys.stdout.write(s)
				sys.stdout.flush()
				sys.stdout.write("\n")
		sys.stdout.write("\n")
		if addr.symbol.IsValid():
			insns = self.getFuncInstructions(addr)
			if insns:
				npush, sub = self.getPushCountAndStackDecrement(insns)
				for nn in range(insns.GetSize(), 0, -1):
					ii = insns.GetInstructionAtIndex(nn - 1)
					if ii.addr.offset > addr.offset:
						continue
					if nn > 2:
						self.printInstruction(
							insns.GetInstructionAtIndex(nn - 3))
					if nn > 1:
						self.printInstruction(
							insns.GetInstructionAtIndex(nn - 2))
					self.printInstruction(ii)
					break
				# The meaning is `sub` is subtracted from SP inside the
				# function. Lower SP values are closer to the top in the
				# output, so the arrow should poit upwards
				self.prevPc = pos+ptrSize+(npush*ptrSize)+sub
				print("  %d pushs + 0x%X SP\u2191, prev PC @ %s" % (
					npush, sub, xx(self.prevPc)))
				sys.stdout.flush()
		block = addr.block
		count = 0
		while 0 and block.IsValid():
			if block.GetInlinedCallSiteFile().IsValid():
				for p in self.getPossibleSourceLines2(
						block.GetInlinedCallSiteFile(),
						block.GetInlinedCallSiteLine(), "at %s:%d"):
					print("block %d: %s %s" % (
						count, block.GetInlinedName(), p))
			block = block.GetParent()
			count += 1
		# This only prints "loc='static'". How do i get real var locations?
		if 0:
			# arguments, locals, statics
			for v in block.GetVariables(self.target, True, True, False):
				print("'%s' loc='%s' v='%s' t=%s(%d)" % (
					v.name, v.location, v.value,
					v.type.name, v.type.size))
		sys.stdout.write("\n")
		
	def getPushCountAndStackDecrement(self, insns):	
		npush = sub = 0
		for ii in insns:
			mn = ii.GetMnemonic(self.target)
			if "pushq" == mn:
				npush += 1
			elif "subq" == mn:
				ops = ii.GetOperands(self.target).split(", %rsp")
				if len(ops) == 2:
					if sub:
						sys.stdout.write(
							"Extra sub SP instruction (1st sub=%X): " % sub)
						self.printInstruction(ii)
					elif not ops[0].startswith("$"):
						sys.stdout.write("Non-constant sub SP: ")
						self.printInstruction(ii)
						continue
					sub += int(ops[0][1:], base=0)
		return npush, sub

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

	def printRegions(self):
		regions = self.process.GetMemoryRegions()
		r = lldb.SBMemoryRegionInfo()
		for i in range(regions.GetSize()):
			if not regions.GetMemoryRegionAtIndex(i, r):
				raise Exception("TODO")
			name = r.GetName()
			if name:
				name = os.path.basename(name)
			print("%s %s%s%s%s %016X +%X %s" % (
				os.path.basename(self.path),
				(r.IsReadable() and "r" or "."),
				(r.IsWritable() and "w" or "."),
				(r.IsExecutable() and "x" or "."),
				(r.IsMapped() and "m" or "."),
				r.GetRegionBase(), r.GetRegionEnd() - r.GetRegionBase(),
				name))

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
			new = self.target.AddModule(path, None, None, None)
			if not new:
				raise Exception("%s not added" % path)
			if new.uuid != m.uuid:
				self.verb("Skipping %s (%s) for '%s'\n" % (
					new.file.fullpath, new.uuid, m.file.basename))
				self.target.RemoveModule(new)
				continue
			if m.num_sections != new.num_sections:
				self.verb(
					"Module %s: num_sections differ,\n%d in %s\n%d in %s" % (
						m.uuid, m.num_sections, m.file.fullpath,
						new.num_sections, new.file.fullpath))
				self.target.RemoveModule(new)
				continue
			for i in range(m.num_sections):
				check(self.target.SetSectionLoadAddress(
					new.sections[i],
					m.sections[i].GetLoadAddress(self.target)))
			self.target.RemoveModule(m)
			return 
		msg = ("'%s' (%s) not in storage" % (
			m.file.fullpath, m.uuid))
		if self.args.unchecked:
			self.verb(msg)
		else:
			raise Exception(msg)

	def fixModulesNotInStorage(self):
		# some modules get removed
		for m in self.target.modules[:]:
			if m.file.fullpath.startswith(self.args.storage):
				continue
			if m.file.fullpath.startswith("/Volumes"):
				self.replaceModuleFromStorage(m)
			if m.file.fullpath.startswith("/Applications"):
				self.replaceModuleFromStorage(m)

	def printModules(self, tool):
		count = Count()
		mtime = time.localtime(os.path.getmtime(self.path))
		if self.args.modules:
			print("\
nsect, all sections size on disk, id, load addr, name, symfile")
		for m in self.target.modules:
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
				if fsize:
					def printSec(prefix, sec):
						print("%s%s" % (prefix, sec.name))
						for i in range(sec.GetNumSubSections()):
							printSec(prefix + " ", sec.GetSubSectionAtIndex(i))
					for sec in m.sections:
						printSec("  ", sec)
		if self.args.stat:
			if not hasattr(tool, "statHeaderPrinted"):
				print(" modules: total, system, store, other, absent")
				tool.statHeaderPrinted = True
			print(
				self.getTime() + "%3d %3d %3d %3d %3d %11s %11s %s '%s'" % (
					self.target.GetNumModules(),
					count.system, count.store, count.other, 
					count.absent, cut(self.path, 8),
					cut(self.target.executable.basename, 8),
					self.process.selected_thread.frames[0].addr,
					self.process.selected_thread.GetStopDescription(80)))

	def getSomeLoadAddress(self, m):
		for s in m.sections:
			if s.GetLoadAddress(self.target) != 0xFFFFFFFFFFFFFFFF:
				break
		return s.GetLoadAddress(self.target)

	def getTime(self):
		mtime = time.localtime(os.path.getmtime(self.path))
		return time.strftime("%Y-%m-%d %H:%M| ", mtime)

	def queueDownloadSymbols(self, server):
		if not self.args.storage:
			raise Exception("Can't download without storage dir")
		work = []
		for m in self.target.modules:
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
				if 0 and self.args.storage:
					t.fixModulesNotInStorage()
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
			for mo in t.target.modules:
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
		elif self.args.thread or self.args.threadX:
			t.printWordsFromStack(t.process.selected_thread)
		elif self.args.threads:
			t.printStacks()
		elif self.args.bt:
			t.doCmd("bt")
		elif self.args.threadf:
			t.printDecodedFrames(t.process.selected_thread)
		elif self.args.modules or self.args.absent:
			t.printModules(self)
		elif not self.args.stat:
			t.printRegions()
		if not (self.args.modules or self.args.absent):
			if self.args.stat:
			   	t.printModules(self)

if __name__ == "__main__":
	# This makes my Mac (standard LLDB package) segfault 
	if 0 and sys.version_info[0] < 3:
		import codecs
		sys.stdout = codecs.getwriter("utf-8")(sys.stdout)
	Tool(parser.parse_args(), None).run()
