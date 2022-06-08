#!/usr/bin/env python3
"""Trace function calls & print stacks

Tracepoint syntax:

(NAME_GLOB*[>TARGET]|~NAME|0x<addr>)[@FILTER[@...]][#COMMAND[#...]]

NAME_GLOB*: BP on every symbol with full name matching NAME_GLOB*
 (nb: full name in C++ has `(arg list)` at the end)
>TARGET: Set BPs an all `call` instructions to this target inside 
 NAME_GLOB* functions instead of function entry
~NAME: Use debugger API that sets BP by name
@FILTER: Only trace when function FILTER is in the stack
#COMMAND: Run debugger command on each trace. 
 If command contains parens (or -p option is on), it's a python script.
 For available calls & vars see source

Examples:
trace.py\
 'RTFTagWriter::*ElementImpl*#icu($$rsi)'\
 '~RTFStreamWriter::OpenBlock#"OB %s" % levelIn(1)'\
 '~RTFStreamWriter::CloseBlock#"CB %s" % levelOut(1)'\
 $(pidof b-kodwebd) -v -o /win/kodeks/rtf2.logc -p -s2

Print arg 1 of startElementImpl and endElementImpl as ICU UnicodeStrings.
When OpenBlock/CloseBlock are called, count and print current block depth.
Limit stack printout to 2 frames, duplicate output to /win/kodeks/rtf2.logc,
print paths relative to /win/kodeks.

Bugs:
 Call stack is printed with most immediate function at the bottom, 
 instead of at the top like debuggers do...

"""
from __future__ import print_function
import argparse, re, sys, os, subprocess, json, fnmatch, struct
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

psize = 8

def check(error):
	if error.fail:
		raise Exception(str(error))

def rightLimited(s, size):
	if len(s) < size - 3:
		return s
	return "..." + s[-size:]

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

def callProcessHandleBp2(frame, bp_loc, dict):
	process = frame.GetThread().GetProcess()
	print(" addr=%s=%x sp=%X" % (frame.addr, frame.pc, frame.sp))
	Process.objects[process.id].handleBreakpoint(frame, bp_loc)

def callProcessHandleBp(frame, bp_loc, dict):
	process = frame.GetThread().GetProcess()
	error = lldb.SBError()
	args = [
		frame.reg[n].GetValueAsUnsigned() for n in [
			"rdi", "rsi", "rdx", "rcx"]]
	print(" addr=%s=%x sp=%X args=%s" % (
		frame.addr, frame.pc, frame.sp, ["%X" % t for t in args]))
	hexDumpMem(process, args[1], args[1] + args[2], error)

class Util:
	def check(self, result):
		if self.error.fail:
			raise Exception(str(self.error))
		return result

class TracePoint(Util):
	instancesById = {}

	def __init__(self):
		self.count = 0
		self.debuggerBps = []

	def getId(self):
		if hasattr(self, "id"):
			return self.id
		if self.symbolName:
			for c in reversed(self.symbolName):
				if c in self.instancesById:
					continue
				self.setId(c)
				return c
		self.id = "!"
		return self.id

	def setId(self, c):
		self.id = c
		self.instancesById[c] = self
		return self

	def removeInvalidFunctions(self, ff):
		result = []
		for i in range(len(ff)):
			if ff[i].symbol.name == None:
				continue
			print("name=%s" % ff[i].symbol.name)
			result += [ff[i]]
		return result
	
	def getFunc(self, name, target):
		# TODO
		# FF returns imprecise matches
		ff = target.FindFunctions(name)
		if len(ff) == 0:
			return None
		if len(ff) != 1:
			ff = self.removeInvalidFunctions(ff)
		if len(ff) == 0:
			return None
		if len(ff) != 1:
			raise Exception("%d functions" % len(ff))
		if not ff[0].IsValid():
			raise Exception("not ff[0].IsValid()")
		if not ff[0].symbol.IsValid():
			raise Exception("not ff[0].symbol.IsValid()")
		print("name=%s addr=%X fa=%X modname=%s" % (
			ff[0].symbol.name, ff[0].symbol.addr.GetLoadAddress(target),
			ff[0].symbol.addr.offset, ff[0].symbol.addr.module))
		if not ff[0].symbol.addr.IsValid():
			raise Exception("not ff[0].symbol.addr.IsValid()")
		return ff[0].symbol

	def getAddrOf(self, name, target):
		# load_addr doesn't work bc target is not "current"
		f = self.getFunc(name, target)
		if not f:
			raise Exception("No function '%s'" % name)
		return f.addr.GetLoadAddress(target)

	def getAddrs(self, target, process):
		if self.addr:
			return [self.addr]
		if self.nameIsFull:
			if "*" in self.symbolName:
				addrs = []
				for m in target.modules:
					for s in m:
						if not s.name:
							continue
						if fnmatch.fnmatch(s.name, self.symbolName):
							addrs.append(s.addr.GetLoadAddress(target))
				return addrs
			return [self.getAddrOf(self.symbolName, target)]
		# `None` means set BP by name 
		return [None]

	def filterAccepts(self, frame, toolProc):
		return True

class Context:
	def __init__(self):
		self.levels = {}
		self.a = 0

GlobalContext = Context()

class NamedTracePoint(TracePoint):
	def parse(self, name, addr=None):
		self.name = name
		self.addr = addr
		self.symbolName = None
		self.commands = []
		self.filters = []
		self.calls = None
		self.stackEnabled = True
		parts = name.split("#")
		if len(parts) > 1:
			name = parts[0]
			self.commands = [x.strip() for x in parts[1:]]
			if self.commands[0] == "":
				self.stackEnabled = False
				self.commands = self.commands[1:]
		parts = name.split("@")
		if len(parts) > 1:
			name = parts[0]
			self.filters = parts[1:]
		if name.startswith("0x"):
			self.addr = int(name, 16)
			return self
		self.nameIsFull = not name.startswith("~")
		if not self.nameIsFull:
			name = name[1:]
		parts = name.split(">")
		if len(parts) > 1:
			if not self.nameIsFull:
				raise Exception("No calls in BreakpointCreateByName")
			name = parts[0]
			self.calls = parts[1:]
		self.symbolName = name
		return self

	def getAddrs(self, target, process):
		if self.addr:
			return [self.addr]
		if not self.nameIsFull:
			return [None]
		func = self.getFunc(self.symbolName, target)
		if not self.calls:
			return TracePoint.getAddrs(self, target, process)
		addrs = []
		availableCalls = set()
		instructions = func.GetInstructions(target)
		for ins in instructions:
			if ins.GetMnemonic(target) == "callq" and\
			   (not "%" in ins.GetOperands(target)):
				p = int(ins.GetOperands(target), 16)
				arg = lldb.SBAddress(p, target)
				cmt = arg.GetSymbol()
				cmt = cmt and cmt.name
				for template in self.calls:
					if fnmatch.fnmatch(cmt, template):
						addrs.append(ins.GetAddress().GetLoadAddress(target))
				availableCalls.add(cmt)
			else:
				cmt = ins.GetComment(target)
			# print("%8s %s ; %s" % (
			# 	ins.GetMnemonic(target), ins.GetOperands(target), cmt))
		if not addrs:
			for name in availableCalls:
				print(" available: '%s'" % name)
			raise Exception("Calls %s not found in %s" % (
				self.calls, func.name))
		return addrs

	def copy(self, other):
		self.addr = other.addr
		self.commands = other.commands
		self.filters = other.filters
		self.nameIsFull = other.nameIsFull
		self.symbolName = other.symbolName
		return self

	def substCommand(self, frame, cmd):
		"'memory read $rxx' is broken if DWARF is broken"
		def getReg(match):
			return "0x%x" % (
				frame.reg[match.group(1)].GetValueAsUnsigned())
		return re.sub(r"\$\$([a-z]{3})", getReg, cmd)

	def runScript(self, frame, cmd):
		error = lldb.SBError()
		def getMemory(start, size):
			s = frame.thread.process.ReadMemory(start, size, error)
			if error.fail:
				raise Exception("%s size=%d" % (error, size))
			return s
		def xd(start, size):
			hexDumpMem(frame.thread.process, start, start+size, error)
			check(error)
		def vi0c(start):
			ptr, length = struct.unpack("Pxxxxi", getMemory(start, 16))
			# print("ptr=%X length=%d" % (ptr, length))
			if length == 0:
				return []
			return struct.unpack("i" * length, getMemory(ptr, length * 4))
		def vi(format, start):
			return v(format, "i", start)
		def v(format, fc2, start):
			format = format.replace("8", "x"*8)
			ptr, length = struct.unpack(
				format, getMemory(start, struct.calcsize(format)))
			if format.index("P") > format.index("i"):
				ptr, length = length, ptr
			if length == 0:
				return ()
			f2 = fc2 * length
			return struct.unpack(f2, getMemory(ptr, struct.calcsize(f2)))
		def icu(ptr):
			buf = getMemory(ptr, 32)
			flags, length, start = struct.unpack("HxxxxxxixxxxP", buf[8:])
			if flags & 2:
				return bytes(buf[10:(10+(flags>>4))]).decode("utf-16")
			return bytes(getMemory(start, (length - 1) * 2)).decode("utf-16")
		def levelIn(tag):
			GlobalContext.levels[tag] = GlobalContext.levels.get(tag, 0) + 1
			return "%s %d" % (tag, GlobalContext.levels[tag])
		def levelOut(tag):
			GlobalContext.levels[tag] = GlobalContext.levels.get(tag, 0) - 1
			return "%s %d" % (tag, GlobalContext.levels[tag])
		def output(str):
			if not hasattr(GlobalContext, "output"):
				GlobalContext.output = open("t-out.txt", "w")
			GlobalContext.output.write(str)
			return "%d characters written" % len(str)
		def level(tag):
			return GlobalContext.levels.get(tag, 0)
		r = eval(cmd, {}, dict(
			f=frame, p=frame.thread.process, e=error, z=print,
			m=getMemory, o=output,
			g=GlobalContext,
			x=xd,
			vi=vi, vi0c=vi0c, v=v,
			icu=icu,
			levelIn=levelIn, levelOut=levelOut, level=level))
		return r

	def filterAccepts(self, frame, toolProc):
		if 1:
			v = toolProc.fltMap.get(frame.thread.id, [])
			for filter in self.filters:
				if filter not in v:
					return False
			return True
		for filter in self.filters:
			for f in frame.thread.frames:
				if f.addr.symbol.name and\
				   fnmatch.fnmatch(f.addr.symbol.name, filter) or\
				   f.module.file.basename and\
				   fnmatch.fnmatch(f.module.file.basename, filter):
					return True
		return not self.filters

	def trace2(self, frame, toolProc):
		self.count += 1
		if self.stackEnabled:
			toolProc.printStack(frame)
		if self.commands:
			toolProc.process.SetSelectedThread(frame.thread)
			for cmd in self.commands:
				c2 = self.substCommand(frame, cmd)
				toolProc.write("%s%d %s= " % (
					self.id, self.count, rightLimited(c2, 40)))
				if toolProc.options.python or re.match(".*([(]|[+]=)", c2):
					r = self.runScript(frame, c2)
					toolProc.print("%s" % r)
				else:
					toolProc.debugger.HandleCommand(c2)
					toolProc.writeToLog("TODO Copy command output here\n")
		else:
			toolProc.print("trace '%s'" % self.symbolName)

class FilterTracePoint(NamedTracePoint):
	def parse(self, name, addr=None):
		NamedTracePoint.parse(self, name, addr)
		parts = self.symbolName.split("-", 1)
		self.symbolName = parts[0]
		self.condition = len(parts) > 1 and parts[1]
		return self
	
	def trace2(self, frame, toolProc):
		if self.condition:
			if not self.runScript(
					frame, self.substCommand(frame, self.condition)):
				return
		v = toolProc.fltMap.get(frame.thread.id, [])
		v.append(self.name)
		toolProc.fltMap[frame.thread.id] = v
		toolProc.addTask(frame.sp + psize, self)
		toolProc.updateBreakpoints()
		frame.thread.StepOut()

	def runDeferredTask(self, toolProc, frame):
		v = toolProc.fltMap.get(frame.thread.id, [])
		if v[-1] == self.name:
			v = v[:-1]
			toolProc.fltMap[frame.thread.id] = v
			toolProc.updateBreakpoints()
		else:
			print("Warning: out of '%s' but last filter is '%s'" % (
				self.name, v[-1]))

class RetTracePoint(NamedTracePoint):
	def trace2(self, frame, toolProc):
		print("Adding task to %X" % (frame.sp + psize))
		toolProc.addTask(frame.sp + psize, self)
		frame.thread.StepOut()

	def runDeferredTask(self, toolProc, frame):
		NamedTracePoint.trace2(self, frame, toolProc)
	

class SSLWriteTrace(TracePoint):
	def getAddrs(self, target, process):
		return [self.getAddrOf("SSLWrite", target) + 254]

	def trace(self, frame, process, error):
		buf = frame.reg["r12"].GetValueAsUnsigned()
		size = frame.reg["r15"].GetValueAsUnsigned()
		print("write %d bytes:" % size)
		hexDumpMem(process, buf, buf + size, error)


class SSLReadTrace(TracePoint):
	def getAddrs(self, target, process):
		return [self.getAddrOf("SSLRead", target) + 613]

	def trace(self, frame, process, error):
		# pointer to resulting number of bytes is in arg3=rcx at start
		rbp = frame.reg["rbp"].GetValueAsUnsigned()
		buf = process.ReadPointerFromMemory(rbp - 0x58, error)
		if error.fail:
			raise Exception(str(error))
		psize = process.ReadPointerFromMemory(rbp - 0x50, error)
		if error.fail:
			raise Exception(str(error))
		size = process.ReadPointerFromMemory(psize, error)
		if error.fail:
			raise Exception(str(error))
		print("read %d bytes:" % size)
		hexDumpMem(process, buf, buf + size, error)

class NSEvent(Util):
	types = dict(
		NSEventTypeLeftMouseDown			 = 1,
		NSEventTypeLeftMouseUp				 = 2,
		NSEventTypeRightMouseDown			 = 3,
		NSEventTypeRightMouseUp				 = 4,
		NSEventTypeMouseMoved				 = 5,
		NSEventTypeLeftMouseDragged			 = 6,
		NSEventTypeRightMouseDragged		 = 7,
		NSEventTypeMouseEntered				 = 8,
		NSEventTypeMouseExited				 = 9,
		NSEventTypeKeyDown					 = 10,
		NSEventTypeKeyUp					 = 11,
		NSEventTypeFlagsChanged				 = 12,
		NSEventTypeAppKitDefined			 = 13,
		NSEventTypeSystemDefined			 = 14,
		NSEventTypeApplicationDefined		 = 15,
		NSEventTypePeriodic					 = 16,
		NSEventTypeCursorUpdate				 = 17,
		NSEventTypeScrollWheel				 = 22,
		NSEventTypeTabletPoint				 = 23,
		NSEventTypeTabletProximity			 = 24,
		NSEventTypeOtherMouseDown			 = 25,
		NSEventTypeOtherMouseUp				 = 26,
		NSEventTypeOtherMouseDragged		 = 27,
		NSEventTypeGesture		  = 29,
		NSEventTypeMagnify		  = 30,
		NSEventTypeSwipe		  = 31,
		NSEventTypeRotate		  = 18,
		NSEventTypeBeginGesture	  = 19,
		NSEventTypeEndGesture	  = 20,
		NSEventTypeSmartMagnify	 = 32,
		NSEventTypeQuickLook  = 33,
		NSEventTypePressure	 = 34,
		NSEventTypeDirectTouch	= 37)

	rtypes = {v: k for k, v in types.items()}

	def __init__(self, addr, process):
		self.error = lldb.SBError()
		mem = self.check(process.ReadMemory(addr, 0x20, self.error))
		_, self.type, self.x, self.y = struct.unpack("QQdd", mem)

	def getTypeName(self):
		return self.rtypes.get(self.type, "type%d" % self.type)

class HandleEventCall:
	def __init__(self, frame):
		self.name = frame.addr.symbol.name
		self.pself = frame.reg["rdi"].GetValueAsUnsigned()
		self.pev = frame.reg["rdx"].GetValueAsUnsigned()
		self.ev = NSEvent(self.pev, frame.thread.process)

	def runDeferredTask(self, toolProc, frame):
		r = frame.reg["rax"].GetValueAsUnsigned()
		print("\r x=%d y=%d r=%X %s %s" % (
			self.ev.x, self.ev.y, r, self.ev.getTypeName(), self.name))

class HandleEventTrace(TracePoint):
	def __init__(self, addr):
		self.addr = addr
		self.error = lldb.SBError()

	def trace2(self, frame, toolProc):
		call = HandleEventCall(frame)
		toolProc.addTask(frame.sp + psize, call)
		frame.thread.StepOut()
		

class Count:
	def __init__(self):
		self.stopped = 0

class Process(Util):
	objects = {}
	
	def __init__(self, options):
		self.options = options
		self.debugger = lldb.SBDebugger.Create()
		self.error = lldb.SBError()
		self.breakpoints = {}
		self.lastPrintedStack = []
		self.stacksEnabled = True
		self.printImage = False
		self.count = Count()
		if self.options.verbose:
			if not self.debugger.EnableLog("lldb", ["dyld", "target"]):
				raise Exception("Bad log")
		self.tasksBySp = {}
		self.fltMap = {}
		self.filterNames = set()
		self.output = None
		if self.options.output:
			self.output = open(self.options.output, "w")
			self.output.write(" -*- mode: compilation -*-\n")

	def write(self, msg):
		sys.stdout.write(msg)
		self.writeToLog(msg)

	def writeToLog(self, msg):
		if self.output:
			self.output.write(msg)
			self.output.flush()

	def print(self, msg):
		self.write(msg + "\n")

	def addTask(self, sp, task):
		if 0 and sp in self.tasksBySp:
			raise Exception("%X already here!" % sp)
		self.tasksBySp[sp] = task

	def load(self, pid=None, launch=None):
		self.target = self.check(self.debugger.CreateTarget(
			launch and launch[0] or "", "", "", True, self.error))
		if launch:
			sys.stderr.write("Launching %s..." % launch)
			self.process = self.check(self.target.Launch(
				self.debugger.GetListener(),
				launch[1:],
				None, None, None, None, os.getcwd(),
				0, True, self.error));
		elif re.match(r"\d+", pid):
			ai = lldb.SBAttachInfo(int(pid))
			sys.stderr.write("Attaching pid=%d..." % ai.GetProcessID())
		else:
			ai = lldb.SBAttachInfo(pid, self.options.wait)
			sys.stderr.write("Attaching name='%s'..." % pid)
		if not launch:
			self.process = self.check(self.target.Attach(ai, self.error))
		sys.stderr.write("Done\n")
		Process.objects[self.process.id] = self
		return self

	def unload(self):
		sys.stderr.write("Detaching %s..." % self.process)
		self.error = self.process.Detach()
		if not self.error.success:
			msg = str(self.error)
			if msg != "error: Sending disconnect packet failed.":
				raise Exception(str(self.error))
		self.debugger.DeleteTarget(self.target)
		sys.stderr.write("Done\n")

	def printStack(self, frame):
		if not self.stacksEnabled:
			return
		skipStart = None
		if self.options.slen:
			start = max(
				frame.thread.GetNumFrames() - int(self.options.slen), 0)
		else:
			start = 0
		for i in range(start, frame.thread.GetNumFrames()):
			idx = frame.thread.GetNumFrames() - i - 1
			f = frame.thread.frames[idx]
			if i + 1 < len(self.lastPrintedStack) and\
			   f.addr == self.lastPrintedStack[i].addr and\
			   idx > 0 and\
			   frame.thread.frames[idx - 1].addr ==\
			   self.lastPrintedStack[i + 1].addr:
				skipStart = skipStart or f
				continue
			if skipStart:
				head = "%d-%d" % (skipStart.idx, f.idx)
				skipStart = None
			else:
				head = "%d" % f.idx
			sl = self.getSourceLine(f, " at %s:%d")
			name = f.addr.symbol.name
			if sl and name:
				name = name.split("(")[0]
			sys.stderr.write("\r")
			self.print("%7s %16x %s%s" % (
				head, f.addr.GetLoadAddress(self.target),
				self.printImage and (f.module.file.basename + " ") or "",
				name) + sl)
		self.lastPrintedStack = frame.thread.frames[::-1]

	def getSourceLine(self, f, template):
		if not f.line_entry.IsValid():
			return ""
		cwd = (
			self.options.output and os.path.dirname(self.options.output) or
			os.getcwd()).split(os.sep)[-1]
		parts = f.line_entry.file.fullpath.split(os.sep)
		try:
			path = os.sep.join(parts[parts.index(cwd) + 1:])
		except ValueError:
			path = f.line_entry.file.fullpath
		return template % (path, f.line_entry.line)
			
	def handleBreakpoint(self, frame, bp_loc):
		tr = self.breakpoints.get(frame.pc)
		if 0 and tr is None and bp_loc is None:
			print("stopped in '%s'" % frame.name)
		try:
			tr = tr or self.breakpoints[frame.name]
		except KeyError:
			return False
		if tr.filterAccepts(frame, self):
			if hasattr(tr, "trace2"):
				tr.trace2(frame, self)
			else:
				self.printStack(frame)
				tr.trace(frame, self.process, self.error)
		return True

	def traceSsl(self):
		if 0:
			b2 = self.target.BreakpointCreateByName("SSLWrite")
			b2.SetScriptCallbackFunction("callProcessHandleBp")
			for c in [b, b2]:
				print("Breakpoint %d:" % c.id)
				for loc in c:
					print(" Addr=%x" % loc.GetLoadAddress())
		self.setBp(SSLReadTrace())
		self.setBp(SSLWriteTrace())
		self.runTrace()

	def updateBreakpoints(self):
		activeFilters = []
		for v in self.fltMap.values():
			activeFilters += v
		for t in self.breakpoints.values():
			active = True
			for f in t.filters:
				if not f in activeFilters:
					active = False
			for dbp in t.debuggerBps:
				if dbp.IsEnabled() and not active:
					print("Disabling '%s'" % t.name)
					dbp.SetEnabled(False)
				if active and not dbp.IsEnabled():
					print("Enabling '%s'" % t.name)
					dbp.SetEnabled(True)

	def setBp(self, t):
		addrs = t.getAddrs(self.target, self.process)
		for addr in addrs:
			self.addBpForAddr(t, addr)

	def addBpForAddr(self, t, addr):
		id = t.getId()
		if addr:
			self.breakpoints[addr] = t
			self.print("Setting bp '%s' to %X" % (t.id, addr))
			b = self.target.BreakpointCreateByAddress(addr)
		else:
			self.breakpoints[t.symbolName] = t
			self.print("Setting bp to '%s'" % t.symbolName)
			b = self.target.BreakpointCreateByName(t.symbolName)
		if b.num_locations == 0:
			raise Exception("No locations for BP %s" % b)
		for i in range(b.num_locations):
			loc = b.GetLocationAtIndex(i)
			self.print("Location %s" % loc)
			self.breakpoints[loc.GetLoadAddress()] = t
		# Does not get called on Linux
		b.SetScriptCallbackFunction("callProcessHandleBp2")
		t.debuggerBps.append(b)
		if 1:
			for f in t.filters:
				if not f in self.filterNames:
					self.setBp(FilterTracePoint().parse(f))
					self.filterNames.add(f)

# /// Thread stop reasons.
# enum StopReason {
#  eStopReasonInvalid = 0,
#  eStopReasonNone,
#  eStopReasonTrace,
#  eStopReasonBreakpoint,
#  eStopReasonWatchpoint,
#  eStopReasonSignal,
#  eStopReasonException,
#  eStopReasonExec, ///< Program was re-exec'ed
#  eStopReasonPlanComplete,
#  eStopReasonThreadExiting,
#  eStopReasonInstrumentation
#};

	def getBpFrame(self, ev):
		# What didn't work:
		# frame = self.process.selected_thread.GetFrameAtIndex(0)
		# frame = lldb.SBThread.GetStackFrameFromEvent(ev)
		# frame = lldb.SBThread.GetThreadFromEvent(ev).GetFrameAtIndex(0)
		#
		# This hangs on Linux
		# for t in self.process.thread:
		for tn in range(self.process.GetNumThreads()):
			t = self.process.GetThreadAtIndex(tn)
			# This worked on Linux:
			# if not t:
			if t is None:
				print("Thread %d is '%s'" % (tn, t))
				continue
			# print("tid=%d reason=%s" % (t.id, t.GetStopReason()))
			# Worked on Linux
			if t.GetStopReason() == lldb.eStopReasonBreakpoint:
				return t.GetFrameAtIndex(0)
			# Should work on Mac...
			if 0 and t.GetStopReason() == lldb.eStopReasonSignal:
				return t.GetFrameAtIndex(0)
		return None

	def runTrace(self):
		if len(self.breakpoints) == 0:
			raise Exception("No breakpoints set!")
		self.updateBreakpoints()
		self.listener = self.debugger.GetListener()
		self.process.GetBroadcaster().AddListener(
			self.listener,
			lldb.SBProcess.eBroadcastBitStateChanged |
			lldb.SBProcess.eBroadcastBitInterrupt)
		self.error = self.process.Continue()
		if not self.error.success:
			raise Exception(str(self.error))
		ev = lldb.SBEvent()
		while True:
			sys.stderr.write("\rWaiting (stopped=%d)..." % (
				self.count.stopped))
			# timeout to catch SIGINT 
			while not self.listener.WaitForEvent(1, ev):
				pass
			state = lldb.SBProcess.GetStateFromEvent(ev)
			if state == lldb.eStateStopped:
				self.count.stopped += 1
				for tn in range(self.process.GetNumThreads()):
					t = self.process.GetThreadAtIndex(tn)
					frame = t.GetFrameAtIndex(0)
					if frame.sp in self.tasksBySp:
						self.tasksBySp[frame.sp].runDeferredTask(self, frame)
						del self.tasksBySp[frame.sp]
						tn = -1
						break
				# On Mac handleBreakpoint is called by attached script
				# (not on Linux) 
				if tn != -1 and sys.platform != "darwin":
					tn = -1
					frame = self.getBpFrame(ev)
					if not frame or not self.handleBreakpoint(frame, None):
						print("Bad stop frame='%s'" % frame)
				self.process.Continue()
			elif state == lldb.eStateRunning:
				pass
			elif state == lldb.eStateExited:
				sys.stderr.write("exited...")
				break
			else:
				sys.stderr.write(
					"event=%s\n" % lldb.SBDebugger.StateAsCString(state))

	def dumpThreads(self):
		for tn in range(self.process.GetNumThreads()):
			t = self.process.GetThreadAtIndex(tn)
			print("tid=%d reason=%d '%s'" % (t.id, t.GetStopReason(), t))

	def breakAtEveryEntryPointOfModule(self, name):
		m = self.target.module[name]
		if not m:
			raise Exception("No module '%s'" % name)
		for s in m:
			if s.external:
				self.setBp(NamedTracePoint(
					s.name, s.addr.GetLoadAddress(self.target)))
			
	def listSymbols(self, includeNonDynamic):
		for m in self.target.modules:
			for s in m:
				if includeNonDynamic or s.external:
					print("%s %s %s" % (
						m.file.fullpath, s.name, s.addr))

	def setHandleEventBreakpoints(self):
		for m in self.target.modules:
			for s in m:
				if s.name.endswith("handleEvent:]"):
					self.setBp(
						HandleEventTrace(s.addr.GetLoadAddress(self.target)))

	def inspect(self, tid):
		print("process=%s" % self.process)
		tmp = [t for t in self.process.threads if t.id == tid]
		if len(tmp) != 1:
			raise Exception("Threads: %s" % [
				t.id for t in self.process.threads])
		th = tmp[0]
		for f in th.frames:
			print(" %s %s" % (f.module.file.fullpath, f))

# sudo -S <- read password from stdin

class Tool:
	def __init__(self, options):
		self.options = options

	def run(self):
		if self.options.tid:
			tid = int(self.options.tid)
		if self.options.with_dtrace:
			return self.collectProcesses()
		pid = self.options.PID
		functions = self.options.FUNCTION
		launch = self.options.launch and self.options.launch.split(" ")
		if "@@" in functions:
			i = functions.index("@@")
			launch = functions[:i]
			functions = functions[i+1:]
		elif "@" in functions:
			i = functions.index("@")
			launch = functions[i + 1:]
			functions = functions[:i]
		if functions and not launch:
			pid = functions[-1]
			functions = functions[:-1]
		if not (pid or launch):
			sys.stderr.write("Need PID or command\n")
			sys.exit(1)
		process = Process(self.options).load(pid, launch)
		try:
			if self.options.tid:
				try:
					process.inspect(tid)
				except Exception:
					print("exception in inspect: %s" % sys.exc_info()[1])
					self.traceAll(process, functions)
			elif self.options.list:
				process.listSymbols(False)
			elif self.options.list2:
				process.listSymbols(True)
			else:
				self.traceAll(process, functions)
		finally:
			process.unload()

	def traceAll(self, process, functions):
		if self.options.ssl:
			return process.traceSsl()
		idChar = "a"
		for expr in functions:
			if expr.endswith(".dylib"):
				process.breakAtEveryEntryPointOfModule(expr)
			else:
				if expr.startswith("/"):
					point = RetTracePoint().parse(expr[1:])
				else:
					point = NamedTracePoint().parse(expr)
				# Need to set id here so predictable order exists:
				# arg1 = "a" arg2 = "b" etc.
				if point.addr:
					point.setId(idChar)
					idChar = chr(ord(idChar) + 1)
				if 0 and point.symbolName and "*" in point.symbolName:
					for m in process.target.modules:
						for s in m:
							if s.name and fnmatch.fnmatch(
									s.name, point.symbolName):
								p2 = point.__class__().copy(point)
								p2.symbolName = s.name
								p2.addr = s.addr.GetLoadAddress(
									process.target)
								process.setBp(p2)
				else:
					process.setBp(point)
		if self.options.events:
			process.setHandleEventBreakpoints()
		process.runTrace()

	def collectProcesses(self):
		command = [
			"sudo", # "-S",
			os.path.join(os.path.dirname(__file__), "collecttcp.d"),
			"-DPRINT=1", "-DSTOP=\"%s\"" % self.options.with_dtrace]
		print("Running %s..." % json.dumps(" ".join(command)))
		p = subprocess.Popen(
			command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		while p:
			line = p.stdout.readline()
			if not line:
				break
			sys.stderr.write("dtrace: %s" % line)
			m = re.match(r"thread (\d+) (\d+)", line)
			if m:
				q = Process(self.options).load(m.group(1))
				q.inspect(int(m.group(2)))
				q.unload()
		

parser = argparse.ArgumentParser(
	description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument(
	"-l", "--list", action="store_true", help="List symbols in libs")
parser.add_argument(
	"-m", "--list2", action="store_true", help="List all symbols")
parser.add_argument(
	"-t", "--tid", help="Inspect thread TID")
parser.add_argument(
	"-d", "--with-dtrace",
	help="Use collecttcp.d with STOP set to WITH_DTRACE")
parser.add_argument(
	"-S", "--ssl", action="store_true", help="Trace SSL reads & writes")
parser.add_argument(
	"-r", "--launch", help="Launch command line with spaces")
parser.add_argument(
	"--events", action="store_true",
	help="Trace handleEvent methods in every class and parse NSEvent structs")
parser.add_argument(
	"--output", "-o", help="Text output path")
parser.add_argument(
	"--python", "-p", action="store_true", help="Only python commands")
parser.add_argument(
	"--slen", "-s", help="Stack limit")
parser.add_argument(
	"--wait", "-w", action="store_true", help="Wait if process doesn't exist")
#parser.add_argument(
#	"--nolib", action="store_true",
#	help="Set BPs in main executable only")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("FUNCTION", nargs="*")
parser.add_argument("PID", nargs="?")
Tool(parser.parse_args()).run()
