#!/usr/bin/env python
from __future__ import print_function
"Trace function calls & print stacks"
import argparse, re, sys, os, subprocess, json, fnmatch, struct
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

psize = 8

def hexDumpMem(process, start, end, error):
	lsize = 16
	while start < end:
		if lsize > end - start:
			lsize = end - start
		st = process.ReadMemory(start, lsize, error)
		if error.fail:
			raise Exception(str(error))
		sys.stderr.write(" %X " % start)
		sys.stderr.write(
			("%02X " * lsize) % tuple(bytearray(st)))
		for c in st:
			sys.stderr.write(ord(c) < 32 and "." or c)
		sys.stderr.write("\n")
		start += lsize

def callProcessHandleBp2(frame, bp_loc, dict):
	process = frame.GetThread().GetProcess()
	# print(" addr=%s=%x sp=%X" % (frame.addr, frame.pc, frame.sp))
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
	def getAddrOf(self, name, target):
		ff = target.FindFunctions(name)
		if len(ff) == 0:
			return 0
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
		# load_addr doesn't work bc target is not "current"
		return ff[0].symbol.addr.GetLoadAddress(target)

	def getAddr(self, target, process):
		if self.addr:
			return self.addr
		if self.nameIsFull:
			return self.getAddrOf(self.symbolName, target)
		return None

class NamedTracePoint(TracePoint):
	def __init__(self, name, addr=None):
		self.addr = addr
		self.commands = []
		self.filters = []
		parts = name.split("#")
		if len(parts) > 1:
			name = parts[0]
			self.commands = parts[1:]
		parts = name.split("@")
		if len(parts) > 1:
			name = parts[0]
			self.filters = parts[1:]
		if name.startswith("0x"):
			self.addr = int(name, 16)
			return
		self.nameIsFull = not name.startswith("~")
		if self.nameIsFull:
			self.symbolName = name
		else:
			self.symbolName = name[1:]

	def substCommand(self, frame, cmd):
		"'memory read $rxx' is broken if DWARF is broken"
		def getReg(match):
			return "0x%x" % (
				frame.reg[match.group(1)].GetValueAsUnsigned())
		return re.sub(r"\$\$([a-z]{3})", getReg, cmd)

	def runScript(self, frame, cmd):
		c = compile(cmd, cmd, "single")
		error = lldb.SBError()
		# Somehow eval gets r printed by itself (???)
		r = eval(c, {}, dict(
			f=frame, p=frame.thread.process, e=error, z=print))
		# print("result: %s" % r)

	def trace2(self, frame, toolProc):
		for filter in self.filters:
			found = None
			for f in frame.thread.frames:
				if f.addr.symbol.name and\
				   fnmatch.fnmatch(f.addr.symbol.name, filter) or\
				   f.module.file.basename and\
				   fnmatch.fnmatch(f.module.file.basename, filter):
					found = f
					break
			if not found:
				return
		if not self.commands:
			toolProc.printStack(frame)
		if self.commands:
			toolProc.process.SetSelectedThread(frame.thread)
			for cmd in self.commands:
				c2 = self.substCommand(frame, cmd)
				if 1 or c2 != cmd:
					sys.stdout.write("%s= " % c2)
				if c2.startswith("p.") or c2.startswith("print("):
					self.runScript(frame, c2)
				else:
					toolProc.debugger.HandleCommand(c2)
		else:
			sys.stdout.write("trace '%s'\n" % self.symbolName)

class RetTracePoint(NamedTracePoint):
	def trace2(self, frame, toolProc):
		toolProc.addTask(frame.sp + psize, self)
		frame.thread.StepOut()

	def runDeferredTask(self, toolProc, frame):
		NamedTracePoint.trace2(self, frame, toolProc)
	

class SSLWriteTrace(TracePoint):
	def getAddr(self, target, process):
		return self.getAddrOf("SSLWrite", target) + 254

	def trace(self, frame, process, error):
		buf = frame.reg["r12"].GetValueAsUnsigned()
		size = frame.reg["r15"].GetValueAsUnsigned()
		print("write %d bytes:" % size)
		hexDumpMem(process, buf, buf + size, error)


class SSLReadTrace(TracePoint):
	def getAddr(self, target, process):
		return self.getAddrOf("SSLRead", target) + 613

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
	    NSEventTypeLeftMouseDown             = 1,
		NSEventTypeLeftMouseUp               = 2,
		NSEventTypeRightMouseDown            = 3,
		NSEventTypeRightMouseUp              = 4,
		NSEventTypeMouseMoved                = 5,
		NSEventTypeLeftMouseDragged          = 6,
		NSEventTypeRightMouseDragged         = 7,
		NSEventTypeMouseEntered              = 8,
		NSEventTypeMouseExited               = 9,
		NSEventTypeKeyDown                   = 10,
		NSEventTypeKeyUp                     = 11,
		NSEventTypeFlagsChanged              = 12,
		NSEventTypeAppKitDefined             = 13,
		NSEventTypeSystemDefined             = 14,
		NSEventTypeApplicationDefined        = 15,
		NSEventTypePeriodic                  = 16,
		NSEventTypeCursorUpdate              = 17,
		NSEventTypeScrollWheel               = 22,
		NSEventTypeTabletPoint               = 23,
		NSEventTypeTabletProximity           = 24,
		NSEventTypeOtherMouseDown            = 25,
		NSEventTypeOtherMouseUp              = 26,
		NSEventTypeOtherMouseDragged         = 27,
		NSEventTypeGesture        = 29,
		NSEventTypeMagnify        = 30,
		NSEventTypeSwipe          = 31,
		NSEventTypeRotate         = 18,
		NSEventTypeBeginGesture   = 19,
		NSEventTypeEndGesture     = 20,
		NSEventTypeSmartMagnify  = 32,
		NSEventTypeQuickLook  = 33,
		NSEventTypePressure  = 34,
		NSEventTypeDirectTouch  = 37)

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
		print(" x=%d y=%d r=%X %s %s" % (
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

	def addTask(self, sp, task):
		if sp in self.tasksBySp:
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
			ai = lldb.SBAttachInfo(pid, False)
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
			raise Exception(str(self.error))
		self.debugger.DeleteTarget(self.target)
		sys.stderr.write("Done\n")

	def printStack(self, frame):
		if not self.stacksEnabled:
			return
		skipStart = None
		for i in range(frame.thread.GetNumFrames()):
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
			if sl:
				name = name.split("(")[0]
   			print("\r%7s %16x %s%s" % (
   				head, f.addr.GetLoadAddress(self.target),
   				self.printImage and (f.module.file.basename + " ") or "",
   				name) + sl)
   		self.lastPrintedStack = frame.thread.frames[::-1]

	def getSourceLine(self, f, template):
		if not f.line_entry.IsValid():
			return ""
		cwd = os.getcwd().split(os.sep)[-1]
		parts = f.line_entry.file.fullpath.split(os.sep)
		try:
			path = os.sep.join(parts[parts.index(cwd) + 1:])
		except ValueError:
			path = f.line_entry.file.fullpath
		return template % (path, f.line_entry.line)
			
	def handleBreakpoint(self, frame, bp_loc):
		tr = self.breakpoints.get(frame.pc) or\
			self.breakpoints[frame.name]
		if hasattr(tr, "trace2"):
			tr.trace2(frame, self)
		else:
			self.printStack(frame)
			tr.trace(frame, self.process, self.error)

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

	def setBp(self, t):
		addr = t.getAddr(self.target, self.process)
		if addr:
			self.breakpoints[addr] = t
			print("Setting bp to %X" % addr)
			b = self.target.BreakpointCreateByAddress(addr)
		else:
			self.breakpoints[t.symbolName] = t
			print("Setting bp to '%s'" % t.symbolName)
			b = self.target.BreakpointCreateByName(t.symbolName)
		if b.num_locations == 0:
			raise Exception("No locations for BP %s" % b)
		for i in range(b.num_locations):
			loc = b.GetLocationAtIndex(i)
			print("Location %s" % loc)
			self.breakpoints[loc.GetLoadAddress()] = t
   		b.SetScriptCallbackFunction("callProcessHandleBp2")

	def runTrace(self):
		if len(self.breakpoints) == 0:
			raise Exception("No breakpoints set!")
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
			if 0:
				if not self.listener.WaitForEvent(lldb.UINT32_MAX, ev):
					raise Exception("timeout lldb.UINT32_MAX achieved???")
			# timeout to catch SIGINT 
			while not self.listener.WaitForEvent(1, ev):
				pass
			state = lldb.SBProcess.GetStateFromEvent(ev)
			if state == lldb.eStateStopped:
				self.count.stopped += 1
				frame = self.process.selected_thread.GetFrameAtIndex(0)
				if frame.sp in self.tasksBySp:
					self.tasksBySp[frame.sp].runDeferredTask(self, frame)
					del self.tasksBySp[frame.sp]
				self.process.Continue()
			elif state == lldb.eStateRunning:
				pass
			elif state == lldb.eStateExited:
				sys.stderr.write("exited...")
				break
			else:
				sys.stderr.write(
					"event=%s\n" % lldb.SBDebugger.StateAsCString(state))

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
					self.setBp(HandleEventTrace(s.addr.GetLoadAddress(self.target)))

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
		try:
			i = functions.index("@")
			functions = functions[:i]
			launch = functions[:i + 1]
		except ValueError:
			pass
		if functions and not launch:
			pid = functions[-1]
			functions = functions[:-1]
		if not (pid or launch):
			sys.stderr.write("Need PID or command\n")
			sys.exit(1)
		process = Process(self.options).load(pid, launch)
		if self.options.tid:
			try:
				process.inspect(tid)
			except Exception, e:
				print("exception in inspect: %s" % e)
			self.traceAll(process, functions)
		elif self.options.list:
			process.listSymbols(False)
		elif self.options.list2:
			process.listSymbols(True)
		else:
			self.traceAll(process, functions)
		process.unload()

	def traceAll(self, process, functions):
		if self.options.ssl:
			return process.traceSsl()
		for expr in functions:
			if expr.endswith(".dylib"):
				process.breakAtEveryEntryPointOfModule(expr)
			elif expr.startswith("/"):
				process.setBp(RetTracePoint(expr[1:]))
			else:
				process.setBp(NamedTracePoint(expr))
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
		

parser = argparse.ArgumentParser(description=__doc__)
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
	"-s", "--ssl", action="store_true", help="Trace SSL reads & writes")
parser.add_argument(
	"-r", "--launch", help="Launch command line with spaces")
parser.add_argument(
	"--events", action="store_true",
	help="Trace handleEvent methods in every class and parse NSEvent structs")
#parser.add_argument(
#	"--nolib", action="store_true",
#	help="Set BPs in main executable only")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("FUNCTION", nargs="*")
parser.add_argument("PID", nargs="?")
Tool(parser.parse_args()).run()
