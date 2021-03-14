#!/usr/bin/env python
from __future__ import print_function
"Trace function calls & print stacks"
import argparse, re, sys, os, subprocess, json
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


class TracePoint:
	def getAddrOf(self, name, target):
		ff = target.FindFunctions(name)
		if len(ff) == 0:
			return 0
		if len(ff) != 1:
			raise Exception("TODO")
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


class NamedTracePoint(TracePoint):
	def __init__(self, name, addr=None):
		self.command = None
		parts = name.split(",")
		if len(parts) > 1:
			name = parts[0]
			self.command = parts[1]
		self.symbolName = name
		self.addr = addr

	def getAddr(self, target, process):
		return self.addr

	def trace2(self, frame, toolProc):
		if self.command:
			toolProc.debugger.HandleCommand(self.command)
		else:
			sys.stdout.write("trace '%s'\n" % self.symbolName)
	

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


class Process:
	objects = {}
	
	def __init__(self, options):
		self.options = options
		self.debugger = lldb.SBDebugger.Create()
		self.error = lldb.SBError()
		self.breakpoints = {}
		self.lastPrintedStack = []
		self.stacksEnabled = True

	def load(self, pid):
		self.target = self.debugger.CreateTarget(
			"", "", "", True, self.error)
		if not self.target:
			raise Exception(str(self.error))
		if re.match(r"\d+", pid):
			ai = lldb.SBAttachInfo(int(pid))
			sys.stderr.write("Attaching pid=%d..." % ai.GetProcessID())
		else:
			ai = lldb.SBAttachInfo(pid, False)
			sys.stderr.write("Attaching name='%s'..." % pid)
		self.process = self.target.Attach(ai, self.error)
		if not self.process:
			raise Exception(str(self.error))
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

	def handleBreakpoint(self, frame, bp_loc):
		if self.stacksEnabled:
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
				print("\r%7s %16x %s %s" % (
					head, f.addr.GetLoadAddress(self.target),
					f.module.file.basename,
					f.addr.symbol.name))
			self.lastPrintedStack = frame.thread.frames[::-1]
		tr = self.breakpoints.get(frame.pc) or\
			self.breakpoints[frame.name]
		if hasattr(tr, "trace2"):
			tr.trace2(frame, self)
		else:
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
			sys.stderr.write("Waiting...")
			if 1:
				if not self.listener.WaitForEvent(lldb.UINT32_MAX, ev):
					raise Exception("timeout lldb.UINT32_MAX achieved???")
			# timeout to catch SIGINT 
			while not self.listener.WaitForEvent(1, ev):
				pass
			state = lldb.SBProcess.GetStateFromEvent(ev)
			if state == lldb.eStateStopped:
				self.process.Continue()
			elif state == lldb.eStateExited:
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
			
	def listDynSymbols(self):
		for m in self.target.modules:
			for s in m:
				if s.external:
					print("%s %s %s" % (
						m.file.fullpath, s.name, s.addr))

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
		process = Process(self.options).load(self.options.PID)
		if self.options.tid:
			try:
				process.inspect(tid)
			except Exception, e:
				print("exception in inspect: %s" % e)
			self.traceAll(process)
		elif self.options.list:
			process.listDynSymbols()
		else:
			self.traceAll(process)
		process.unload()

	def traceAll(self, process):
		if self.options.FUNCTION:
			for expr in self.options.FUNCTION:
				if expr.endswith(".dylib"):
					process.breakAtEveryEntryPointOfModule(expr)
				else:
					process.setBp(NamedTracePoint(expr))
			process.runTrace()
		else:
			process.traceSsl()

	def collectProcesses(self):
		command = [
			"sudo", # "-S",
			os.path.join(os.path.dirname(__file__), "collecttcp.d"),
			"-DPRINT=1", "-DSTOP=\"%s\"" % self.options.with_dtrace]
		print("Running %s...", json.dumps(" ".join(command)))
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
	"-t", "--tid", help="Inspect thread TID")
parser.add_argument(
	"-d", "--with-dtrace",
	help="Use collecttcp.d with STOP set to WITH_DTRACE")
parser.add_argument(
	"-s", "--ssl", help="Trace SSL reads & writes")
parser.add_argument("PID", nargs="?")
parser.add_argument("FUNCTION", nargs="*")
Tool(parser.parse_args()).run()
