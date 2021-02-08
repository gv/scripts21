#!/usr/bin/env python
from __future__ import print_function
"Emacs object & stack decoder"
import sys, argparse, json, re
import lldb

psize = 8

types = dict(
	#	 /* Symbol.	 XSYMBOL (object) points to a struct Lisp_Symbol.  */
	Lisp_Symbol = 0,

	#	 /* Miscellaneous.	XMISC (object) points to a union Lisp_Misc,
	#		whose first member indicates the subtype.  */
	Lisp_Misc = 1,

	#	 /* Integer.  XINT (obj) is the integer value.	*/
	Lisp_Int0 = 2,
	#	 Lisp_Int1 = USE_LSB_TAG ? 6 : 3,

	#	 /* String.	 XSTRING (object) points to a struct Lisp_String.
	#		The length of the string, and its contents, are stored therein.	 */
	Lisp_String = 4,

	#	 /* Vector of Lisp objects, or something resembling it.
	#		XVECTOR (object) points to a struct Lisp_Vector, which contains
	#		the size and contents.	The size field also contains the type
	#		information, if it's not a real vector object.	*/
	Lisp_Vectorlike = 5,

	#	 /* Cons.  XCONS (object) points to a struct Lisp_Cons.	 */
	# Lisp_Cons = USE_LSB_TAG ? 3 : 6,

	Lisp_Float = 7)

rtypes = {v: k for k, v in types.items()}

def range64(begin, end, step):
	while begin < end:
		yield begin
		begin += step

class Count:
	def __init__(self):
		self.occurence = 0
		self.match = 0

class StackDecoder:
	def __init__(self, debugger, options=None):
		self.debugger, self.options = debugger, options
		self.error = lldb.SBError()
		self.count = Count()

	def run(self):
		StackDecoder.obj = self
		self.target = self.debugger.CreateTarget(
			"", "", "", True, self.error)
		if not self.target:
			raise Exception(str(self.error))
		name = "Emacs-x86_64-10_10"
		sys.stderr.write("Attaching '%s'..." % name)
		self.process = self.target.Attach(
			lldb.SBAttachInfo(name, False), self.error)
		if not self.process:
			raise Exception(str(self.error))
		sys.stderr.write("Done\n")
		self.initRuntime()
		if self.options.breakpoint:
			self.traceFunction(self.options.breakpoint)
		else:
			self.trace()
		# Destroy() is necessary to not SEGV at exit
		# the rest maybe not
		self.check(self.process.Detach())
		self.debugger.DeleteTarget(self.target)
		lldb.SBDebugger.Destroy(self.debugger)

	def initRuntime(self):
		contexts = self.target.FindSymbols("lispsym")
		if len(contexts) == 0:
			raise Exception(
				"'lispsym' array not found, can't resolve symbols")
		if len(contexts) != 1:
			raise Exception("TODO")
		if not contexts[0].IsValid():
			raise Exception("not contexts[0].IsValid()")
		if not contexts[0].symbol.IsValid():
			raise Exception("not contexts[0].symbol.IsValid()")
		# self.symbolBase = contexts[0].symbol.addr.GetLoadAddress(self.target)
		self.symbolBase = contexts[0].symbol.addr.GetFileAddress()
		print("Symbol base=%016X offset=%16X mod=%s" % (
			self.symbolBase, contexts[0].symbol.addr.offset,
			contexts[0].symbol.addr.module))
		return self

	def check(self, error):
		if not error.success:
			raise Exception(str(error))

	def trace(self):
		b = self.target.BreakpointCreateByName("Ffuncall")
		b.SetScriptCallbackFunction("StackDecoder.obj.handleBreakpoint")

	def traceFunction(self, fn):
		self.setBreakpoint(fn, "StackDecoder.obj.printStack")
		self.runProcess()

	def setBreakpoint(self, fn, call):
		b = self.target.BreakpointCreateByName(fn)
		b.SetScriptCallbackFunction(call)
		if b.num_locations == 0:
			raise Exception("No location for '%s'" % fn)

	def runProcess(self):
		listener = self.debugger.GetListener()
		self.process.GetBroadcaster().AddListener(
			listener, lldb.SBProcess.eBroadcastBitStateChanged |
			lldb.SBProcess.eBroadcastBitInterrupt)
		self.check(self.process.Continue())
		ev = lldb.SBEvent()
		while True:
			sys.stderr.write("Waiting...")
			if not listener.WaitForEvent(lldb.UINT32_MAX, ev):
				raise Exception("TODO")
			state = lldb.SBProcess.GetStateFromEvent(ev)
			if state == lldb.eStateStopped:
				self.check(self.process.Continue())
				continue
			if state == lldb.eStateRunning:
				continue
			sys.stderr.write(
				"event=%s\n" % lldb.SBDebugger.StateAsCString(state))
			if state == lldb.eStateExited:
				break

	def handleBreakpoint(self, frame, bp_loc, dict):
		length, objects = [
			frame.reg[n].GetValueAsUnsigned() for n in ["rdi", "rsi"]]
		print(self.describeArgs(objects, length))

	def printStack_(self, frame, bp_loc, dict):
		thread = frame.GetThread()
		for f in thread:
			print("%s sp=%X" % (f, f.GetSP()))
			self.debugger.HandleCommand("memory read %d -fA" % (f.GetSP()))

	def printStack1(self, frame, bp_loc, dict):
		pos = frame.GetSP()
		funcall = self.getFunctionPtr("Ffuncall")
		points = [funcall + 740, funcall + 645]
		print("sp=%X funcall=%X points=%X,%X" % (
			pos, funcall, points[0], points[1]))
		matchCount = 0
		while True:
			ptr = self.process.ReadPointerFromMemory(pos, self.error)
			if not self.error.success:
				# LLDB won't give us stack bottom address
				print("Stop stack scan: %s" % self.error)
				break
			# Necessary to catch OverflowError...
			try:
				isMatch = ptr in points
			except Exception, e:
				isMatch = False
				# print(" %s pos=%X ptr=%X" % (e, pos, ptr))
			if isMatch:
			# if "%X" % ptr == "%X" % points[0] or "%X" % ptr == "%X" % points[1]:
				count = self.process.ReadPointerFromMemory(
					pos - 24, self.error) + 1
				if self.error.success:
					args = self.process.ReadPointerFromMemory(
						pos - 16, self.error) - 8
					try:
						if count >= 80:
							raise Exception("count must be < 80")
						print(" %4d %4d %s" % (
							self.count.occurence, matchCount,
							self.describeArgs(args, count)))
					except Exception, e:
						print(" %4d %4d args=%X count=%d %s" % (
							self.count.occurence, matchCount, args, count, e))
					matchCount += 1
				if not self.error.success:
					print(str(self.error))
			pos += psize

	def printStack(self, frame, bp_loc, dict):
		try:
			self.printStack1(frame, bp_loc, dict)
		finally:
			self.count.occurence += 1

	def getFunctionPtr(self, name):
		contexts = self.target.FindFunctions(name)
		if len(contexts) == 0:
			raise Exception("No address for '%s'" % name)
		if len(contexts) != 1:
			raise Exception("TODO")
		ptr = contexts[0].symbol.addr.GetLoadAddress(self.target)
		if 0xFFFFFFFFFFFFFFFF == ptr:
			raise Exception("ptr=%X" % ptr)
		return ptr
		
	def describeArgs(self, objects, length):
		q = objects
		end = objects + length * psize
		# print("objects=%X length=%d end=%X" % (objects, length, end))
		descs = []
		while q < end:
			descs += [self.describeObject(self.readPointer(q))]
			q += psize
		return "(%s)" % " ".join(descs)
		# this gives:
		# OverflowError: Python int too large to convert to C long	
		# return "(%s)" % " ".join([
		#	self.describeObject(self.readPointer(p))
		#	for p in range64(objects, objects + length * psize, psize)])

	def readPointer(self, addr):
		p = self.process.ReadPointerFromMemory(addr, self.error)
		self.check(self.error)
		return p

	def describeObject(self, pointer, recursive=True):
		typeId = 7 & pointer
		type = rtypes.get(typeId)
		if not type:
			return "%016X(%d)" % (pointer, typeId)
		if "Lisp_String" == type:
			p2 = pointer - typeId
			size = self.readPointer(p2 + 8)
			dataAddr = self.readPointer(p2 + 24)
			data = self.process.ReadMemory(dataAddr, size, self.error)
			if not self.error.success:
				return "(size=%d %s)" % (size, self.error)
			return json.dumps(data)
		if recursive and "Lisp_Symbol" == type:
			# typeId = 0
			p2 = self.symbolBase + pointer
			name = self.readPointer(p2 + 8)
			return "'%s" % self.describeObject(name, False)
		return "%016X(%s)" % (pointer, type)

	def setTarget(self, target):
		self.target = target
		self.process = target.GetProcess()
		return self.initRuntime()

	def describeObjectFromSBValue(self, sbv):
		raise Exception("TODO")

def printLispObject(debugger, command, result, internal_dict):
	args = re.split(r"\s+", command)
	if args[0] == "":
		print("usage: plo OBJECT [OBJECT] ...")
		return
	sd = StackDecoder(debugger).setTarget(debugger.GetSelectedTarget())
	for argument in args:
		sbv = sd.target.EvaluateExpression(argument)
		print(" '%s' = %s" % (
			argument, sbv.value and
			sd.describeObject(sbv.GetValueAsUnsigned(sd.error)) or sbv.error))
		if not sd.error.success:
			print(" + %s" % sd.error)
			
def printLispArgs(debugger, command, result, internal_dict):
	commandArguments = re.split(r"\s+", command)
	if len(commandArguments) != 2:
		print("usage: pla ADDRESS COUNT")
		return
	sd = StackDecoder(debugger).setTarget(debugger.GetSelectedTarget())
	vals = []
	for a in commandArguments:
		sbv = sd.target.EvaluateExpression(a)
		if not sbv.error.success:
			print(" %s: %s" % (a, sbv.error))
		vals += [sbv]
	if not (vals[0].error.success and vals[1].error.success):
		return
	count = vals[1].GetValueAsSigned()
	maxCount = 4096
	if count > maxCount:
		raise Exception("count=%d (maxCount=%d)" % (count, maxCount))
	pos = vals[0].GetValueAsUnsigned()
	end = pos + psize * count
	while pos < end:
		print(" %16X %s" % (pos, sd.describeObject(sd.readPointer(pos))))
		pos += psize

def scanStack(debugger, command, result, internal_dict):
	if re.split(r"\s+", command)[0] != "":
		print("usage: blt")
		return
	sd = StackDecoder(debugger).setTarget(debugger.GetSelectedTarget())
	sd.printStack(sd.process.GetSelectedThread().GetSelectedFrame(), None, None)

def __lldb_init_module(debugger, internal_dict):
	debugger.HandleCommand(
		"command script add -f emacstools.printLispObject plo")
	debugger.HandleCommand(
		"command script add -f emacstools.printLispArgs pla")
	debugger.HandleCommand(
		"command script add -f %s.scanStack lbt" % __name__)
	print("'%s' loaded" % __name__)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("-b", "--breakpoint", help="Set breakpoint at <name>")
	StackDecoder(lldb.SBDebugger.Create(), parser.parse_args()).run()
