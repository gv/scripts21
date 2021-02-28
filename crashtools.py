#!/usr/bin/env python
from __future__ import print_function
"LLDB commands to get stuff from crash dumps"
import argparse, re, os, sys, time, subprocess, urllib.request
import lldb

def check(error):
	if error.fail:
		raise Exception(str(error))

class Count:
	def __init__(self):
		self.absent = 0
		self.modules = 0
		self.other = 0
		self.system = 0
		self.store = 0

class Util:
	def verb(self, message):
		if not self.args.verbose:
			return
		sys.stderr.write(message)
		sys.stderr.flush()

class SymbolNotOnServer(Exception):
	pass

class Target(Util):
	def __init__(self, path, args, debugger):
		self.path, self.args, self.debugger = path, args, debugger
		self.error = lldb.SBError()
		self.target = self.check(self.debugger.CreateTarget(
			"", "", "", True, self.error))
		self.verb("Loading '%s'..." % self.path)
		self.process = self.check(self.target.LoadCore(path, self.error))
		self.verb("DONE\n")

	def check(self, result):
		if self.error.fail:
			raise Exception(str(self.error))
		return result

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

	def printModules(self, tool):
		count = Count()
		mtime = time.localtime(os.path.getmtime(self.path))
		for m in self.target.modules:
			path = m.file.fullpath;
			parts = path.split("/")
			if len(parts) > 1:
				name = "/%s/.../%s" % (parts[1], parts[-1])
				if m.file.fullpath.startswith(self.args.storage):
					count.store += 1
					name = m.file.fullpath
				elif parts[1] in ["Volumes", "Applications"]:
					count.other += 1
				else:
					count.system += 1
			else:
				name = path
				count.other += 1
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
				print("%d %08X %s %016X '%s' '%s'" % (
					m.num_sections, fsize, self.getId(m),
					self.getSomeLoadAddress(m), name,
					m.GetSymbolFileSpec()))
		if self.args.stat:
			if not hasattr(tool, "statHeaderPrinted"):
				print(" modules: total, system, store, other, absent")
				tool.statHeaderPrinted = True
			print(
				self.getTime() + "%3d %3d %3d %3d %3d %s %s" % (
					self.target.GetNumModules(),
					count.system, count.store, count.other, 
					count.absent, self.path,
					self.target.executable.basename))

	def getSomeLoadAddress(self, m):
		for s in m.sections:
			if s.GetLoadAddress(self.target) != 0xFFFFFFFFFFFFFFFF:
				break
		return s.GetLoadAddress(self.target)

	def getId(self, m):
		return "".join(str(m.uuid).split("-")).upper() + "0"

	def getTime(self):
		mtime = time.localtime(os.path.getmtime(self.path))
		return time.strftime("%Y-%m-%d %H:%M| ", mtime)

	def downloadSymbols(self):
		for m in self.target.modules:
			self.verb("Full=%s\n" % m.file.fullpath)
			self.downloadTemplate("%s%s/%s/%s.dSYM.tar.bz2", m)
			self.downloadTemplate("%s%s/%s/%s.tar.bz2", m)

	def downloadTemplate(self, tmpl, m):
		prefix = self.args.download
		if not prefix.endswith("/"):
			prefix += "/"
		url = tmpl % (
			prefix, m.file.basename, self.getId(m), m.file.basename)
		try:
			self.download(url, useCurl=True)
		except SymbolNotOnServer:
			print("%s not found" % url)

	def download(self, url, useCurl=False):
		self.verb("Downloading %s ...\n" % url)
		import bz2
		c = bz2.BZ2Decompressor()
		if useCurl:
			curl = subprocess.Popen([
				"curl", "-L", url], stdout=subprocess.PIPE)
			src = curl.stdout
		else:
			src = urllib.request.urlopen(url)
			if src.getcode() != 200:
				raise Exception("src.getcode() = %d" % src.getcode())
		tar = subprocess.Popen(["tar", "t"], stdin=subprocess.PIPE)
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
			p = c.decompress(p)
			try:
				tar.stdin.write(p)
			except EOFError:
				pass # tar exited?
		tar.stdin.close()
		if useCurl and curl.wait() != 0:
			raise Exception("curl.wait() = %d", curl.wait())
		if tar.wait() != 0:
			raise Exception("tar.wait() = %d", tar.wait())

class Tool(Util):
	def __init__(self, args, debugger):
		self.args, self.debugger = args, debugger
		if self.debugger is None:
			self.verb("Starting debugger...")
			self.debugger = lldb.SBDebugger.Create()
			self.verb("DONE name=%s\n" % self.debugger.GetInstanceName())
		if self.args.storage:
			dirs = [os.path.join(self.args.storage, x) for x in os.listdir(
				self.args.storage) if not x.startswith(".")]
			self.verb("dirs=%s\n" % " ".join(dirs))
			check(lldb.SBDebugger.SetInternalVariable(
				"target.exec-search-paths", " ".join(dirs),
				self.debugger.GetInstanceName()))
		if self.args.verbose:
			# doesn't check
			if not self.debugger.EnableLog("lldb", ["dyld"]):
				raise Exception("Bad log")
		
	def run(self):
		self.args.DMPFILE.sort(key=os.path.getmtime, reverse=True)
		# self.verb("Press ENTER...")
		# sys.stdin.read(1)
		for path in self.args.DMPFILE:
			t = Target(path, self.args, self.debugger)
			if self.args.download:
				t.downloadSymbols()
			elif self.args.modules or self.args.absent:
				t.printModules(self)
			elif not self.args.stat:
				t.printRegions()
			if not (self.args.modules or self.args.absent):
				if self.args.stat:
			   		t.printModules(self)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("DMPFILE", help="Path to core file", nargs="+")
	parser.add_argument(
		"-m", "--modules", action="store_true", help="List binaries")
	parser.add_argument(
		"-a", "--absent", action="store_true", help="List absent binaries")
	parser.add_argument(
		"-s", "--stat", action="store_true",
		help="Print a line of numbers for every file")
	parser.add_argument(
		"-d", "--download", help="Symbol server URL to download symbols from")
	parser.add_argument(
		"-r", "--storage", help="Path to binary archive")
	parser.add_argument("-v", "--verbose", action="store_true")
	Tool(parser.parse_args(), None).run()
