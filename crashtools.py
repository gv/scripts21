#!/usr/bin/env python
from __future__ import print_function
"LLDB commands to get stuff from crash dumps"
import argparse, re, os, sys, time, subprocess, urllib.request
import lldb

def check(error):
	if error.fail:
		raise Exception(str(error))

def cut(s, limit):
	return len(s) > (limit+3) and "%s..." % s[:limit] or s

def getId(m):
	return "".join(str(m.uuid).split("-")).upper() + "0"

def num(n):
	return ",".join(re.findall(r"\d{1,3}", str(n)[::-1]))[::-1]

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
				num(count.done), num(count.total)))
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

class Target(Util):
	def __init__(self, args, debugger):
		self.args, self.debugger = args, debugger
		self.error = lldb.SBError()
		self.target = self.check(self.debugger.CreateTarget(
			"", "", "", True, self.error))
		# Hack: add mapping to nonexistent files so
		# ModuleList::GetSharedModule gets called first without a real path
		# and finds storage files in target.exec-search-paths
		if self.args.storage:
			self.check(self.target.AppendImageSearchPath(
				"/Volumes", self.args.storage, self.error))
			self.check(self.target.AppendImageSearchPath(
				"/Applications", self.args.storage, self.error))
		if self.args.download:
			self.setVar("target.preload-symbols", "false")
			
	def load(self, path):
		self.path = path
		self.verb("Loading '%s'..." % self.path)
		self.process = self.check(self.target.LoadCore(path, self.error))
		self.verb("DONE\n")
		return self

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

	def getName(self, m):
		if not m.IsValid():
			return "-"
		if m.file.fullpath.startswith(self.args.storage):
			return m.file.fullpath
		parts = m.file.fullpath.split(os.sep)
		if len(parts) <= 1:
			return m.file.fullpath
		return "/%s/.../%s" % (parts[1], parts[-1])

	def getSymbolFileName(self, m):
		if m.GetSymbolFileSpec() == m.file:
			return "-"
		return m.GetSymbolFileSpec()

	def getSourceLinePrefix(self, f):
		if not f.line_entry.IsValid():
			return " "
		cwd = os.getcwd().split(os.sep)[-1]
		parts = f.line_entry.file.fullpath.split(os.sep)
		try:
			path = os.sep.join(parts[parts.index(cwd) + 1:])
		except ValueError:
			path = f.line_entry.file.fullpath
		return "%s:%d:" % (path, f.line_entry.line)

	def printStacks(self):
		for t in self.process.threads:
			print("%3d %8d ================= %d '%s'" % (
				t.idx, t.id, t.stop_reason, t.GetStopDescription(80)))
			for f in t.frames:
				print("%s %3d %3d %16X '%s' %s (%s)" % (
					self.getSourceLinePrefix(f), 
					t.idx, f.idx, f.pc, f.addr.symbol.name,
					self.getName(f.addr.module),
					self.getSymbolFileName(f.addr.module)))
				# arguments, locals, statics, in_scope_only
				for v in f.GetVariables(True, True, False, True):
					print("name='%s' loc='%s' val='%s' type='%s' (%d)" % (
						v.name, v.location, v.value, v.type.name, v.type.size))

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
		for ver in os.listdir(self.args.storage):
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
				print("%d %08X %s %016X '%s' %s" % (
					m.num_sections, fsize, getId(m),
					self.getSomeLoadAddress(m), name,
					(m.GetSymbolFileSpec() == m.file) and
					"-" or m.GetSymbolFileSpec()))
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
			m.file.basename, getId(m), m.file.basename))
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
			dirs = [os.path.join(self.args.storage, x) for x in os.listdir(
				self.args.storage) if not x.startswith(".")]
			self.setVar("target.exec-search-paths", " ".join(dirs))
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
		self.args.DMPFILE.sort(key=os.path.getmtime, reverse=True)
		for path in self.args.DMPFILE:
			t = Target(self.args, self.debugger).load(path)
			if 0 and self.args.storage:
				t.fixModulesNotInStorage()
			self.handleTarget(t)
		self.count = WorkCount(len(self.work))
		for task in self.work:
			task.run(self)
			self.count.done += 1

	def handleTarget(self, t):
		if self.args.download:
			self.work += t.queueDownloadSymbols(Server(self.args))
		elif self.args.threads:
			t.printStacks()
		elif self.args.modules or self.args.absent:
			t.printModules(self)
		elif not self.args.stat:
			t.printRegions()
		if not (self.args.modules or self.args.absent):
			if self.args.stat:
			   	t.printModules(self)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("DMPFILE", help="Path to core file", nargs="*")
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
	parser.add_argument(
		"-u", "--unchecked", action="store_true",
		help="Allow binaries not in archive")
	parser.add_argument(
		"-n", "--attachname", help="Attach to a live process by name")
	parser.add_argument(
		"-t", "--threads", action="store_true", help="Print stacks")
	parser.add_argument("-v", "--verbose", action="store_true")
	parser.add_argument(
		"-b", "--dverbose", action="store_true", help="LLDB verbose output")
	Tool(parser.parse_args(), None).run()
