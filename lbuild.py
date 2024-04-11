#!/usr/bin/env python3.9
"Process build logs and/or run build commands + save artefacts"
import sys, os, argparse, subprocess, datetime, shutil, errno, re,\
	stat, shlex

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
	"--gprof", action="store_true", help="Compile with -pg")
parser.add_argument(
	"--asan", action="store_true", help="Compile with ASAN")
parser.add_argument(
	"--command", "-c", action="store_true", help="Run command")
parser.add_argument(
	"--docker", "-d", action="store_true",
	help="Run command in a container")
parser.add_argument(
	"--lid", action="store_true",
	help="Don't inhibit systemd lid switch handler")
parser.add_argument("--codeql", "-q", help="Run codeql")
parser.add_argument("--alert", "-a", action="store_true")
parser.add_argument("POSITIONAL", nargs="*")

def nn(n):
	return ",".join(re.findall(r"\d{1,3}", str(n)[::-1]))[::-1]

class Paths:
	def __init__(self, build, base, args):
		self.base = base # srcdir
		self.absBase = os.path.abspath(self.base)
		self.logName = "_build.log"
		prefix = build.getConf("prefix")
		name = os.path.basename(sys.argv[0])
		if name.startswith("python"):
			name = os.path.basename(sys.argv[1])
		if prefix:
			dir = os.path.join(prefix, name.split(".")[0])
		else:
			dir = build.getConf("dir", ".")
		if args.gprof:
			dir += ".gprof"
		if args.asan:
			dir += ".asan"
		self.build = os.path.join(self.base, dir)
		self.log = os.path.join(self.base, self.logName)
		
	def artefact(self, aname):
		return os.path.join(self.build, aname)

	def save(self, name):
		return os.path.join(self.build, name)

class Count:
	def __init__(self, name):
		self.name = name
		self.size = 0

class Command:
	def __init__(self, line):
		# TODO quoting
		self.argv = line.strip().split(" ")

	def isCompile(self):
		return "-c" in self.argv


class Input:
	def __init__(self, args, paths):
		self.args = args
		self.takeoff = datetime.datetime.now()
		self.commands = []
		self.verbose = sys.stdout
		self.lines = Count("lines")
		self.cc = Count("commands")
		self.compiles = Count("compiles")
		self.paths = paths
		self.prefix = ["scl", "enable", "gcc-toolset-9", "--"] 
		# TODO
		# It is possible to make it work by using
		# docker run option --security-opt=seccomp:unconfined
		# or --privilege 
		self.prefix += ["setarch", "x86_64", "-R"]

	def getConf(self, name, default=None):
		if name == "dir":
			return os.getcwd()

	def add(self, line, log):
		self.lines.size += 1
		if hasattr(line, "decode"):
			line = line.decode("utf-8")
		# Remove coloring
		line = re.sub(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]", "", line)
		# Windows paths must be converted before putting into _b.log
		m = re.match(r"\s*([\w:\\._-]+)([(]\d+[)]:.+)", line)
		if m:
			path, rest = m.groups()
			if path.lower().startswith(self.paths.absBase.lower()):
				path = path[len(self.paths.absBase) + 1:]
			path = path.replace("\\", "/")
			line = path + rest
		line = line.replace("\r", "")
		leftToRight = True
		if leftToRight:
			m = re.match(r"([/\w.]+:\d+)(.+)", line)
			if m:
				path, rest = m.groups()
				line = "%s at %s" % (rest, path)
		if not line.endswith("\n"):
			line += "\n"
		if log:
			log.write(line)
			log.flush()
		if self.verbose:
			self.verbose.write("%s %s" % (self.describeTime(), line))
			self.verbose.flush()
		if line.find(" -o ") < 0:
			return
		command = Command(line)
		self.commands.append(command)
		if command.isCompile():
			self.compiles.size += 1
		self.cc.size += 1

	def describeTime(self):
		f = datetime.datetime.now() - self.takeoff
		return "%02d\uFE55%02d\uFE55%02d" % (
			f.seconds / 3600, f.seconds / 60 % 60,
			f.seconds % 60)

	def read(self, stream, out):
		while True:
			line = stream.readline()
			if not line:
				break
			self.add(line, out)

	def logCommand(self, cmd, out=None, env=None):
		cmd = self.prefix + cmd
		self.add("In '%s' Running '%s'...\n" % (
			self.paths.build, shlex.join(cmd)), out)
		p = subprocess.Popen(
			cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
			bufsize=0, cwd=self.paths.build, env=env)
		self.read(p.stdout, out)
		r = p.wait()
		if r != 0:
			raise subprocess.CalledProcessError(r, cmd)
			# raise Exception("Status %d from '%s'" % (r, shlex.join(cmd)))

# TODO Should be subclass of Input
class Build:
	def __init__(self, conf, args):
		self.args = args
		confpath = conf['src']
		if os.path.isdir(confpath):
			base = confpath
		else:
			raise Exception("TODO")
		self.conf = conf
		self.platform = sys.platform
		if self.platform.startswith("linux"):
			self.platform = "linux"
			self.env = dict(os.environ)
			self.env["PATH"] = "%s:%s" % (
				os.path.dirname(__file__), self.env["PATH"])
			if self.args.gprof:
				self.env["CXXFLAGS"] = self.env["CFLAGS"] = "-lkjhg"
		else:
			self.env = dict(os.environ)
			toolbase = os.path.dirname(os.path.dirname(sys.executable))
			self.toolbase = toolbase
			self.env["PATH"] = ";".join([
				os.path.join(toolbase, "poedit", "gettexttools", "bin"),
				os.path.dirname(sys.executable),
				os.path.dirname(self.getGit()),
				self.env["PATH"]])
		self.pconf = conf.get(self.platform, {})
		self.paths = Paths(self, base, self.args)
		self.saved = Count("saved")

	def run(self):
		if not self.args.lid:
			cmd = ["systemd-inhibit", "--what=handle-lid-switch"] +\
				sys.argv + ["--lid"]
			print("Running '%s'..." %  shlex.join(cmd))
			os.execvp(cmd[0], cmd)
		msg = code = 0
		try:
			self.mkdir(self.paths.build)
			self.loadName()
			self.runBuildCommands()
			self.saveArtefacts()
			msg = "Done build %s in %s (saved %s)\n" % (
				self.getName(), self.bl.describeTime(), self.saved.size)
		except Exception as e:
			msg = str(e)
			code = getattr(e, "returncode", 1)
		print(msg)
		# TODO Archive this final line as well
		if self.args.alert:
			subprocess.check_call([
				"zenity", "--info", "--text=" + msg])
		sys.exit(code)

	def checkOutput(self, cmd, **kw):
		print("Running '%s'..." % (shlex.join(cmd)))
		return subprocess.check_output(cmd, **kw)

	def getGit(self):
		if "win32" != self.platform:
			return "git"
		return os.path.join(
			self.toolbase, "portablegit", "bin", "git.exe")

	def loadName(self):
		modified = self.checkOutput(
			[self.getGit(), "ls-files", "--modified"],
			cwd=self.paths.base).strip()
		print("modified='%s'" % modified)
		self.dirty = not not len(modified)
		self.rev = self.checkOutput(
			[self.getGit(), "rev-parse", "HEAD"],
			cwd=self.paths.base).strip()[:8]
		if self.rev.decode:
			self.rev = self.rev.decode("utf-8")

	def getName(self):
		return "%s%s" % (
			self.rev, self.dirty and "-dirty" or "")

	def mkdir(self, path):
		try:
			os.mkdir(path)
		except OSError:
			e = sys.exc_info()[1]
			if e.errno != errno.EEXIST:
				print("Creating '%s': e=%s errno=%s" % (
					path, e, e.errno))

	def saveArtefacts(self):
		if self.dirty:
			for p in self.getConf("files"):
				if os.path.basename(p) == p:
					continue
				a = self.paths.artefact(p)
				self.copy(
					a, os.path.join(self.paths.build, os.path.basename(p)))
			return
		save = self.paths.save(self.getName())
		self.mkdir(save)
		self.copy(self.paths.log, os.path.join(save, self.paths.logName))
		for n in self.pconf["files"]:
			a = self.paths.artefact(n)
			self.copy(a, os.path.join(save, "%s-%s" % (
				self.getName(), n)))

	def copy(self, a, b):
		size = os.stat(a).st_size
		print("Copying '%s' (%s bytes) to '%s'..." % (a, nn(size), b))
		shutil.copyfile(a, b)
		os.chmod(b, stat.S_IREAD | stat.S_IRWXU | stat.S_IRWXG)

	def getConf(self, name, default=None):
		return self.pconf.get(name, self.conf.get(name, default))

	def runBuildCommands(self):
		self.bl = Input(args, self.paths) 
		with open(self.paths.log, "wt") as log:
			self.bl.add(
				"-*- mode: compilation -*-\n", log)
			self.bl.add("Build %s\n" % self.getName(), log)
			self.logBuildCommands(log)
			
	def expand(self, arg):
		if "$make" == arg:
			return ["make", "CXXLD=g++ -Wl,-Map,$@.map"]
		here = os.path.dirname(os.path.realpath(__file__))
		arg = arg.replace("$here", here)
		if self.args.asan:
			if "-DCMAKE_BUILD_TYPE=RelWithDebInfo" == arg:
				return [
					arg,
					"-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-fsanitize=address -static-libasan"]
		return [arg]

	def logBuildCommands(self, log):
		for cmd in self.getConf("commands"):
			if hasattr(cmd, "split"):
				cmd = cmd.split(" ")
			cmd = sum([self.expand(a) for a in cmd], [])
			prefix = self.getConf("cmdPrefix")
			if prefix:
				self.bl.prefix = prefix
			elif "win32" != self.platform:
				dockerImage = self.getConf("docker")
				if dockerImage:
					# TODO Kill all previous builds
					# command: docker ps --filter ancestor=IMAGE
					top = self.getConf("top", self.paths.base)
					base = os.path.normpath(
						os.path.join(os.getcwd(), top))
					build = os.path.realpath(self.paths.build)
					self.bl.prefix = [
						"docker", "run", "--rm",
						"-v", f"{base}:{base}"]
					if base != build:
						self.bl.prefix +=["-v", f"{build}:{build}"]
					self.bl.prefix += [
						"-u", str(os.getuid()),
						"-w", build,
						"-e", f"HOME={build}",
						"-e",
						"ASAN_OPTIONS=new_delete_type_mismatch=0,detect_leaks=0,help=1",
						"-t", dockerImage,
						"ionice", "-n7"]
			self.bl.logCommand(cmd, log, self.env)
			
class BuildLogTool:
	def __init__(self, args):
		self.args = args
		self.output = None
		
	def reportCounts(self, counts):
		for count in counts:
			print(" %16s %s" % (nn(count.size), count.name))
			if self.output:
				self.output.write(" %16s %s\n" % (
					nn(count.size), count.name))
				
	def run(self):
		# Inputs are log files
		bl = Input(args, Paths(self, os.getcwd(), self.args))
		bl.verbose = None
		for path in self.args.POSITIONAL:
			bl.read(open(path, "r"), None)
		if self.args.codeql:
			codeql = os.path.expanduser("~/codeql/codeql")
			extrLog = Input(args, bl.paths)
			extrLog.logCommand([
				codeql, "database", "init", self.args.codeql,
				"--language=cpp", "--source-root=.", "--overwrite"])
			for command in bl.commands:
				extrLog.logCommand([
					codeql, "database", "trace-command", "--",
					self.args.codeql] +	command.argv)
			extrLog.logCommand([
				codeql, "database", "finalize", self.args.codeql])
		self.reportCounts([bl.lines, bl.cc, bl.compiles])
				
				
args = parser.parse_args()
if __name__ == "__main__":
	if not args.command and not args.docker:
		BuildLogTool(args).run()
		sys.exit(0)
	if not args.docker:
		sys.exit(Build(
			{"commands": [args.POSITIONAL], "src": "."}, args).run())
	sys.exit(Build(
		{"commands": [args.POSITIONAL], "src": ".", "docker": "build:9"},
		args).run())
 
