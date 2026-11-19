#!/usr/bin/env python3
"""
Download audio from LR4 archive pages
Schedule mode: "YEAR,WEEKDAY,HH:MM"
(weekday: Mo/Tu/We/Th/Fr/Sa/Su or 0-6)

Options to try if not working:
--base-url https://159.148.56.130/arh0/_definst_/4/{yyyy}{mm}/{yyyy}{mm}{dd}_{hh}{mm2}_r4.m4a/playlist.m3u8
--base-url https://muste.radio.org.lv/arh1/_definst_/4/{yyyy}{mm}/{yyyy}{mm}{dd}_{hh}{mm2}_r4.m4a/playlist.m3u8
"""
import argparse, urllib.request, re, subprocess, sys, json, os
from datetime import date, timedelta

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
	"--ytdlp", "-y", action="store_true", help="Use ytdlp")
parser.add_argument(
	"--skip", "-S", help="Regexp in record url to skip")
parser.add_argument(
	"--limit", "-L", type=int, help="Stop after N downloads")
parser.add_argument(
	"--base-url",
	default="https://muste.radio.org.lv/arh0/_definst_/4/{yyyy}{mm}/{yyyy}{mm}{dd}_{hh}{mm2}_r4.m4a/playlist.m3u8",
	help="URL template for schedule mode (use {yyyy},{mm},{dd},{hh},{mm2})")
parser.add_argument("INPUT", nargs="*")
args = parser.parse_args()

if args.ytdlp:
	top = os.path.dirname(os.path.dirname(__file__))
	sys.path.append(top + "/src/yt-dlp")
	import yt_dlp.YoutubeDL

def nn(n):
	return ",".join(re.findall(r"\d{1,3}", str(n)[::-1]))[::-1]

class Count:
	def __init__(self):
		self.total = self.done = self.was = self.skipped = 0
		
WEEKDAY_MAP = {"mo": 0, "tu": 1, "we": 2, "th": 3, "fr": 4, "sa": 5, "su": 6}

def parseWeekday(wday):
	wday = wday.lower()
	if wday in WEEKDAY_MAP:
		return WEEKDAY_MAP[wday]
	try:
		return int(wday)
	except ValueError:
		return None

def generateScheduleUrls(schedule, baseUrl):
	"""Generate all m3u8 URLs matching 'YEAR,WEEKDAY,HH:MM' schedule."""
	parts = schedule.split(",")
	years = None
	if len(parts) == 3:
		years = parts[0].split("-")
		if len(years) == 2:
			years = range(int(years[0]), int(years[1]) + 1)
		elif len(years) == 1:
			years = [int(years[0])]
	if not years:
		sys.stderr.write("Schedule must be 'YEAR[-YEAR],WEEKDAY,HH:MM'\n")
		return
	weekday = parseWeekday(parts[1])
	if weekday is None:
		sys.stderr.write(f"Unknown weekday: {parts[1]} (use Mo/Tu/We/Th/Fr/Sa/Su or 0-6)\n")
		return
	if not (0 <= weekday <= 6):
		sys.stderr.write("Weekday must be 0 (Mon) to 6 (Sun)\n")
		return
	hh, mm2 = parts[2].split(":")
	for year in years:
		for month in range(1, 13):
			for day in range(1, 32):
				try:
					d = date(year, month, day)
				except ValueError:
					break
				if d.weekday() != weekday:
					continue
				url = baseUrl.format(
					yyyy=year, mm=f"{month:02d}", dd=f"{day:02d}",
					hh=hh, mm2=mm2)
				yield url

class Input:
	def __init__(self, url):
		self.url = url

class Download:
	def run(self, args):
		self.args = args
		self.count = Count()
		self.failures = []
		inputs = []
		for inp in self.args.INPUT:
			if inp.endswith("/playlist.m3u8"):
				inputs.append(inp)
			elif inp.startswith("20"):
				urls = list(generateScheduleUrls(inp, args.base_url))
				inputs += urls
				self.count.total += len(urls)
			else:
				# TODO2 Convert into playlist urls here
				inputs.append(inp)
		for inp in sorted(inputs):
			if inp.endswith("/playlist.m3u8"):
				self.dlM3u(inp)
				if self.args.limit and self.count.done >= self.args.limit:
					break
			else:
				self.downloadFromSearchPage(inp)
		for inp in self.failures:
			print("%s: %s" % (inp.error, inp.url))
		self.printState()
		print("")

	def printState(self):
		sys.stderr.write(
			"\rTotal %d, downloaded %d, was there %d, "
			"skipped %d, failed %d" % (
				self.count.total, self.count.done, self.count.was,
				self.count.skipped, len(self.failures)))

	def download(self, url):
		cmd = ["curl", "-L", "--retry", "99999", url]
		sys.stderr.write("Running %s ...\n" % (" ".join(cmd)))
		cmd += ["-v"]
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
		text = p.stdout.read().decode()
		r = p.wait()
		if r != 0:
			raise Exception("curl returned %d" % (r))
		return text
		
	def downloadFromSearchPage(self, url):
		text = self.download(url)
		sys.stderr.write("Downloaded %s bytes\n" % nn(len(text)))
		json1 = text.split("var links = ")[1]
		json1 = json1.split(";")[0]
		if 1: sys.stderr.write("json=%s\n" % json1)
		data = json.loads(json1)
		self.count.total = len(sources := list(self.getSources(data)))
		for src in sorted(sources):
			self.dlM3u(src)
			if self.args.limit and self.count.done >= self.args.limit:
				break
			sys.stderr.write(
				"\rTotal %d, downloaded %d, was there %d, skipped %d" % (
					self.count.total, self.count.done, self.count.was,
					self.count.skipped))

	def getSources(self, data):
		for key, value in data.items():
			for srcData in value["audio"][0]["sources"]:
				src = srcData["file"]
				if src.startswith("http"):
					yield src
					
	def dlM3u1(self, src):
		if self.args.skip and re.search(self.args.skip, src):
			self.count.skipped += 1
			return
		name = src.replace("/playlist.m3u8", "")
		name = name.split("/")[-1]
		if self.args.ytdlp:
			yt_dlp.YoutubeDL({'outtmpl': name}).download([src])
		else:
			path = name + ".mp3"
			if os.path.isfile(path):
				self.count.was += 1
				sys.stderr.write("\nAlready downloaded '%s'\n" % path)
			else:
				sys.stderr.write("\n")
				tmpPath = name + ".tmp.mp3"
				try:
					subprocess.check_call(["ffmpeg", "-i", src, "-y", tmpPath])
					os.rename(tmpPath, path)
					self.count.done += 1
				except subprocess.CalledProcessError as e:
					if e.returncode == 234:
						sys.stderr.write("Code 234\n") # Why I did that?
					else:
						raise

	def dlM3u(self, src):
		inp = Input(src)
		try:
			self.dlM3u1(src)
		except subprocess.CalledProcessError as e:
			inp.error = e
			self.failures.append(inp)

Download().run(parser.parse_args())
