#!/usr/bin/env python3
"Calculate avg battery discharge rate over time when system not sleeping"
import argparse, datetime, bisect
import dbus, systemd.journal

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
	"-v", "--verbose", action="store_true", help="Print events")

class BatteryEvent:
	def __init__(self, v):
		self.values = v

	def getTs(self):
		return self.values[0]

	def getDateTime(self):
		return datetime.datetime.fromtimestamp(self.getTs())

	def getCharge(self):
		return self.values[1]

	def describeCharge(self):
		return "%3.1f" % self.getCharge()

	def getState(self):
		try:
			return [
				"Unknown", "Charging", "Discharging", "Empty",
				"Fully charged", "Pending charge", "Pending discharge"
			][self.values[2]]
		except IndexError:
			return self.values[2]

	def __lt__(self, other):
		return self.getTs() < other.getTs()
		
class SleepEvent(BatteryEvent):
	def __init__(self, logEntry):
		# print(logEntry)
		self.entry = logEntry

	def getTs(self):
		return int(self.entry['__REALTIME_TIMESTAMP']/1000000)

	def getState(self):
		return self.entry['MESSAGE']

	def describeCharge(self):
		return "    "

class Span:
	def __init__(self, start):
		self.events = [start]

	def getDischargeStart(self):
		return self.events[0]

	def getDischargeEnd(self):
		return sorted(self.events, key=BatteryEvent.getCharge)[0]

	def getEventsInside(self, ee):
		p = bisect.bisect_left(
			list(map(BatteryEvent.getDateTime, ee)),
			self.events[0].getDateTime())
		q = bisect.bisect_right(
			list(map(BatteryEvent.getDateTime, ee)),
			self.events[-1].getDateTime())
		return ee[p:q]

	def getEventsInsideJr(self, jr, convert):
		jr.seek_realtime(self.events[0].getTs())
		while True:
			ev = convert(jr.get_next())
			# print(ev.getDateTime())
			if ev.getDateTime() > self.events[-1].getDateTime():
				break
			yield ev

class BatteryHistory:
	def loadSleepEvents(self):
		jr = systemd.journal.Reader(
			converters={'__REALTIME_TIMESTAMP': int})
		jr.this_machine() 
		jr.add_match(MESSAGE="Suspending...")
		self.suspends = list(map(SleepEvent, jr))
		jr.flush_matches()
		jr.seek_head()
		jr.add_match(MESSAGE="ACPI: Low-level resume complete")
		self.resumes = list(map(SleepEvent, jr))

	def getSuspendedSeconds(self, start, end):
		suspended = 0
		while True:
			ps = bisect.bisect_left(self.suspends, start)
			if ps >= len(self.suspends) or self.suspends[ps] > end:
				break
			pr = bisect.bisect_left(self.resumes, self.suspends[ps])
			if pr >= len(self.resumes) or self.resumes[pr] > end:
				suspended += end.getTs() - self.suspends[ps].getTs()
				break
			start = self.resumes[pr]
			suspended += start.getTs() - self.suspends[ps].getTs()
		return suspended
		
	def show(self, args):
		self.args = args
		self.loadSleepEvents()
		bus = dbus.SystemBus()
		self.battery = bus.get_object(
			'org.freedesktop.UPower',
			'/org/freedesktop/UPower/devices/battery_BAT0')
		self.getHistory = self.battery.get_dbus_method(
			'GetHistory',
			'org.freedesktop.UPower.Device')
		events = self.getHistory("charge", 0, 0)
		self.cycles = []
		if len(events) <= 1:
			sys.stderr.write("Too few events (%d)" % len(events))
		events = list(map(BatteryEvent, events))
		events.sort(key=BatteryEvent.getTs)
		for i, e in enumerate(events):
			if i == 0 or i < len(events) - 1 and\
			   events[i-1].getCharge() < e.getCharge() and\
			   e.getCharge() > events[i+1].getCharge():
				self.cycles.append(Span(e))
				continue
			self.cycles[-1].events.append(e)
		for s in self.cycles:
			self.reportCycle(s)

	def reportCycle(self, s):
		start = s.getDischargeStart()
		end = s.getDischargeEnd()
		total = end.getTs() - start.getTs()
		compensated = total - self.getSuspendedSeconds(start, end)
		if start.getCharge() > end.getCharge():
			estimated90 = ", e. %s" % datetime.timedelta(seconds=int(
				compensated/(start.getCharge()-end.getCharge())*90))
		else:
			estimated90 = ""
		print("%s: %s => %s in %s (t. %s%s)" % (
			start.getDateTime().ctime(),
			start.describeCharge(),
			end.describeCharge(),
			datetime.timedelta(seconds=compensated),
			datetime.timedelta(seconds=total),
			estimated90))
		if self.args.verbose:
			all = s.events + list(s.getEventsInside(self.suspends)) +\
				list(s.getEventsInside(self.resumes))
			for v in sorted(all):
				print(" %s: %s %s" % (
					datetime.datetime.fromtimestamp(v.getTs()),
					v.describeCharge(), v.getState()))
			
BatteryHistory().show(parser.parse_args())
