#!/usr/bin/env python3
"Request battery charge history from upowerd"
import argparse, datetime
import dbus

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Print events")

class Span:
    def __init__(self, start):
        self.start = start
        self.end = None
        self.notStart = []

class BatteryHistory:
    @staticmethod
    def getTs(v):
        return v[0]

    @staticmethod
    def getCharge(v):
        return v[1]

    @staticmethod
    def getState(v):
        try:
            return [
                "Unknown", "Charging", "Discharging", "Empty",
                "Fully charged", "Pending charge", "Pending discharge"
            ][v[2]]
        except IndexError:
            return v[2]
        
    def show(self, args):
        bus = dbus.SystemBus()
        self.battery = bus.get_object(
            'org.freedesktop.UPower',
            '/org/freedesktop/UPower/devices/battery_BAT0')
        self.getHistory = self.battery.get_dbus_method(
            'GetHistory',
            'org.freedesktop.UPower.Device')
        events = self.getHistory("charge", 0, 0)
        c = 0
        self.falls = []
        for v in sorted(events, key=self.getTs):
            if self.getCharge(v) > c:
                if not self.falls or self.falls[-1].end:
                    self.falls.append(Span(v))
                self.falls[-1].start = v
            else:
                self.falls[-1].end = v
                self.falls[-1].notStart.append(v)
            c = self.getCharge(v)
        for s in self.falls:
            print("%s: %3.1f => %3.1f in %s" % (
                datetime.datetime.fromtimestamp(
                    self.getTs(s.start)).ctime(),
                self.getCharge(s.start),
                self.getCharge(s.end or s.start),
                datetime.timedelta(seconds=
                    self.getTs(s.end or s.start) - self.getTs(s.start))))
            if args.verbose:
                for v in [s.start] + s.notStart:
                    print(" %s: %3.1f %s" % (
                        datetime.datetime.fromtimestamp(self.getTs(v)),
                        self.getCharge(v), self.getState(v)))
            
BatteryHistory().show(parser.parse_args())
