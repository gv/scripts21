#!/usr/bin/env python3
"Manipulate kernel scancode translation table or trace USB keyboard events"
import sys, argparse, ctypes, fcntl

bpfText="""
// For struct hid_usage
#include <linux/hid.h>

// Can have only primitive types. Nested structures not allowed
struct data {
unsigned type;
unsigned scancode;
unsigned keycode;
s32 value;
};

BPF_PERF_OUTPUT(events);

int on_hid_p_e(struct pt_regs *ctx, struct hid_device *hid, 
  struct hid_field *field, struct hid_usage *usage, s32 value)
{
  struct data data = {usage->type, usage->hid, usage->code, value};
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
"""

class Trace:
    def __init__(self, args):
        self.args = args
        
    def run(self):
        import bcc
        self.b = b = bcc.BPF(text=bpfText)
        b.attach_kprobe(event="hid_process_event", fn_name="on_hid_p_e")
        b["events"].open_perf_buffer(self.print)
        sys.stderr.write("Tracing HID events...\n")
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

    def print(self, cpu, data, size):
        ev = self.b["events"].event(data)
        if self.args.down and ev.value != 1:
            return
        print("type=%d scancode=%d keycode=%d value=%d" % (
            ev.type, ev.scancode, ev.keycode, ev.value))

class ScancodeField(ctypes.Union):
    _fields_ = ("buffer", ctypes.c_ubyte * 32), ("u32", ctypes.c_uint32)

class InputKeymapEntry(ctypes.Structure):
    _fields_ =\
        ("flags", ctypes.c_ubyte),\
        ("len", ctypes.c_ubyte),\
        ("index", ctypes.c_uint16),\
        ("keycode", ctypes.c_uint32),\
        ("scancode", ScancodeField)

if ctypes.sizeof(InputKeymapEntry) != 40:
    raise Exception(
        "sizeof(InputKeymapEntry) = %d" % ctypes.sizeof(InputKeymapEntry))
    
class Keyboard:
    EVIOCGKEYCODE_V2 = 0x80284504
    EVIOCSKEYCODE_V2 = 0x40284504
    
    def __init__(self):
        self.path =\
            "/dev/input/by-id/usb-HAILUCK_CO._LTD_USB_KEYBOARD-event-kbd"
        self.f = open(self.path)

    def printKeycode(self, scancode):
        mem = InputKeymapEntry(len=4)
        mem.scancode.u32 = scancode
        fcntl.ioctl(self.f, self.EVIOCGKEYCODE_V2, mem)
        self.printMapEntry(mem)

    def printMapEntry(self, mem):
        print("scancode=%d keycode=%d" % (mem.scancode.u32, mem.keycode))

    def setKeycode(self, scancode, keycode):
        scancode = int(scancode)
        keycode = int(keycode)
        mem = InputKeymapEntry(len=4)
        mem.scancode.u32 = scancode
        mem.keycode = keycode
        fcntl.ioctl(self.f, self.EVIOCSKEYCODE_V2, mem)
        self.printMapEntry(mem)

    def setupSysrq(self):
        path = "/proc/sys/kernel/sysrq"
        target = "1"
        old = open(path).read().strip()
        open(path, "w").write(target)
        if old != target:
            print("Changed %s from '%s' to '%s'" % (path, old, target))
        # Japanese key => Sysrq
        self.setKeycode(458805, 99)
        # Fix "`"
        self.setKeycode(458889, 41)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--get", "-g", help="Convert scancode to 'keycode'")
parser.add_argument(
    "--set", "-s", nargs=2, help="Args: SCANCODE KEYCODE")
parser.add_argument(
    "--trace", action="store_true", help="Print input events")
parser.add_argument(
    "--down", action="store_true",
    help="Don't print key release events")
parser.add_argument(
    "--sysrq", action="store_true",
    help="Set up Sysrq key on GPD Pocket 2 keyboard (Japanese firmware)")

args = parser.parse_args()
if args.get:
    Keyboard().printKeycode(int(args.get))
elif args.set:
    Keyboard().setKeycode(*args.set)
elif args.sysrq:
    Keyboard().setupSysrq()
elif args.trace or args.down:
    Trace(args).run()
else:
    parser.usage()