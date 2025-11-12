#!/usr/bin/env python3
"""
Script for mouse click latency measurement
Usage: sudo python3 mousetrace.py
"""

from bcc import BPF
import os, sys, time

class MousePressTracer:
	"""eBPF tracer for mouse button presses"""

	BPF_PROGRAM = r"""
		#include <linux/input.h>
		#include <linux/sched.h>		// TASK_COMM_LEN

		struct event {
				u64 uptime_us, latency_us;
				u32 pid;
				char comm[TASK_COMM_LEN];
				u8 source;							// 0 = kernel, 1 = user
		};

		BPF_PERF_OUTPUT(events);

    BPF_ARRAY(last_kernel_time, u64, 1);

		// kprobe handler
		int kprobe__input_event(struct pt_regs *ctx, struct input_dev *dev,
														unsigned int type, unsigned int code, int value)
		{
				if (type != EV_KEY)
						return 0;
				if (value != 1)
						return 0;
				if (code != BTN_LEFT && code != BTN_RIGHT && code != BTN_MIDDLE)
						return 0;

				struct event evt = {};
				evt.uptime_us = bpf_ktime_get_ns() / 1000;
				evt.pid = 0;
				evt.comm[0] = '\0';
				evt.source = 0;
        u64 ns = bpf_ktime_get_ns();
        u32 idx = 0;
        last_kernel_time.update(&idx, &ns);

				events.perf_submit(ctx, &evt, sizeof(evt));
				return 0;
		}

typedef enum
{
	GDK_NOTHING		= -1,
	GDK_DELETE		= 0,
	GDK_DESTROY		= 1,
	GDK_EXPOSE		= 2,
	GDK_MOTION_NOTIFY = 3,
	GDK_BUTTON_PRESS	= 4,
	GDK_2BUTTON_PRESS = 5,
	GDK_DOUBLE_BUTTON_PRESS = GDK_2BUTTON_PRESS,
	GDK_3BUTTON_PRESS = 6,
	GDK_TRIPLE_BUTTON_PRESS = GDK_3BUTTON_PRESS,
	GDK_BUTTON_RELEASE	= 7,
	GDK_KEY_PRESS		= 8,
	GDK_KEY_RELEASE = 9,
	GDK_ENTER_NOTIFY	= 10,
	GDK_LEAVE_NOTIFY	= 11,
	GDK_FOCUS_CHANGE	= 12,
	GDK_CONFIGURE		= 13,
	GDK_MAP		= 14,
	GDK_UNMAP		= 15,
	GDK_PROPERTY_NOTIFY = 16,
	GDK_SELECTION_CLEAR = 17,
	GDK_SELECTION_REQUEST = 18,
	GDK_SELECTION_NOTIFY	= 19,
	GDK_PROXIMITY_IN	= 20,
	GDK_PROXIMITY_OUT = 21,
	GDK_DRAG_ENTER				= 22,
	GDK_DRAG_LEAVE				= 23,
	GDK_DRAG_MOTION				= 24,
	GDK_DRAG_STATUS				= 25,
	GDK_DROP_START				= 26,
	GDK_DROP_FINISHED			= 27,
	GDK_CLIENT_EVENT	= 28,
	GDK_VISIBILITY_NOTIFY = 29,
	GDK_SCROLL						= 31,
	GDK_WINDOW_STATE			= 32,
	GDK_SETTING						= 33,
	GDK_OWNER_CHANGE			= 34,
	GDK_GRAB_BROKEN				= 35,
	GDK_DAMAGE						= 36,
	GDK_TOUCH_BEGIN				= 37,
	GDK_TOUCH_UPDATE			= 38,
	GDK_TOUCH_END					= 39,
	GDK_TOUCH_CANCEL			= 40,
	GDK_TOUCHPAD_SWIPE		= 41,
	GDK_TOUCHPAD_PINCH		= 42,
	GDK_PAD_BUTTON_PRESS	= 43,
	GDK_PAD_BUTTON_RELEASE = 44,
	GDK_PAD_RING					= 45,
	GDK_PAD_STRIP					= 46,
	GDK_PAD_GROUP_MODE		= 47,
	GDK_EVENT_LAST				/* helper variable for decls */
} GdkEventType;

		struct _GdkEventButton
		{
		GdkEventType type;
		/* ... */
		};


		// uprobe handler (user-level GTK/GDK)
		int trace_gdk_event(struct pt_regs *ctx, struct _GdkEventButton *ev)
		{
				if (ev->type != GDK_BUTTON_PRESS) return 0;

				struct event evt = {};

				evt.uptime_us = bpf_ktime_get_ns() / 1000;
        u32 idx = 0;
        u64 *last = last_kernel_time.lookup(&idx);
        if (last) 
evt.latency_us = (bpf_ktime_get_ns() - *last)/1000;
            else
                evt.latency_us = 0;

				// pid: tgid is upper 32 bits
				u64 pid_tgid = bpf_get_current_pid_tgid();
				evt.pid = pid_tgid >> 32;

				bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
				evt.source = 1;

				events.perf_submit(ctx, &evt, sizeof(evt));
				return 0;
		}
		"""

	def __init__(self):
		self.libPaths = None
		self.bpf = None
		self.startTime = time.time()
		# header printed flag
		self._printedHeader = False

	def findLibPaths(self):
		candidates = [
				"/usr/lib/x86_64-linux-gnu/libgtk-3.so.0",
				"/usr/lib64/libgtk-3.so.0",
				"/usr/lib/libgtk-3.so.0",
#				"/usr/lib/x86_64-linux-gnu/libgtk-4.so.1",
#				"/usr/lib64/libgtk-4.so.1",
#				"/usr/lib/libgtk-4.so.1",
		]
		self.libPaths = [x for x in candidates if os.path.exists(x)]

	def loadProgram(self):
		print("Compiling BPF...")
		self.bpf = BPF(text=self.BPF_PROGRAM)
		# BCC will auto-attach kprobe functions named kprobe__<sym>
		self.findLibPaths()
		if not self.libPaths:
			raise FileNotFoundError("Could not find libgtk shared library")

		for path in self.libPaths:
			self.bpf.attach_uprobe(
				name=path, sym="gtk_main_do_event", fn_name="trace_gdk_event")

	def _printHeader(self):
		print("------------------------------------------------------------")
		print("Attached:")
		print("  • kprobe -> input_event (kernel)")
		for path in self.libPaths:
			print(f"  • uprobe -> {path}")
		print("Press Ctrl-C to exit.")
		print("------------------------------------------------------------")
		print(f"{'TIME':<19} {'SOURCE':<6} {'PID':<6} {'COMM':<20} {'UPTIME(us)':>12}	 {'LATENCY':<10}")
		print("-" * 80)
		self._printedHeader = True

	def _handleEvent(self, cpu, data, size):
		"""Perf buffer callback. 'data' is a pointer to the struct event bytes."""
		evt = self.bpf["events"].event(data)

		comm = evt.comm.decode('utf-8', 'replace') if\
			isinstance(evt.comm, bytes) else evt.comm

		t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
		if evt.source == 0:
			print(f"{t:<19} {'KERN':<6} {'-':<6} {'-':<20} {evt.uptime_us:>12}\
{'-':>8}")
		else:
			# user event: show pid and comm
			print(
				f"{t:<19} {'USER':<6} {evt.pid:<6} {comm:<20} {evt.uptime_us:>12}	\
{evt.latency_us:>8}")

	def runTracer(self):
		self._printHeader()
		# Open perf buffer and set callback
		self.bpf["events"].open_perf_buffer(self._handleEvent)
		
		try:
			while True:
				# poll with timeout in ms
				self.bpf.perf_buffer_poll(timeout=1000)
		except KeyboardInterrupt:
			print("\nDetaching... done.")
		except Exception as e:
			print(f"\nError while polling perf buffer: {e}", file=sys.stderr)

if __name__ == "__main__":
	tracer = MousePressTracer()
	try:
		tracer.loadProgram()
		tracer.runTracer()
	except Exception as e:
		print("Error:", e, file=sys.stderr)
		sys.exit(1)
