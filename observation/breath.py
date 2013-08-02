# perf script event handlers, generated by perf script -g python
# Licensed under the terms of the GNU GPL License version 2

# The common_* event handler fields are the most useful fields common to
# all events.  They don't necessarily correspond to the 'common_*' fields
# in the format files.  Those fields not available as handler params can
# be retrieved using Python functions of the form common_*(context).
# See the perf-trace-python Documentation for the list of available functions.

import os
import sys

print os.environ['PERF_EXEC_PATH']

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

import re
sz_pattern = re.compile("[\x20-\xFF]+")

import pwd

def get_sz(pid, addr):
				try:
								m = open("/proc/%u/mem" % (pid))
								m.seek(addr)
								b = m.read(256)
								s = sz_pattern.match(b)
								return s and s.group(0)
				except Exception as e:
								return e

def get_username(pid):
				s = os.stat("/proc/%u/" % (pid))
				uid = s.st_uid
				return pwd.getpwuid(uid)[0]
				

def trace_begin():
	print "in trace_begin"

def trace_end():
	print "in trace_end"

def need(comm):
				return "smbd" == comm
				if "perf" == comm: return False
				return True
				

def syscalls__sys_enter_openat(event_name, context, common_cpu,
															 common_secs, common_nsecs, common_pid, common_comm,
															 nr, dfd, filename, flags, 
															 mode):

				if not need(common_comm): return

				print_header(event_name, common_cpu, common_secs, common_nsecs,
										 common_pid, common_comm)

				print "dfd=%u, filename=%s, " \
						"flags=%u, mode=%u\n" % \
						(dfd, get_sz(common_pid, filename), flags, 
						 mode),

def syscalls__sys_enter_open(event_name, context, common_cpu,
														 common_secs, common_nsecs, common_pid, common_comm,
														 nr, filename, flags, mode):
				if not need(common_comm): return

				print_header(event_name, common_cpu, common_secs, common_nsecs,
										 common_pid, common_comm)

				print "filename=%s, flags=%u, " \
						"mode=%u\n" % \
						(get_sz(common_pid, filename), flags, mode),

def trace_unhandled(event_name, context, event_fields_dict):
		print ' '.join(['%s=%s'%(k,str(v))for k,v in sorted(event_fields_dict.items())])

def print_header(event_name, cpu, secs, nsecs, pid, comm):
				print "%-20s %8u %-20s %s" % (event_name, pid, comm, 
																			get_username(pid)),
