
""" implementation for lldb kernel debugging script lsmp

		@Author     -   Ian Fang    

		July 30, 2018
"""

import lldb
import argparse
from functools import wraps
from xnutils import *


target = None

def print_header(header):
	""" Higher order function for printing formatted output to console."""
	def _print_header(func):
		@wraps(func)
		def __print_line(*args, **kwargs):
			print_format, lines, ret = func(*args, **kwargs)
			if lines is None or print_format is None:
				return 
			print header
			for line in lines:
				print print_format.format(*line)
			return ret
		return __print_line
	return _print_header


class ListMachPort:

	lldb_command = 'lsmp'

	def __init__(self, debugger, internal_dic):
		pass


	def __call__(self, debugger, command, exe_ctx, result):
		args = ListMachPort.parser.parse_args(command.split())
		
		target_pid, mpindex, count = args.pid, args.mpindex, args.count

		disposition     = args.show_receive 		   | 			\
						  args.show_send 		   	   | 			\
						  args.show_send_once          | 			\
						  args.show_dead

		if disposition == 0:
			disposition = MACH_PORT_TYPE_ALL

		# struct task *, not task port
		task = task_for_pid(target_pid)

		if task is None:
			print "Cannot find process with pid %d" % target_pid
			exit(-1)

		if mpindex is None:
			self.task_list_mach_port(task, disposition, count)
			return

		ipc_port = None
		try:
			ipc_port = task_get_ith_ipc_port(task, mpindex)
		except IndexError as e:
			print e
			return

		self.port_show_details(ipc_port, disposition, count)


	@print_header("{0: >5s}   {1: <30s} {2: <30s} {3: <20s} {4: <50s} {5: <15s} {6: <15s}".\
		format('index', 'ie_bits', 'disposition', 'receiver_pid', 'receiver_name', 'ip_srights', 'ip_sorights'))
	def task_list_mach_port(self, target_task, disposition, count):
		""" List mach ports with ONE OF disposition which TARGET_TASK holds a reference to.
			params:
				target_task         - lldb.SBValue
				disposition 		- bitmap
				count 				- Bool  				If true, only count totals and don't list details.

			prints:
				index               = Index into is_table
				ie_bits
				disposition
				receiver_pid
				receiver_name
				ip_srights
				ip_sorights
		"""
		if count:
			count_rcv = count_send = count_sonce = count_dead = count_null = count_rcv_send = 0

		lines = []
		# lines.append((0, 0xff000000, ' N/A ', -1, 'N/A (Sentinel entry)', -1, -1))

		for entry, index in task_iterate_ipc_entry(target_task, disposition):
			ie_bits = port_entry_get_ie_bits(entry)

			port = port_entry_get_port(entry)

			if port.GetValueAsUnsigned() == MACH_PORT_NULL:
				if count:
					count_null += 1
				continue

			if count:
				if ie_bits & (MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_SEND) == (MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_SEND):
					count_rcv_send += 1
				elif ie_bits & MACH_PORT_TYPE_RECEIVE:
					count_rcv      += 1
				elif ie_bits & MACH_PORT_TYPE_SEND:
					count_send     += 1
				elif ie_bits & MACH_PORT_TYPE_SEND_ONCE:
					count_sonce    += 1
				elif ie_bits & MACH_PORT_TYPE_DEAD_NAME:
					count_dead     += 1
			else:
				disp = ie_bits_get_disposition_str(ie_bits)

				srights = port.GetChildMemberWithName('ip_srights').GetValueAsUnsigned()
				sorights = port.GetChildMemberWithName('ip_sorights').GetValueAsUnsigned()
				receiver_pid, receiver_name, _ = port_get_receiver_info(port)
				lines.append((index, ie_bits, disp, receiver_pid, receiver_name, srights, sorights))

		if count:

			print_count_results(disposition, count_rcv_send, count_rcv, count_dead, count_sonce, count_null=count_null)

			itk_space = target_task.GetChildMemberWithName('itk_space')
			is_table_size = itk_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()
			print "# ipc_space size: %d" % is_table_size  # 0th entry is sentinel
			return None, None, None
		else:
			print_format = "{0: >5d}   0x{1: <28x} {2: <30s} {3: <20d} {4: <50s} {5: <15d} {6: <15d}"
			return print_format, lines, None


	@print_header("{0: >5s}   {1: <10s} {2: <50s} {3: <30s} {4: <30s} {5: <30s}".\
		format('#', 'pid', 'name', 'ie_bits', 'disposition', 'ie_index'))
	def port_show_details(self, target_port, disposition, count):
		""" Output details about TARGET_PORT
			params:
				target_port         - lldb.SBValue
				disposition         - bitmap
				count 				- Bool  				If true, only count totals and don't list details.

			prints:
				pid
				name
				ie_bits
				disposition
				entry_index
		"""
		proc_pid, proc_name, ie_bits, indices = port_find_right(target_port, disposition)

		if count:
			count_rcv = count_send = count_sonce = count_dead = count_rcv_send = 0

			for bits in ie_bits:
				if bits & (MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_SEND) == (MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_SEND):
					count_rcv_send += 1
				elif bits & MACH_PORT_TYPE_RECEIVE:
					count_rcv 	   += 1
				elif bits & MACH_PORT_TYPE_SEND:
					count_send 	   += 1
				elif bits & MACH_PORT_TYPE_SEND_ONCE:
					count_sonce    += 1
				elif bits & MACH_PORT_TYPE_DEAD_NAME:
					count_dead     += 1

			print_count_results(disposition, count_rcv_send, count_rcv, count_dead, count_sonce)

			return None, None, None

		else:
			disp_strs = []

			for bits in ie_bits:
				disp_str = ie_bits_get_disposition_str(bits)
				disp_strs.append(disp_str)

			print_format = "{0: >5d}   {1: <10d} {2: <50s} 0x{3: <28x} {4: <30s} {5: <30d}"
			lines = zip(range(1, len(proc_pid)+1), proc_pid, proc_name, ie_bits, disp_strs, indices)
			
			return print_format, lines, None


	# 											------------------ 											   #
	###################							 HELPER FUNCTIONS							 ###################
	#											------------------           								   #


	@print_header("----------\nCount:")
	def print_count_results(disposition, count_rcv_send, count_rcv, count_dead, count_sonce, count_null=None):
		total = 0

		if disposition & MACH_PORT_TYPE_SEND_ONCE:
			print "# of SEND ONCE rights: %d" % count_sonce
			total += count_sonce
		if disposition & MACH_PORT_TYPE_DEAD_NAME:
			print "# of DEAD rights: %d" % count_dead
			total += count_dead
		if disposition & MACH_PORT_TYPE_RECEIVE:
			print "# of RECEIVE rights: %d" % count_rcv
			total += count_rcv
		if disposition & MACH_PORT_TYPE_SEND:
			print "# of SEND rights: %d" % count_send
			total += count_send
		if disposition & MACH_PORT_TYPE_SEND or disposition & MACH_PORT_TYPE_RECEIVE:
			print "# of SEND_RECEIVE rights: %d" % count_rcv_send
			total += count_rcv_send
		if disposition == MACH_PORT_TYPE_ALL and count_null is not None:
			print "# of NULL ports: %d" % count_null
			total += count_null

		print '------------------'
		print "# Total: %d" % total

		return None, None, total


	@classmethod
	def register_with_lldb(cls, debugger, module):
		cls.parser = cls.create_parser()
		command = 'command script add -c %s.%s %s' % (module, 
													  cls.__name__, 
													  cls.lldb_command)
		debugger.HandleCommand(command)
		print('The %s command has been installed.' % cls.lldb_command)


	@classmethod
	def create_parser(cls):
		parser = argparse.ArgumentParser(description="Query information about mach ports", prog='lsmp')

		parser.add_argument('pid',
							type=lambda x: int(x, 0),			# auto base detection to allow hex input
							help='the pid of the process'
							)

		parser.add_argument('-i',
							'--index',
							dest='mpindex',
							type=lambda x: int(x, 0),			# ditto
							help='the index of the mach port'
							)

		parser.add_argument('--RCV',
							dest='show_receive',
							action='store_const',
							const=MACH_PORT_TYPE_RECEIVE,
							default=0,
							help='include RECEIVE right'
							)

		parser.add_argument('--SONCE',
							dest='show_send_once',
							action='store_const',
							const=MACH_PORT_TYPE_SEND_ONCE,
							default=0,
							help='include SEND_ONCE right'
							)

		parser.add_argument('--SEND',
							dest='show_send',
							action='store_const',
							const=MACH_PORT_TYPE_SEND,
							default=0,
							help='include SEND right'
							)

		parser.add_argument('--DEAD',
							dest='show_dead',
							action='store_const',
							const=MACH_PORT_TYPE_DEAD_NAME,
							default=0,
							help='include DEAD_NAME right'
							)

		parser.add_argument('-c',
							'--count',
							dest='count',
							action='store_true',
							default=False,
							help='if specified, only output the count'
							)

		return parser




def __lldb_init_module(debugger, internal_dic):
	""" lldb `command script import` auto invoke"""
	global target
	target = debugger.GetSelectedTarget()

	ListMachPort.register_with_lldb(debugger, __name__)

	