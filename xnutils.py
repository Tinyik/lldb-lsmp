""" Utility functions for XNU
		@Author   	-  	Ian Fang 	

		July 30, 2018
"""

import lldb
import re


# DONOTCHANGE: /osfmk/mach/port.h
MACH_PORT_NULL				= 0x00000000
MACH_PORT_TYPE_SEND 		= 0x00010000
MACH_PORT_TYPE_RECEIVE 		= 0x00020000
MACH_PORT_TYPE_SEND_ONCE 	= 0x00040000
MACH_PORT_TYPE_DEAD_NAME 	= 0x00100000

SIZE_OF_IPC_ENTRY = 0x18

# Cache for lldb.type conversion
_str_to_sbtype_cache = {}

def task_for_pid(target_pid):
	""" Return the task corresponds to TARGET_PID.
		params:
			target_pid         - int
		
		returns:
			task               - lldb.SBValue      the task if one exist, 
												   otherwise an error is printed to console.
	"""
	task_queue = lldb.debugger.GetSelectedTarget().FindFirstGlobalVariable('tasks')
	task_ptr_type = getsbtype('struct task *')

	for task in iterate_queue(task_queue, task_ptr_type, 'tasks'):
		p_pid = task_get_p_pid(task)
		if p_pid == target_pid:
			return task


def task_get_p_pid(target_task):
	""" Return the p_pid of TARGET_TASK's wrapper proc.
		params:
			target_task 		- lldb.SBValue

		returns:
			p_pid 				- int
	"""
	bsd_info_void_ptr = target_task.GetChildMemberWithName('bsd_info')
	proc_ptr_type = getsbtype('struct proc *')
	proc = bsd_info_void_ptr.Cast(proc_ptr_type)

	p_pid = proc.GetChildMemberWithName('p_pid').GetValueAsUnsigned()
	return p_pid


def task_get_p_name(target_task):
	""" Return the p_name of TARGET_TASK's wrapper proc.
		assumes:
			TARGET_TASK is not NULL.

		params:
			target_task 		- lldb.SBValue

		returns:
			p_name 				- str
	""" 
	bsd_info_void_ptr = target_task.GetChildMemberWithName('bsd_info')
	proc_ptr_type = getsbtype('struct proc *')
	proc = bsd_info_void_ptr.Cast(proc_ptr_type)
	p_name = proc.GetChildMemberWithName('p_name').GetSummary().strip('"')
	return p_name


def port_get_receiver_info(target_port):
	""" Return the p_pid and p_name that owns the receive right to TARGET_PORT.
		params:
			target_port 				- lldb.SBValue

		returns:
			(receiver_proc_pid, 		- int
			 receiver_proc_name,		- str
			 receiver_task     )		- lldb.SBValue
	"""
	receiver_itk_space = target_port.GetChildMemberWithName('data').GetChildMemberWithName('receiver')
	itk_space_addr = receiver_itk_space.GetValueAsUnsigned()
	ipc_space_kernel = lldb.debugger.GetSelectedTarget().FindFirstGlobalVariable('ipc_space_kernel')
	ipc_space_reply  = lldb.debugger.GetSelectedTarget().FindFirstGlobalVariable('ipc_space_reply')

	if itk_space_addr == ipc_space_kernel.GetValueAsUnsigned():
		receiver_proc_pid = 0
		receiver_proc_name = 'ipc_space_kernel'
		receiver_task = None
	elif itk_space_addr == ipc_space_reply.GetValueAsUnsigned():
		receiver_proc_pid = 0
		receiver_proc_name = 'ipc_space_reply'
		receiver_task = None
	else:
		receiver_task = receiver_itk_space.GetChildMemberWithName('is_task')
		if receiver_task.GetValueAsUnsigned() == 0:
			print receiver_itk_space
			print '[port_get_receiver_info]: Weird space %x has no task, adding a placeholder task...' % itk_space_addr
			receiver_task = None
			receiver_proc_pid = -1
			receiver_proc_name = 'N/A'
		else:
			receiver_proc_pid = task_get_p_pid(receiver_task)
			receiver_proc_name = task_get_p_name(receiver_task)

	return (receiver_proc_pid, receiver_proc_name, receiver_task)


def task_get_ith_ipc_entry(target_task, index):
	""" Return the INDEX-th ipc_entry in TARGET_TASK's itk_space.
		params:
			target_task 		- lldb.SBValue
			index 				- int

		returns:
			ipc_entry 			- lldb.SBValue

		throws:
			IndexError			- If index is out of bound.
	"""
	itk_space = target_task.GetChildMemberWithName('itk_space')
	is_table_size = itk_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()
	is_table = itk_space.GetChildMemberWithName('is_table')

	if index >= is_table_size:
		raise IndexError("Index must be less than is_table_size.")
	if index <= 0:
		raise IndexError("Index must be positive. 0 is reserved for sentinel node.")

	ith_ipc_entry_addr = is_table.GetValueAsUnsigned() + index * SIZE_OF_IPC_ENTRY
	ith_ipc_entry_sbaddr = lldb.SBAddress(ith_ipc_entry_addr, lldb.debugger.GetSelectedTarget())
	ipc_entry_type = getsbtype("struct ipc_entry")
	ipc_entry = lldb.debugger.GetSelectedTarget().CreateValueFromAddress('ith_entry', ith_ipc_entry_sbaddr, ipc_entry_type)

	return ipc_entry


def task_get_ith_ipc_port(target_task, index):
	""" Return the INDEX-th ipc_port in TARGET_TASK's itk_space.
		params:
			target_task 		- lldb.SBValue
			index 				- int

		returns:
			ipc_port 			- lldb.SBValue

		throws:
			IndexError			- If index is out of bound.
	"""
	ipc_entry = task_get_ith_ipc_entry(target_task, index)
	ipc_port_ptr_type = getsbtype('struct ipc_port *')
	ipc_port = ipc_entry.GetChildMemberWithName('ie_object').Cast(ipc_port_ptr_type)

	return ipc_port


def port_find_right(target_port, disposition=None):
	""" Return the p_pid and p_name that has reference to TARGET_PORT with disposition bitmap DISPOSITION
		params:
			target_port 				- lldb.SBValue
			disposition 				- bitmap 				If None, no restriction on disposition,
																and thus all references to TARGET_PORT are returned.
																
		returns:
			(proc_pids, 				- list of int          
			 proc_names,				- list of str
			 proc_ie_bits)				- list of int
	"""
	proc_pids 		= []
	proc_names 		= []
	entry_ie_bits 	= []
	entry_indices	= []

	target_port_addr = target_port.GetValueAsUnsigned()

	# If dispostion is just MACH_PORT_TYPE_RECEIVE, we take the fast path
	if disposition == MACH_PORT_TYPE_RECEIVE:
		receiver_pid, receiver_proc_name, receiver_task = port_get_receiver_info(target_port)
		for entry in task_iterate_ipc_entry(receiver_task, MACH_PORT_TYPE_RECEIVE):
			port = port_entry_get_port(entry)
			if port.GetValueAsUnsigned() == target_port_addr:
				proc_pids.append(receiver_pid)
				proc_names.append(receiver_proc_name)
				entry_ie_bits.append(port_entry_get_ie_bits(entry))
				entry_indices.append(entry.GetChildMemberWithName('index').GetValueAsUnsigned())
				break

		return (proc_pids, proc_names, entry_ie_bits, entry_indices)

	task_queue = lldb.debugger.GetSelectedTarget().FindFirstGlobalVariable('tasks')
	task_ptr_type = getsbtype('struct task *')

	for task in iterate_queue(task_queue, task_ptr_type, 'tasks'):
		for entry in task_iterate_ipc_entry(task, disposition):
			port = port_entry_get_port(entry)
			if port.GetValueAsUnsigned() == target_port_addr:
				proc_pids.append(task_get_p_pid(task))
				proc_names.append(task_get_p_name(task))
				entry_ie_bits.append(port_entry_get_ie_bits(entry))
				entry_indices.append(entry.GetChildMemberWithName('ie_index').GetValueAsUnsigned())

	return (proc_pids, proc_names, entry_ie_bits, entry_indices)


def task_iterate_ipc_entry(target_task, disposition=None):
	""" Iterate over all ipc_entry in TARGET_TASK with port type DISPOSITION.
		params:
			target_task 		- lldb.SBValue
			disposition 		- bitmap               If None, no restriction on port disposition

		yields:
			A lldb.SBValue generator with SBType <struct ipc_entry *>.
	"""
	ipc_space = target_task.GetChildMemberWithName('itk_space')
	is_table_size = ipc_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()
	is_table = ipc_space.GetChildMemberWithName('is_table')

	cur_index = 0
	while cur_index < is_table_size:
		ith_ipc_entry_addr = is_table.GetValueAsUnsigned() + cur_index * SIZE_OF_IPC_ENTRY
		ith_ipc_entry_sbaddr = lldb.SBAddress(ith_ipc_entry_addr, lldb.debugger.GetSelectedTarget())
		ipc_entry_type = getsbtype("struct ipc_entry")
		ipc_entry = lldb.debugger.GetSelectedTarget().CreateValueFromAddress('ith_entry', ith_ipc_entry_sbaddr, ipc_entry_type)

		cur_index += 1

		# First entry of is_table is a sentinel node with ie_bits 0xff000000 and thus will not be yielded
		if disposition == None or port_entry_contains_disposition(ipc_entry, disposition):
			yield ipc_entry


def task_iterate_ipc_port(target_task, dispostion=None):
	""" Iterate over all ipc_port in TARGET_TASK with port type DISPOSITION.
		params:
			target_task 		- lldb.SBValue
			disposition 		- bitmap               If None, no restriction on port disposition

		yields:
			A lldb.SBValue generator with SBType <struct ipc_port *>.
	"""
	for entry in task_iterate_ipc_entry(target_task, dispostion):
		ipc_port_ptr_type = getsbtype('struct ipc_port *')
		ipc_port = entry.GetChildMemberWithName('ie_object').Cast(ipc_port_ptr_type)
		yield ipc_port


def port_entry_get_ie_bits(target_entry):
	""" Return the ie_bits on ie_entry TARGET_ENTRY.
		params:
			target_entry 		- lldb.SBValue

		returns:
			ie_bits 			- int
	"""
	ie_bits = target_entry.GetChildMemberWithName('ie_bits').GetValueAsUnsigned()

	return ie_bits


def port_entry_get_port(target_entry):
	""" Get mach port inside TARGET_ENTRY
		params:
			target_entry 		- lldb.SBValue

		returns:
			port 				- lldb.SBValue
	"""
	ipc_port_ptr_type = getsbtype('struct ipc_port *')
	port = target_entry.GetChildMemberWithName('ie_object').Cast(ipc_port_ptr_type)

	return port

def ie_bits_get_disposition_str(ie_bits):
	""" Convert IE_BITS to a human readable disposition string
		params:
			ie_bits 		    - int

		returns:
			disp_str 			- str
	"""
	disp_str = ''

	if ie_bits & MACH_PORT_TYPE_RECEIVE:
		disp_str = disp_str + ' RCV '
	if ie_bits & MACH_PORT_TYPE_SEND:
		disp_str = disp_str + ' SEND '
	if ie_bits & MACH_PORT_TYPE_SEND_ONCE:
		disp_str = disp_str + ' SONCE '
	if ie_bits & MACH_PORT_TYPE_DEAD_NAME:
		disp_str = disp_str + ' DEAD '

	if disp_str is '':
		disp_str = ' OTHER '

	return disp_str


def port_entry_contains_disposition(target_entry, dispostion):
	""" Test if TARGET_ENTRY has ONE OF the dispostion specified in bitmap DISPOSITION.
		For testing exact match, use PORT_ENTRY_MATCHES_DISPOSITION()
		params:
			target_entry 		- lldb.SBValue
			disposition 		- bitmap

		returns:
			result				- Bool
	"""
	ie_bits = target_entry.GetChildMemberWithName('ie_bits').GetValueAsUnsigned()

	return (ie_bits & dispostion) != 0


def port_entry_matches_disposition(target_entry, dispostion):
	""" Test if TARGET_ENTRY matches dispostion specified in bitmap DISPOSITION.
		params:
			target_entry 		- lldb.SBValue
			disposition 		- bitmap
		
		returns:
			result				- Bool
	"""
	ie_bits = target_entry.GetChildMemberWithName('ie_bits').GetValueAsUnsigned()

	return (ie_bits ^ dispostion) == 0


def iterate_queue(queue_head, entry_type, entry_field_name):
	""" Iterate over a queue_head_t.
		params:
			queue_head 		   	- lldb.SBValue
			entry_type	   		- lldb.SBType
			entry_field_name	- str

		yields:
			A lldb.SBValue generator with SBType <struct ENTRY_TYPE>.
	"""

	queue_head_addr = 0x0
	if queue_head.TypeIsPointerType():
		queue_head_addr = queue_head.GetValueAsUnsigned()
	else:
		queue_head_addr = queue_head.GetAddress().GetLoadAddress(lldb.debugger.GetSelectedTarget())

	cur_entry = queue_head.GetChildMemberWithName('next')

	while cur_entry.GetValueAsUnsigned() != queue_head_addr and cur_entry.GetValueAsUnsigned() != 0:
		cur_entry = cur_entry.Cast(entry_type)
		yield cur_entry
		cur_entry = cur_entry.GetChildMemberWithName(entry_field_name).GetChildMemberWithName('next')


def getsbtype(target_type):
	""" Convert a type string TARGET_TYPE to lldb.SBType.
		params:
			target_type		- str

		returns:
			A lldb.SBType if one exists otherwise a NameError is raised.

		throws:
			NameError		- If type cannot be found or casting cannot be completed
	"""
	global _str_to_sbtype_cache
	target_type = target_type.strip()

	if target_type in _str_to_sbtype_cache:
		return _str_to_sbtype_cache[target_type]

	type_is_struct = False
	m = re.match(r'\s*struct\s*(.*)$', target_type)
	if m:
		type_is_struct = True
		target_type = m.group(1)

	tmp_type = None
	type_is_pointer = False
	if target_type.endswith('*'):
		type_is_pointer = True

	search_type = target_type.rstrip('*').strip()

	type_arr = [t for t in lldb.debugger.GetSelectedTarget().FindTypes(search_type)]

	if type_is_struct:
		type_arr = [t for t in type_arr if t.type == lldb.eTypeClassStruct]

	# After the sort, the struct type with more fields will be at index [0].
	# This hueristic helps selecting struct type with more fields compared to ones with "opaque" members
	type_arr.sort(reverse=True, key=lambda x: x.GetNumberOfFields())
	if len(type_arr) > 0:
		tmp_type = type_arr[0]
	else:
		raise NameError("Unable to find type "+target_type)

	if not tmp_type.IsValid():
		raise NameError("Unable to Cast to type "+target_type)

	if type_is_pointer:
		tmp_type = tmp_type.GetPointerType()

	_str_to_sbtype_cache[target_type] = tmp_type

	return _str_to_sbtype_cache[target_type]

