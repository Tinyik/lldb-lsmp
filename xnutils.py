""" Utility functions for XNU
		@Author   	-  	Ian Fang 	

		July 30, 2018
"""

import lldb
import re


# DONOTCHANGE: /osfmk/mach/port.h
MACH_PORT_RIGHT_SEND = 0
MACH_PORT_RIGHT_RECEIVE = 1
MACH_PORT_RIGHT_SEND_ONCE = 2
MACH_PORT_RIGHT_DEAD_NAME = 4

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
        if proc and p_pid == target_pid:
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
		params:
			target_task 		- lldb.SBValue

		returns:
			p_name 				- str
	"""
	bsd_info_void_ptr = target_task.GetChildMemberWithName('bsd_info')
    proc_ptr_type = getsbtype('struct proc *')
    proc = bsd_info_void_ptr.Cast(proc_ptr_type)

    p_name = proc.GetChildMemberWithName('p_name').GetSummary()
    return p_name


def port_get_receiver(target_port):
	""" Return the p_pid and p_name that owns the receive right to TARGET_PORT.
		params:
			target_port 			- lldb.SBValue

		returns:
			(receiver_proc_pid, 	- int
			 receiver_proc_name)		- str
	"""
    receiver_itk_space = target_port.GetChildMemberWithName('data').GetChildMemberWithName('receiver')

    receiver_task = receiver_itk_space.GetChildMemberWithName('is_task')
    receiver_proc_pid = task_get_p_pid(receiver_task)
    receiver_proc_name = task_get_p_name(receiver_task)

    return (receiver_proc_pid, receiver_proc_name)


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
	ipc_space = target_task.GetChildMemberWithName('itk_space')
    is_table_size = ipc_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()
    is_table = itk_space.GetChildMemberWithName('is_table')

    if index >= is_table_size:
    	raise IndexError("Index greater than is_table_size.")

    ith_ipc_entry_addr = is_table.GetValueAsUnsigned() + index * SIZE_OF_IPC_ENTRY
    ith_ipc_entry_sbaddr = lldb.SBAddress(ith_ipc_entry_addr, target)
    ipc_entry_type = getsbtype("struct ipc_entry")
    ipc_entry = target.CreateValueFromAddress('ith_entry', ith_ipc_entry_sbaddr, ipc_entry_type)

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


def port_find_right(target_port, dispostion=None):
	""" Return the p_pid and p_name that has reference to TARGET_PORT with disposition DISPOSITION
		params:
			target_port 				- lldb.SBValue
			disposition 				- int 					If None, no restriction on disposition,
																and thus all references to TARGET_PORT are returned.
																
		returns:
			(proc_pids, 				- list of int           If disposition is NOT MACH_PORT_RIGHT_RECEIVE
			 proc_names)				- list of str

			(receiver_proc_pid, 		- int 					If disposition is MACH_PORT_RIGHT_RECEIVE
			 receiver_proc_name)		- str
	"""
	if disposition == MACH_PORT_RIGHT_RECEIVE:
		return port_get_receiver(target_port)

	task_queue = lldb.debugger.GetSelectedTarget().FindFirstGlobalVariable('tasks')
    task_ptr_type = getsbtype('struct task *')
    target_port_addr = target_port.GetValueAsUnsigned()

    proc_pids = []
    proc_names = []

    for task in iterate_queue(task_queue, task_ptr_type, 'tasks'):
    	for port in task_iterate_ipc_port(task, disposition):

    		assert(port.GetType().TypeIsPointerType() == True)
    		if port.GetValueAsUnsigned() == target_port_addr:
    			proc_pids.append(task_get_p_pid(task))
    			proc_names.append(task_get_p_name(task))


def task_iterate_ipc_entry(target_task, dispostion=None):
	""" Iterate over all ipc_entry in TARGET_TASK with port type DISPOSITION.
		params:
			target_task 		- lldb.SBValue
			port_type 			- int               If None, no restriction on port disposition

		yields:
			A lldb.SBValue generator with SBType <struct ipc_entry *>.
	"""
	ipc_space = target_task.GetChildMemberWithName('itk_space')
    is_table_size = ipc_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()
    is_table = ipc_space.GetChildMemberWithName('is_table')

    cur_index = 0

    while cur_index < is_table_size:
    	ith_ipc_entry_addr = is_table.GetValueAsUnsigned() + cur_index * SIZE_OF_IPC_ENTRY
    	ith_ipc_entry_sbaddr = lldb.SBAddress(ith_ipc_entry_addr, target)
    	ipc_entry_type = getsbtype("struct ipc_entry")
    	ipc_entry = target.CreateValueFromAddress('ith_entry', ith_ipc_entry_sbaddr, ipc_entry_type)

    	cur_index++
    	if disposition == None or port_get_disposition(ipc_entry) == dispostion:
    		yield ipc_entry
    	else:
    		continue


def task_iterate_ipc_port(target_task, dispostion=None):
	""" Iterate over all ipc_port in TARGET_TASK with port type DISPOSITION.
		params:
			target_task 		- lldb.SBValue
			port_type 			- int               If None, no restriction on port disposition

		yields:
			A lldb.SBValue generator with SBType <struct ipc_port *>.
	"""
 	for entry in task_iterate_ipc_entry(target_task, dispostion):
 		ipc_port_ptr_type = getsbtype('struct ipc_port *')
    	ipc_port = ipc_entry.GetChildMemberWithName('ie_object').Cast(ipc_port_ptr_type)
    	yield ipc_port


def port_get_disposition(ipc_entry):
	""" Get mach port dispostion (type) from its containing IPC_ENTRY.
		params:
			ipc_entry 			- lldb.SBValue
		
		returns:
			right type 			- int
	"""
	ie_bits = ipc_entry.GetChildMemberWithName('ie_bits').GetValueAsUnsigned()

	if (ebits & 0x003f0000) == 0:
        return 0

    if (ebits & 0x00010000) != 0:
        return MACH_PORT_RIGHT_SEND

    elif (ebits & 0x00020000) != 0:
        return MACH_PORT_RIGHT_RECEIVE

    elif (ebits & 0x00040000) != 0:
        return MACH_PORT_RIGHT_SEND_ONCE

    elif (ebits & 0x00100000) != 0:
        return MACH_PORT_RIGHT_DEAD_NAME

    else:
        return 0


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

