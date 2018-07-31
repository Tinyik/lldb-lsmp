""" Utility functions for lsmp
		@Author   	-  	Ian Fang 	

		July 30, 2018
"""

import lldb
import re



_str_to_sbtype_cache = {}


def getsbtype(target_type):
	""" Conver a str to lldb.SBType
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
		raise NameError('Unable to find type '+target_type)

	if not tmp_type.IsValid():
		raise NameError('Unable to Cast to type '+target_type)

	if type_is_pointer:
		tmp_type = tmp_type.GetPointerType()

	_str_to_sbtype_cache[target_type] = tmp_type

	return _str_to_sbtype_cache[target_type]


def find_task_with_pid(target_pid):
    """ Return the task corresponds to the given pid
        params:
            target_pid         - int
        
        returns:
            task               - lldb.SBValue      the task if one exist, 
                                                   otherwise an error is printed to console.
    """
    task_queue = lldb.debugger.GetSelectedTarget().FindFirstGlobalVariable('tasks')
    task_ptr_type = getsbtype('struct task *')

    for task in iterate_queue(task_queue, task_ptr_type, 'tasks'):
        bsd_info_void_ptr = task.GetChildMemberWithName('bsd_info')
        proc_ptr_type = getsbtype('struct proc *')
        proc = bsd_info_void_ptr.Cast(proc_ptr_type)

        p_pid = proc.GetChildMemberWithName('p_pid').GetValueAsUnsigned()
        print(p_pid)
        if proc and p_pid == target_pid:
            return task

    print 'Cannot find process with pid %d' % target_pid


def iterate_queue(queue_head, entry_type, entry_field_name):
 	""" Iterate over a queue_head_t.
 		params:
 			queue_head 		   	- lldb.SBValue
 			entry_type	   		- lldb.SBType
 			entry_field_name	- str

 		returns:
 			A lldb.SBValue generator with all tasks.
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

