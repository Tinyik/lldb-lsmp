
""" implementation for lldb kernel debugging script lsmp

        @Author     -   Ian Fang    

        July 30, 2018
"""

import lldb
import argparse
from xnutils import *


target = None

class ListMachPort:

    lldb_command = 'lsmp'

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
                            type=int,
                            help='the pid of the process'
                            )

        parser.add_argument('-i',
                            '--index',
                            dest='mpindex',
                            type=int,
                            help='the index of the mach port'
                            )

        parser.add_argument('-c',
                            '--count',
                            dest='count',
                            action='store_true',
                            default=False,
                            help='if specified, only output the count'
                            )

        return parser

    def __init__(self, debugger, internal_dic):
        pass

    def __call__(self, debugger, command, exe_ctx, result):
        global target

        args = ListMachPort.parser.parse_args(command.split())
        
        target_pid, mpindex = args.pid, args.mpindex

        task = find_task_with_pid(target_pid) 
        ipc_space = task.GetChildMemberWithName('itk_space')
        is_table = ipc_space.GetChildMemberWithName('is_table')

        assert(is_table.GetTypeName() == 'ipc_entry_t')
        assert(is_table.GetType().IsPointerType() == True)

        SIZE_OF_IPC_ENTRY = 0x18

        ith_ipc_entry_addr = is_table.GetValueAsUnsigned() + mpindex * SIZE_OF_IPC_ENTRY
        ith_ipc_entry_sbaddr = lldb.SBAddress(ith_ipc_entry_addr, target)
        ipc_entry_type = getsbtype("struct ipc_entry")
        ipc_entry = target.CreateValueFromAddress('ith_entry', ith_ipc_entry_sbaddr, ipc_entry_type)

        assert(ipc_entry.GetTypeName() == 'ipc_entry')

        ipc_port_ptr_type = getsbtype('struct ipc_port *')
        ipc_port_ptr = ipc_entry.GetChildMemberWithName('ie_object').Cast(ipc_port_ptr_type)

        receiver = ipc_port_ptr.GetChildMemberWithName('data').GetChildMemberWithName('receiver')

        receiver_task_ptr = receiver.GetChildMemberWithName('is_task')
        proc_ptr_type = getsbtype('struct proc *')
        receiver_proc_ptr = receiver_task_ptr.GetChildMemberWithName('bsd_info').Cast(proc_ptr_type)
        receiver_proc_pid = receiver_proc_ptr.GetChildMemberWithName('p_pid').GetValueAsUnsigned()
        receiver_proc_name = receiver_proc_ptr.GetChildMemberWithName('p_name').GetSummary()

        print("Receiver of this port is %s" % receiver_proc_name)


def __lldb_init_module(debugger, internal_dic):
    global target
    target = debugger.GetSelectedTarget()

    ListMachPort.register_with_lldb(debugger, __name__)



# lsmp pid 120 -i 2
# Receive right:
#   process name:
#   pid:
# Send right:

# lsmp pid 120
# List all mach ports in ipc_space

# lsmp pid 120 --count