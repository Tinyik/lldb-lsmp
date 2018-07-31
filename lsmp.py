
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

        parser.add_argument('-n',
                            '--name',
                            dest='mpname',
                            type=int,
                            help='the name of the mach port'
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
        args = ListMachPort.parser.parse_args(command.split())
        
        target_pid, mpindex, mpname, count = args.pid, args.mpindex, args.mpname, args.count


        #FIXME: Add --name switch properly
        if mpname is not None:
            pass

        task = task_for_pid(target_pid) 
        if task is None:
            print "Cannot find process with pid %d" % target_pid
            exit(-1)

        itk_space = task.GetChildMemberWithName('itk_space')
        is_table_size = itk_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()

        if count:
            print 'This process has %d port rights.' % is_table_size
            return

        ipc_port = None
        try:
            ipc_port = task_get_ith_ipc_port(task, mpindex)
        except IndexError as e:
            print 'The given index exceeds is_table_size: %d' % is_table_size
            return

        assert(ipc_entry.GetTypeName() == 'ipc_entry')

        proc_pid, proc_name = port_get_receiver(ipc_port)

        if proc_name is not None:
            print "Receive right of this port belongs to %s" % receiver_proc_name
        else:
            print "This port does not have receiver"


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