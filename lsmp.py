
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
            print_format, lines = func(*args, **kwargs)
            print header
            for line in lines:
                print print_format.format(*line)
        return __print_line
    return _print_header


class ListMachPort:

    lldb_command = 'lsmp'

    def __init__(self, debugger, internal_dic):
        pass


    @print_header("{0: >5s} {1: <10s} {2: <50s} {3: <30s} {4: <30s} {5: <30s}".format('#', 'pid', 'name', 'ie_bits', 'disposition', 'entry_index'))
    def __call__(self, debugger, command, exe_ctx, result):
        args = ListMachPort.parser.parse_args(command.split())
        
        target_pid, mpindex, count = args.pid, args.mpindex, args.count
        disposition = args.show_send | args.show_receive | args.show_send_once

        # struct task *, not task port
        task = task_for_pid(target_pid)

        if task is None:
            print "Cannot find process with pid %d" % target_pid
            exit(-1)

        itk_space = task.GetChildMemberWithName('itk_space')
        is_table_size = itk_space.GetChildMemberWithName('is_table_size').GetValueAsUnsigned()

        if count:
            print "This process has %d port rights." % is_table_size
            return

        ipc_port = None
        try:
            ipc_port = task_get_ith_ipc_port(task, mpindex)
        except IndexError as e:
            print "The given index exceeds is_table_size: %d" % is_table_size
            return

        #FIXME: Current implementation does not consider ipc_space_kernel
        proc_pid, proc_name, ie_bits, indices = port_find_right(ipc_port, disposition)

        disp_strs = []

        for bits in ie_bits:
            tmp_str = ''
            if bits & MACH_PORT_TYPE_RECEIVE:
                tmp_str = tmp_str + ' RCV '
            if bits & MACH_PORT_TYPE_SEND:
                tmp_str = tmp_str + ' SEND '
            if bits & MACH_PORT_TYPE_SEND_ONCE:
                tmp_str = tmp_str + ' SONCE '
            if bits & MACH_PORT_TYPE_DEAD_NAME:
                tmp_str = tmp_str + ' DEAD '

            if tmp_str is '':
                tmp_str = 'OTHER'

            disp_strs.append(tmp_str)

        print_format = "{0: >5d} {1: <10d} {2: <50s} 0x{3: <28x} {4: <30s} {5: <30d}"

        return print_format, zip(range(1, len(proc_pid)+1), proc_pid, proc_name, ie_bits, disp_strs, indices)


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




# lsmp pid 120 -i 2
# Receive right:
#   process name:
#   pid:
# Send right:

# lsmp pid 120
# List all mach ports in ipc_space

# lsmp pid 120 --count