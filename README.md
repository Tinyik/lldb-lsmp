# lldb-lsmp
lsmp implementation for lldb - listing mach ports.


Usage: 

```
$ lldb  
$ (lldb) script import lsmp.py
```


```
# 1. List mach ports for process PID
lsmp PID

# 2. List references to mach port with index IND in process PID's ipc_space.
lsmp PID -i IND

# 3. Filtering port rights
lsmp PID -i IND [--SONCE] [--SEND] [--RCV]
```


## Todo:
- [ ] Support for port sets
