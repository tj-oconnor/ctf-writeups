from pwn import *

e = ELF('./sanityrev')
log.info("%s" % e.string(0x201d))
