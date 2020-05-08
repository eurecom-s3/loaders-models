#!/usr/bin/env python3

from pwn import *

code =   shellcraft.i386.getpc("eax")
code +=  "sub eax, 13\n"
code +=  "mov eax, [eax]\n"
code +=  "push ebp\n"
code +=  "mov ebp, esp\n"
code +=  shellcraft.i386.pushstr('Hello World!\n')
code +=  shellcraft.push("esp")
code +=  "call eax\n"
code +=  shellcraft.i386.mov("eax", 0)
code +=  "mov esp, ebp\n"
code +=  "pop ebp\n"
code +=  shellcraft.i386.ret()

with open("x86printfimport", "wb") as fp:
    fp.write(asm(code))
