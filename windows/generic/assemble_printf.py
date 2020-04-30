#!/usr/bin/env python3

from pwn import *

## module = kernel32!LoadLibraryA("msvcrt.dll")
code =   shellcraft.i386.pushstr('msvcrt.dll')
code +=  shellcraft.push("esp")
code +=  shellcraft.i386.mov("eax", 0x7c801d7b)
code +=  "call eax\n"

## printf = kernel32!GetProcAddress(module, "printf")
code +=  shellcraft.i386.mov('edi', 'eax')
code +=  shellcraft.i386.pushstr('printf')
code +=  shellcraft.push("esp")
code +=  shellcraft.push("edi")
code +=  shellcraft.i386.mov("eax", 0x7c80ae40)
code +=  "call eax\n"

code +=  shellcraft.i386.mov("edi", "eax")
code +=  shellcraft.i386.pushstr('Hello World!\n')
code +=  shellcraft.push("esp")
code +=  shellcraft.i386.mov("eax", "edi")
code +=  "call eax\n"
code +=  shellcraft.i386.mov("eax", 0)
code +=  shellcraft.i386.ret()

with open("x86printf", "wb") as fp:
    fp.write(asm(code))
