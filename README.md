# Loader Models
## Windows
The Windows loader is made of two distinct components, residing respectively in kernel- and user-space.
The entry point of kernel-space part of the loader is the `MiCreateImageFileMap` in ntkrnlmp.exe, while the user-space portion starts with the `LdrpInitializeProcess` in ntdll.dll.  
We modeled three versions of the Windows loader:
- [Windows XP](windows/xp)
- [Windows 7](windows/7)
- [Windows 10](windows/10)

For each version, we provide a model for the kernel-space portion of the loader (MiCreateImageFileMap.lmod) and one for the user-space one (LdrpInitializeProcess.lmod).  
Moreover, we created two models (one for Windows XP and one for Windows 7/10) for the memory mapping operations that the Windows loader performs when loading a PE file. They can be found in this [directory](windows/memory_map).  
These models use of the standard PE data types defined in the this [C header file](windows/headers/ntkrnlmp.h).

## Antivirus tools
### ClamAV
The model for the PE-specific parser of ClamAV is [here](avs/clamav/pe.lmod).  
We also provide a [model](avs/clamav/rva_map_clamav.lmod) for the memory mapping operation by which ClamAV translates virtual address in the process memorr space into offsets in the original PE file
### Yara
A model of the memory mapping operation performed by yara can be found [here](avs/yara/rva_map_yara.lmod).
Yara also enforces very few constraints while parsing PE files, which encoded this [model](avs/yara/pe.lmod).

## Reverse-Engineering tools
### radare2
Similarly to the case of yara, for radare2 we provide a [model](reveng-tools/radare2/rva_map_r2.lmod) of the memory map operation, and a basic [one](reveng-tools/radare2/pe.lmod) of the very few constraints enforced on PE files.

## Linux (preliminary wip)
### Kernel-space  
A model for the `load_elf_binary` function of the Linux kernel (version 5.5) (defined in `fs/binfmt_elf.c`) can be found [here](linux/linux_kernel_32.lmod).
### glibc  
A model for the `glibc_open_verify_32` function of glibc can be found [here](linux/glibc_open_verify_32.lmod).

## ReacOS (preliminary wip)
Model for the `PeFmtCreateSection` function in `ntoskrnl/mm/section.c`  
