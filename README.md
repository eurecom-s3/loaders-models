# Loader Models
## Linux  

## Kernel  
Model for the `load_elf_binary` function in `fs/binfmt_elf.c`  

## glibc  

Depending on if elf is loaded by kernel exec or by glibc, two paths are possible:  

kernel model      --.  
   OR                :--> glibc rest of the model  
glibc open_verify --'  

(libraries take the second path)  

## ReacOS
Model for the `PeFmtCreateSection` function in `ntoskrnl/mm/section.c`  
