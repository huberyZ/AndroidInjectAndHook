.global _shellcode_start_arm32
.global _shellcode_end_arm32
.global _hookstub_function_addr_arm32
.global _original_function_addr_arm32

.data

_shellcode_start_arm32:
    push    {r0, r1, r2, r3}
    mrs     r0, cpsr
    str     r0, [sp, #0xC]
    str     r14, [sp, #8]   
    add     r14, sp, #0x10
    str     r14, [sp, #4]    
    pop     {r0}               
    push    {r0-r12}           
    mov     r0, sp
    ldr     r3, _hookstub_function_addr_arm32
    blx     r3
    ldr     r0, [sp, #0x3C]
    msr     cpsr, r0
    ldmfd   sp!, {r0-r12}       
    ldr     r14, [sp, #4]
    ldr     sp, [r13]
    ldr     pc, _original_function_addr_arm32
    
_hookstub_function_addr_arm32:
.word 0xffffffff

_original_function_addr_arm32:
.word 0xffffffff

_shellcode_end_arm32:

.end
