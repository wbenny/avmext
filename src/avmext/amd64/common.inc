;
;   Constants for system irql and IDT vector conversion.
;

RPL_MASK        equ 00003H

;
;   Gdt Descriptor Offset Definitions.
;

KGDT64_R3_DATA  equ 00028H
KGDT64_R3_CMTEB equ 00050H

;
;   Define constants for system IRQL and IDT vector conversion.
;

MODE_MASK       equ 00001H

;
;   Define TRAP_FRAME64 field offsets.
;
TrErrorCode     equ 00058H
TrRip           equ 00060H
TrSegCs         equ 00068H
TrEFlags        equ 00070H
TrRsp           equ 00078H
TrSegSs         equ 00080H

;
; Define special macros to align trap entry points on cache line boundaries.
;
; N.B. This will only work if all functions in this module are declared with
;      these macros.
;

TRAP_ENTRY macro

        local KernelMode

        push    rbp
        push    rsi
        push    rdi
        push    rbx

        push    r11
        push    r10
        push    r9
        push    r8
        push    rdx
        push    rcx
        push    rax

        test    byte ptr TrSegCs[rsp], MODE_MASK
        jz      KernelMode

        swapgs

KernelMode:

        mov     rbp, rsp

        endm

;
; TRAP_END macro.
;

TRAP_END macro

        local KernelMode

        test    byte ptr TrSegCs[rsp], MODE_MASK
        jz      KernelMode

        swapgs

KernelMode:

        pop     rax
        pop     rcx
        pop     rdx
        pop     r8
        pop     r9
        pop     r10
        pop     r11

        pop     rbx
        pop     rdi
        pop     rsi
        pop     rbp

        endm
