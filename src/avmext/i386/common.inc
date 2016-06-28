;
;   Constants for system irql and IDT vector conversion.
;

RPL_MASK     equ 00003H

;
;   Gdt Descriptor Offset Definitions.
;

KGDT_R3_DATA equ 00020H
KGDT_R0_PCR  equ 00030H

;++
;
;   ENTER_TRAP
;
;   Macro Description:
;
;       Build the TRAP_FRAME structure and set registers needed by a trap.
;
;--

TRAP_ENTRY macro

        push    ebp
        push    ebx
        push    esi
        push    edi

        push    fs

        push    eax
        push    ecx
        push    edx

        push    ds
        push    es
        push    gs

;
;   Set up segment registers.
;

        mov     ax, KGDT_R3_DATA or RPL_MASK
        mov     ds, ax
        mov     es, ax

        mov     ax, KGDT_R0_PCR
        mov     fs, ax

        endm

TRAP_END macro

        pop     gs
        pop     es
        pop     ds

        pop     edx
        pop     ecx
        pop     eax

        pop     fs

        pop     edi
        pop     esi
        pop     ebx
        pop     ebp

        endm
