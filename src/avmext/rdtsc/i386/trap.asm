.386
.MODEL FLAT
include common.inc

;
;   Extern functions.
;

EXTRN   _AvmRdtscEmulationTrap0D@4:PROC
EXTRN   _AvmpRdtscEmulationTrap0DOriginalHandler:DWORD

;                                                                     ;
; ------------------------------------------------------------------- ;
;                            CODE  SECTION                            ;
; ------------------------------------------------------------------- ;
;                                                                     ;

.CODE

    _AvmpRdtscEmulationTrap0D PROC PUBLIC
        TRAP_ENTRY

;
;   Call our new trap function.
;

        push    esp
        call    _AvmRdtscEmulationTrap0D@4

;
;   If our trap did not handle the fault,
;   pass it to the original trap handler.
;

        cmp     eax, 0
        jz      OldHandler

;
;   Fault has been handled,
;   return from the interrupt handler.
;

        TRAP_END

        add     esp, 4
        iretd

OldHandler:

        TRAP_END
        jmp  dword ptr [_AvmpRdtscEmulationTrap0DOriginalHandler]

    _AvmpRdtscEmulationTrap0D ENDP

END
