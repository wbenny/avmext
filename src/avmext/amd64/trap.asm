include common.inc

;
;   Extern functions.
;

EXTRN   AvmRdtscEmulationTrap0D:PROC
EXTRN   AvmpRdtscEmulationTrap0DOriginalHandler:QWORD

;                                                                     ;
; ------------------------------------------------------------------- ;
;                            CODE  SECTION                            ;
; ------------------------------------------------------------------- ;
;                                                                     ;

.CODE

    AvmpRdtscEmulationTrap0D PROC PUBLIC
        TRAP_ENTRY
;
;   Call our new trap function.
;

        mov     rcx, rsp                  ; set first parameter
        
        sub     rsp, 32                   ; shadow space
        call    AvmRdtscEmulationTrap0D
        add     rsp, 32                   ; shadow space

;
;   If our trap did not handle the fault,
;   pass it to the original trap handler.
;

        cmp     rax, 0
        jz      OldHandler

;
;   Fault has been handled,
;   return from the interrupt handler.
;

        TRAP_END

        add     rsp, 8
        iretq

OldHandler:

        TRAP_END
        jmp  qword ptr [AvmpRdtscEmulationTrap0DOriginalHandler]

    AvmpRdtscEmulationTrap0D ENDP

END
