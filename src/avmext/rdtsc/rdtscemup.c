#include "rdtscemu.h"

#include "nt/ntinternal.h"

//
// It is very unlikely that each CPU will have different Trap0D handlers.
//
ULONG_PTR AvmpRdtscEmulationTrap0DOriginalHandler;

//
// Set CR4_TSD flag into the CR4 register.
//
VOID
NTAPI
AvmpRdtscEmulationSetTimeStampDisableFlag(
  VOID
  )
{
  WriteCR4(ReadCR4() | CR4_TSD);
}

//
// Unset CR4_TSD flag from the CR4 register.
//
VOID
NTAPI
AvmpRdtscEmulationUnsetTimeStampDisableFlag(
  VOID
  )
{
  WriteCR4(ReadCR4() & ~CR4_TSD);
}

//
// Force immediate context switch immediate context switch if the current processor
// does not fall in the newly set affinity mask and does not return to the caller
// until the thread is rescheduled on a processor conforming to the new affinity mask.
//
// ref: http://www.drdobbs.com/monitoring-nt-debug-services/184416239
//
VOID
NTAPI
AvmpRdtscEmulationSwitchToProcessor(
  IN UCHAR ProcessorIndex
  )
{
  //
  // If KeSetSystemAffinityThread is called at IRQL <= APC_LEVEL and the call is successful,
  // the new affinity mask takes effect immediately.
  //
  // ref: https://msdn.microsoft.com/en-us/library/windows/hardware/ff553267(v=vs.85).aspx (see Remarks section)
  //

  if (KeGetCurrentIrql() > APC_LEVEL)
  {
    KeLowerIrql(APC_LEVEL);
  }

  KeSetSystemAffinityThread(AFFINITY_MASK(ProcessorIndex));
}

//
// Replace IDT entry.
//

#if defined(_X86_)

VOID
NTAPI
AvmpRdtscEmulationHookInterruptEntry(
  IN  UCHAR Index,
  IN  ULONG_PTR NewRoutineAddress,
  OUT ULONG_PTR* OldRoutineAddress
  )
{
  AVM_KDESCRIPTOR Idtr;
  ReadIDT(&Idtr);

  PAVM_KIDTENTRY Idt = (PAVM_KIDTENTRY)(Idtr.Limit | Idtr.Base << 16);

  DisableInterrupts();
  {
    ULONG_PTR OriginalHandler = (ULONG)(Idt[Index].ExtendedOffset) << 16 | Idt[Index].Offset;
    Idt[Index].Offset = (USHORT)NewRoutineAddress;
    Idt[Index].ExtendedOffset = (USHORT)((ULONG_PTR)NewRoutineAddress >> 16);

    *OldRoutineAddress = OriginalHandler;
  }
  EnableInterrupts();
}

#elif defined(_AMD64_)

VOID
NTAPI
AvmpRdtscEmulationHookInterruptEntry(
  IN  UCHAR Index,
  IN  ULONG_PTR NewRoutineAddress,
  OUT ULONG_PTR* OldRoutineAddress
)
{
  AVM_KDESCRIPTOR Idtr;
  ReadIDT(&Idtr);

  PAVM_KIDTENTRY Idt = (PAVM_KIDTENTRY)(Idtr.LowPart >> 16 | Idtr.HighPart << 48);
  PAVM_KIDTENTRY IdtAt = &Idt[Index];

  DisableInterrupts();
  {
    ULONG_PTR OriginalHandler = (ULONG_PTR)Idt[Index].OffsetLow          |
                                (ULONG_PTR)Idt[Index].OffsetMiddle << 16 |
                                (ULONG_PTR)Idt[Index].OffsetHigh   << 32;

    IdtAt->OffsetLow    = (USHORT)(NewRoutineAddress);
    IdtAt->OffsetMiddle = (USHORT)(NewRoutineAddress >> 16);
    IdtAt->OffsetHigh   = (ULONG) (NewRoutineAddress >> 32);

    *OldRoutineAddress = OriginalHandler;
  }
  EnableInterrupts();
}

#endif
