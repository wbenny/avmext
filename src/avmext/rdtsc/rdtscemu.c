#include "rdtscemu.h"

#include "nt/ntinternal.h"

#define AVM_GENERAL_PROTECTION_FAULT_INTERRUPT_VECTOR   (0x0D)

AVM_RDTSC_EMULATION_LOG_TABLE_ITEM AvmRdtscEmulationLogTable[AVM_RDTSC_EMULATION_LOG_TABLE_SIZE];
ULONG AvmRdtscEmulationLogTableSizeInBytes = sizeof(AvmRdtscEmulationLogTable);
ULONG AvmRdtscEmulationLogTableItemCount = 0;
KSPIN_LOCK AvmRdtscEmulationLogTableLock;

AVM_RDTSC_EMULATION_CONFIGURATION AvmRdtscEmulationConfiguration;

VOID
NTAPI
AvmRdtscEmulationLog(
  AVM_RDTSC_EMULATION_INSTRUCTION_TYPE Instruction,
  PVOID Eip,
  ULONG ReturnedEax,
  ULONG ReturnedEdx,
  ULONG ReturnedEcx
  )
{
  AVM_RDTSC_EMULATION_LOG_TABLE_ITEM TableItem = {
    .ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
    .ReturnedEax = ReturnedEax,
    .ReturnedEdx = ReturnedEdx,
    .ReturnedEcx = ReturnedEcx,
    .Eip = Eip,
    .Instruction = Instruction
  };

  AvmRdtscEmulationLogTable[AvmRdtscEmulationLogTableItemCount++ % RTL_NUMBER_OF(AvmRdtscEmulationLogTable)] = TableItem;
}

//
// Inspired by vmdetectorsys.
//
// ref: https://github.com/x9090/vmdetectorsys
//

#if defined(_X86_)

VOID
NTAPI
AvmRdtscEmulationEmulate(
  PULONG Eax,
  PULONG Edx
  )
{
  static ULONG Seed = 0x01000193;
  ULONG RandomDelta;

  switch (AvmRdtscEmulationConfiguration.Method)
  {
    case AvmRdtscEmulationIncreasingMethodType:
      //
      // Generate RandomDelta in the interval <DeltaFrom, DeltaTo).
      //
      RandomDelta = (ULONG)RtlRandomEx(&Seed);
      RandomDelta %= (AvmRdtscEmulationConfiguration.DeltaTo - AvmRdtscEmulationConfiguration.DeltaFrom);
      RandomDelta += AvmRdtscEmulationConfiguration.DeltaFrom;

      AvmRdtscEmulationConfiguration.TscValue += RandomDelta;

      //
      // Fall through.
      //

    case AvmRdtscEmulationConstantMethodType:
      *Edx = (ULONG)(AvmRdtscEmulationConfiguration.TscValue << 32);
      *Eax = (ULONG)(AvmRdtscEmulationConfiguration.TscValue);
      break;

    default:
      break;
  }
}

//
// Real Trap0D handler.
//
BOOLEAN
NTAPI
AvmRdtscEmulationTrap0D(
  IN PAVM_KTRAP_FRAME UserFrame
  )
{
  SIZE_T InstructionLength = 0;

  KIRQL OldIrql;
  KeAcquireSpinLock(&AvmRdtscEmulationLogTableLock, &OldIrql);

  if (MmIsAddressValid((PVOID)UserFrame->Eip))
  {
    if (RtlEqualMemory((PVOID)UserFrame->Eip, AvmOpRdtsc, sizeof(AvmOpRdtsc)))
    {
      InstructionLength = sizeof(AvmOpRdtsc);

      AvmRdtscEmulationEmulate(
        &UserFrame->Eax,
        &UserFrame->Edx);

      AvmRdtscEmulationLog(
        AvmRdtscType,
        (PVOID)UserFrame->Eip,
        UserFrame->Eax,
        UserFrame->Edx,
        UserFrame->Ecx);
    }
    else if (RtlEqualMemory((PVOID)UserFrame->Eip, AvmOpRdtscp, sizeof(AvmOpRdtscp)))
    {
      InstructionLength = sizeof(AvmOpRdtscp);

      UserFrame->Ecx = AvmRdtscEmulationConfiguration.TscAux;

      AvmRdtscEmulationEmulate(
        &UserFrame->Eax,
        &UserFrame->Edx);

      AvmRdtscEmulationLog(
        AvmRdtscpType,
        (PVOID)UserFrame->Eip,
        UserFrame->Eax,
        UserFrame->Edx,
        UserFrame->Ecx);
    }
  }

  KeReleaseSpinLock(&AvmRdtscEmulationLogTableLock, OldIrql);

  //
  // Move instruction pointer behind the instruction.
  //
  UserFrame->Eip += InstructionLength;

  //
  // Return TRUE if the rdtsc(p) instruction was handled.
  //
  return InstructionLength != 0;
}

#elif defined(_AMD64_)

VOID
NTAPI
AvmRdtscEmulationEmulate(
  PULONGLONG Rax,
  PULONGLONG Rdx
  )
{
  static ULONG Seed = 0x01000193;
  ULONG RandomDelta;

  switch (AvmRdtscEmulationConfiguration.Method)
  {
    case AvmRdtscEmulationIncreasingMethodType:
      //
      // Generate RandomDelta in the interval <DeltaFrom, DeltaTo).
      //
      RandomDelta = (ULONG)RtlRandomEx(&Seed);
      RandomDelta %= (AvmRdtscEmulationConfiguration.DeltaTo - AvmRdtscEmulationConfiguration.DeltaFrom);
      RandomDelta += AvmRdtscEmulationConfiguration.DeltaFrom;

      AvmRdtscEmulationConfiguration.TscValue += RandomDelta;

      //
      // Fall through.
      //

    case AvmRdtscEmulationConstantMethodType:
      *Rdx = (ULONGLONG)(ULONG)(AvmRdtscEmulationConfiguration.TscValue << 32);
      *Rax = (ULONGLONG)(ULONG)(AvmRdtscEmulationConfiguration.TscValue);
      break;

    default:
      break;
  }
}

//
// Real Trap0D handler.
//
BOOLEAN
NTAPI
AvmRdtscEmulationTrap0D(
  IN PAVM_KTRAP_FRAME UserFrame
  )
{
  SIZE_T InstructionLength = 0;

  KIRQL OldIrql;
  KeAcquireSpinLock(&AvmRdtscEmulationLogTableLock, &OldIrql);

  if (MmIsAddressValid((PVOID)UserFrame->Rip))
  {
    if (RtlEqualMemory((PVOID)UserFrame->Rip, AvmOpRdtsc, sizeof(AvmOpRdtsc)))
    {
      InstructionLength = sizeof(AvmOpRdtsc);

      AvmRdtscEmulationEmulate(
        &UserFrame->Rax,
        &UserFrame->Rdx);

      AvmRdtscEmulationLog(
        AvmRdtscType,
        (PVOID)UserFrame->Rip,
        (ULONG)UserFrame->Rax,
        (ULONG)UserFrame->Rdx,
        (ULONG)UserFrame->Rcx);
    }
    else if (RtlEqualMemory((PVOID)UserFrame->Rip, AvmOpRdtscp, sizeof(AvmOpRdtscp)))
    {
      InstructionLength = sizeof(AvmOpRdtscp);

      UserFrame->Rcx = AvmRdtscEmulationConfiguration.TscAux;

      AvmRdtscEmulationEmulate(
        &UserFrame->Rax,
        &UserFrame->Rdx);

      AvmRdtscEmulationLog(
        AvmRdtscpType,
        (PVOID)UserFrame->Rip,
        (ULONG)UserFrame->Rax,
        (ULONG)UserFrame->Rdx,
        (ULONG)UserFrame->Rcx);
    }
  }

  KeReleaseSpinLock(&AvmRdtscEmulationLogTableLock, OldIrql);

  //
  // Move instruction pointer behind the instruction.
  //
  UserFrame->Rip += InstructionLength;

  //
  // Return TRUE if the rdtsc(p) instruction was handled.
  //
  return InstructionLength != 0;
}

#endif

VOID
NTAPI
AvmRdtscEmulationEnable(
  VOID
  )
{
  //
  // Early exit if the hook has been already installed.
  //
  if (AvmpRdtscEmulationTrap0DOriginalHandler != 0)
  {
    return;
  }

  //
  // Hook IDT entry on each processor.
  //
  for (CCHAR i = 0; i < KeNumberProcessors; i++)
  {
    //
    // Synchronously switch CPU.
    //
    AvmpRdtscEmulationSwitchToProcessor(i);

    //
    // Hook IDT entry on current processor.
    //
    AvmpRdtscEmulationHookInterruptEntry(
      AVM_GENERAL_PROTECTION_FAULT_INTERRUPT_VECTOR,
      (ULONG_PTR)&AvmpRdtscEmulationTrap0D,
      &AvmpRdtscEmulationTrap0DOriginalHandler);

    //
    // Set the TSD flag.
    //
    AvmpRdtscEmulationSetTimeStampDisableFlag();
  }
}

VOID
NTAPI
AvmRdtscEmulationDisable(
  VOID
  )
{
  //
  // Early exit if the hook was not installed.
  //
  if (AvmpRdtscEmulationTrap0DOriginalHandler == 0)
  {
    return;
  }

  //
  // Unhook IDT entry on each processor.
  //
  for (CCHAR i = 0; i < KeNumberProcessors; i++)
  {
    //
    // Synchronously switch CPU.
    //
    AvmpRdtscEmulationSwitchToProcessor(i);

    //
    // Unhook IDT entry on current processor.
    //
    ULONG_PTR Dummy;
    AvmpRdtscEmulationHookInterruptEntry(
      AVM_GENERAL_PROTECTION_FAULT_INTERRUPT_VECTOR,
      AvmpRdtscEmulationTrap0DOriginalHandler,
      &Dummy);

    //
    // Unset the TSD flag.
    //
    AvmpRdtscEmulationUnsetTimeStampDisableFlag();
  }
}

NTSTATUS
NTAPI
AvmRdtscEmulationInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  RtlZeroMemory(AvmRdtscEmulationLogTable, AvmRdtscEmulationLogTableSizeInBytes);
  KeInitializeSpinLock(&AvmRdtscEmulationLogTableLock);

  //
  // Initial RDTSC configuration.
  //
  AvmRdtscEmulationConfiguration.Method = AvmRdtscEmulationIncreasingMethodType;
  AvmRdtscEmulationConfiguration.ProcessId = 0;
  
  AvmRdtscEmulationConfiguration.TscValue = ReadTSC();
  ReadTSCP(&AvmRdtscEmulationConfiguration.TscAux);

  AvmRdtscEmulationConfiguration.DeltaFrom = 10;
  AvmRdtscEmulationConfiguration.DeltaTo = 100;
  AvmRdtscEmulationConfiguration.TscAux = 20;

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmRdtscEmulationDestroy(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  AvmRdtscEmulationDisable();
}

