#include "hook.h"

#include "memory.h"
#include "image.h"

PAVM_SERVICE_TABLE_DESCRIPTOR AvmHookServiceDescriptorTable = NULL;
PVOID AvmHookNtoskrnlBaseAddress = NULL;
LIST_ENTRY AvmHookList;

NTSTATUS
NTAPI
AvmHookSSDTHook(
  IN  PANSI_STRING AnsiRoutineName,
  IN  PVOID NewAddress,
  OUT PAVM_HOOK_ENTRY* HookEntry
  )
{
  NTSTATUS Status;
  PAVM_HOOK_ENTRY HookEntryResult = NULL;

  //
  // Get syscall number.
  //
  ULONG SyscallNumber;
  if (!NT_SUCCESS(Status = AvmpHookFindSyscallNumberByRoutineName(AnsiRoutineName, &SyscallNumber)))
  {
    goto ErrorExit;
  }

  //
  // Allocate the hook entry structure.
  //
  HookEntryResult = ExAllocatePoolWithTag(
    NonPagedPool,
    sizeof(AVM_HOOK_ENTRY),
    AVM_HOOK_MEMORY_TAG);

  if (!HookEntryResult)
  {
    Status = STATUS_INSUFFICIENT_RESOURCES;
    goto ErrorExit;
  }

  //
  // Get the address of the system function.
  //
  ULONG OldValue = AvmHookServiceDescriptorTable->Base[SyscallNumber];

#if defined (_AMD64_)

  //
  // Create the hook stub.
  //
  CONST UCHAR HookStub[] = {
    0x48, 0xb8, PointerToByteArray(NewAddress), // mov rax, NewAddress
    0x50,                                       // push rax
    0xc3,                                       // ret
  };

  C_ASSERT(sizeof(HookStub) == AVM_HOOK_STUB_SIZE);

  //
  // Compute the original syscall function address.
  //
  ULONG SyscallRoutineRelativeAddress = OldValue >> 4;
  ULONG SyscallRoutineArgumentCount   = OldValue & 0xf;
  PVOID SyscallRoutineAddress         = (PVOID)((ULONG_PTR)AvmHookServiceDescriptorTable->Base + SyscallRoutineRelativeAddress);

  //
  // Search for spare space where we can save the hook stub.
  //
  ULONG SizeOfTextSection;
  PUCHAR EndOfTextSection = AvmFindEndOfSectionFromAddress(
    SyscallRoutineAddress,
    AvmHookNtoskrnlBaseAddress,
    &SizeOfTextSection);

  if (!EndOfTextSection || !SizeOfTextSection)
  {
    Status = STATUS_NOT_FOUND;
    goto ErrorExit;
  }

  PVOID NewRoutineAddress = AvmpHookFindCaveAddress(
    EndOfTextSection,
    EndOfTextSection + SizeOfTextSection,
    AVM_HOOK_STUB_SIZE);

  if (!NewRoutineAddress)
  {
    Status = STATUS_NOT_FOUND;
    goto ErrorExit;
  }

  //
  // Save the original data in the cave.
  //
  RtlCopyMemory(HookEntryResult->OriginalCaveData.Instructions, NewRoutineAddress, AVM_HOOK_STUB_SIZE);

  //
  // Copy the hook stub in the cave.
  //
  if (!NT_SUCCESS(Status = AvmpCopyMemoryViaMdl(NewRoutineAddress, HookStub, AVM_HOOK_STUB_SIZE)))
  {
    goto ErrorExit;
  }

  //
  // Create new system table entry.
  //
  ULONG NewValue;
  NewValue = (ULONG)((ULONG_PTR)NewRoutineAddress - (ULONG_PTR)AvmHookServiceDescriptorTable->Base);
  NewValue = (NewValue << 4) | SyscallRoutineArgumentCount;

#elif defined (_X86_)

  PVOID SyscallRoutineAddress = (PVOID)OldValue;
  PVOID NewRoutineAddress = NewAddress;

  ULONG NewValue = (ULONG)NewAddress;

#endif

  //
  // Patch the SSDT entry.
  //
  if (!NT_SUCCESS(Status = AvmpInterlockedExchangeViaMdl((PLONG)&AvmHookServiceDescriptorTable->Base[SyscallNumber], NewValue)))
  {
    goto ErrorExit;
  }

  //
  // Fill the HookEntry structure.
  //
  HookEntryResult->OriginalRoutineAddress = SyscallRoutineAddress;
  HookEntryResult->NewRoutineAddress = NewRoutineAddress;
  HookEntryResult->SyscallNumber = SyscallNumber;
  InsertHeadList(&AvmHookList, &HookEntryResult->ListEntry);

  *HookEntry = HookEntryResult;

  return STATUS_SUCCESS;

  //
  // Error exit.
  //
ErrorExit:
  if (HookEntryResult)
  {
    ExFreePoolWithTag(HookEntryResult, AVM_HOOK_MEMORY_TAG);
  }

  return Status;
}

NTSTATUS
NTAPI
AvmHookSSDTUnhook(
  IN PAVM_HOOK_ENTRY HookEntry
  )
{
  NTSTATUS Status;

  ULONG SyscallNumber = HookEntry->SyscallNumber;

#if defined (_AMD64_)

  //
  // Get the argument count.
  //
  ULONG NewValue = AvmHookServiceDescriptorTable->Base[SyscallNumber];
  ULONG SyscallRoutineArgumentCount = NewValue & 0xf;

  //
  // Restore the original value.
  //
  ULONG OldValue;
  OldValue = (ULONG)((ULONG_PTR)HookEntry->OriginalRoutineAddress - (ULONG_PTR)AvmHookServiceDescriptorTable->Base);
  OldValue = (OldValue << 4) | SyscallRoutineArgumentCount;

#elif defined (_X86_)

  ULONG OldValue = (ULONG)(HookEntry->OriginalRoutineAddress);

#endif

  //
  // Patch the SSDT entry.
  //
  if (!NT_SUCCESS(Status = AvmpInterlockedExchangeViaMdl((PLONG)&AvmHookServiceDescriptorTable->Base[SyscallNumber], OldValue)))
  {
    return Status;
  }

#if defined (_AMD64_)

  //
  // Restore the original data in the cave.
  //
  if (!NT_SUCCESS(Status = AvmpCopyMemoryViaMdl(HookEntry->NewRoutineAddress, HookEntry->OriginalCaveData.Instructions, AVM_HOOK_STUB_SIZE)))
  {
    return Status;
  }

#endif

  RemoveEntryList(&HookEntry->ListEntry);

  ExFreePoolWithTag(HookEntry, AVM_HOOK_MEMORY_TAG);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmHookInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  AvmHookNtoskrnlBaseAddress = AvmpHookFindNtoskrnlBase();
  if (!AvmHookNtoskrnlBaseAddress)
  {
    return STATUS_UNSUCCESSFUL;
  }

  AvmHookServiceDescriptorTable = AvmpHookFindSSDT(AvmHookNtoskrnlBaseAddress);
  if (!AvmHookServiceDescriptorTable)
  {
    return STATUS_UNSUCCESSFUL;
  }

  InitializeListHead(&AvmHookList);

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmHookDestroy(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  //
  // Unhook all hooked functions.
  //
  __debugbreak();
  PLIST_ENTRY NextEntry = AvmHookList.Blink;

  while (NextEntry != &AvmHookList)
  {
    PAVM_HOOK_ENTRY HookEntry = CONTAINING_RECORD(
      NextEntry,
      AVM_HOOK_ENTRY,
      ListEntry);

    AvmHookSSDTUnhook(HookEntry);

    NextEntry = AvmHookList.Blink;
  }
}
