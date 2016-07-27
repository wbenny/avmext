#pragma once
#include <ntifs.h>

#if defined(_X86_)
# define AVM_HOOK_SYSCALL_OFFSET 1
#elif defined (_AMD64_)
# define AVM_HOOK_SYSCALL_OFFSET 4
#endif

#define AVM_HOOK_MEMORY_TAG 'HvmA'

typedef struct _AVM_SERVICE_TABLE_DESCRIPTOR
{
  PULONG Base;
  PULONG Count;
  ULONG  Limit;
  PUCHAR Number;
} AVM_SERVICE_TABLE_DESCRIPTOR, *PAVM_SERVICE_TABLE_DESCRIPTOR;

//
// 0x48, 0xb8, PointerToByteArray(NewAddress), // mov rax, NewAddress
// 0x50,                                       // push rax
// 0xc3,                                       // ret
//

#define AVM_HOOK_STUB_SIZE 12

typedef struct _AVM_HOOK_STUB
{
  UCHAR Instructions[AVM_HOOK_STUB_SIZE];
} AVM_HOOK_STUB, *PAVM_HOOK_STUB;

C_ASSERT(sizeof(AVM_HOOK_STUB) == AVM_HOOK_STUB_SIZE);

typedef struct _AVM_HOOK_ENTRY
{
  PVOID OriginalRoutineAddress;
  PVOID NewRoutineAddress;
  LIST_ENTRY ListEntry;
  ULONG SyscallNumber;
#if defined (_AMD64_)
  AVM_HOOK_STUB OriginalCaveData;
#endif
} AVM_HOOK_ENTRY, *PAVM_HOOK_ENTRY;

extern PAVM_SERVICE_TABLE_DESCRIPTOR AvmHookServiceDescriptorTable;
extern PVOID AvmHookNtoskrnlBaseAddress;
extern LIST_ENTRY AvmHookList;

//
// Private functions.
//

PVOID
NTAPI
AvmpHookFindExportedRoutineByName(
  IN PVOID DllBase,
  IN PANSI_STRING AnsiRoutineName
  );

NTSTATUS
NTAPI
AvmpHookFindSyscallNumberByRoutineName(
  IN PANSI_STRING AnsiRoutineName,
  OUT PULONG SyscallNumber
  );

PVOID
AvmpHookFindNtoskrnlBase(
  VOID
  );

PAVM_SERVICE_TABLE_DESCRIPTOR
AvmpHookFindSSDT(
  PVOID NtoskrnlBaseAddress
  );

#if defined (_AMD64_)

PVOID
NTAPI
AvmpHookFindCaveAddress(
  PVOID AddressBegin,
  PVOID AddressEnd,
  ULONG DesiredSize
  );

#endif

//
// Public functions.
//

NTSTATUS
NTAPI
AvmHookSSDTHook(
  IN  PANSI_STRING AnsiRoutineName,
  IN  PVOID NewAddress,
  OUT PAVM_HOOK_ENTRY* HookEntry
  );

NTSTATUS
NTAPI
AvmHookSSDTUnhook(
  IN PAVM_HOOK_ENTRY HookEntry
  );


//
// Initialize & destroy routines.
//

NTSTATUS
NTAPI
AvmHookInitialize(
  IN PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AvmHookDestroy(
  IN PDRIVER_OBJECT DriverObject
  );
