#pragma once
#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

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

#define AVM_PATCH_STUB_SIZE 12

typedef struct _AVM_PATCH_STUB
{
  UCHAR Instructions[AVM_PATCH_STUB_SIZE];
} AVM_PATCH_STUB, *PAVM_PATCH_STUB;

C_ASSERT(sizeof(AVM_PATCH_STUB) == AVM_PATCH_STUB_SIZE);

typedef struct _AVM_PATCH_SSDT_ENTRY
{
  LIST_ENTRY ListEntry;

  PVOID OriginalRoutineAddress;
  PVOID NewRoutineAddress;
  ULONG SyscallNumber;
#if defined (_AMD64_)
  AVM_PATCH_STUB OriginalCaveData;
#endif
} AVM_PATCH_SSDT_ENTRY, *PAVM_PATCH_SSDT_ENTRY;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmPatchInitialize(
  VOID
  );

VOID
NTAPI
AvmPatchDestroy(
  VOID
  );

NTSTATUS
NTAPI
AvmPatchSSDTHook(
  _In_ PANSI_STRING AnsiRoutineName,
  _In_ PVOID NewAddress,
  _Out_ PAVM_PATCH_SSDT_ENTRY* HookEntry
  );

NTSTATUS
NTAPI
AvmPatchSSDTUnhook(
  _In_ PAVM_PATCH_SSDT_ENTRY HookEntry
  );

NTSTATUS
NTAPI
AvmPatchSSDTUnhookAll(
  VOID
  );

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

PVOID
NTAPI
AvmpPatchFindExportedRoutineByName(
  _In_ PVOID DllBase,
  _In_ PANSI_STRING AnsiRoutineName
  );

NTSTATUS
NTAPI
AvmpPatchFindSyscallNumberByRoutineName(
  _In_ PANSI_STRING AnsiRoutineName,
  _Out_ PULONG SyscallNumber
  );

PVOID
AvmpPatchFindNtoskrnlBase(
  VOID
  );

PAVM_SERVICE_TABLE_DESCRIPTOR
AvmpPatchFindSSDT(
  _In_ PVOID NtoskrnlBaseAddress
  );

#if defined (_AMD64_)

PVOID
NTAPI
AvmpPatchFindCaveAddress(
  _In_ PVOID AddressBegin,
  _In_ PVOID AddressEnd,
  _In_ ULONG DesiredSize
  );

#endif

//////////////////////////////////////////////////////////////////////////
// Extern variables.
//////////////////////////////////////////////////////////////////////////

extern LIST_ENTRY AvmPatchSSDTList;

