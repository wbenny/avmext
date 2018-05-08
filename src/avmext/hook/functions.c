#include <stdarg.h>

#include "functions.h"
#include "entry.h"
#include "hook.h"
#include "device/device.h"

PAVM_HOOK_ENTRY AvmHookEntryNtCreateFile = NULL;
PAVM_HOOK_ENTRY AvmHookEntryNtOpenFile = NULL;
PAVM_HOOK_ENTRY AvmHookEntryNtReadVirtualMemory = NULL;
PAVM_HOOK_ENTRY AvmHookEntryNtWriteVirtualMemory = NULL;

BOOLEAN AvmHookWatchedProcessEnabled = TRUE;
HANDLE AvmHookWatchedProcessIdList[16];
ULONG AvmHookWatchedProcessIdCount = 0;

ULONG AvmHookEventListId = 0;
LIST_ENTRY AvmHookEventList;
KSPIN_LOCK AvmHookEventListLock;

BOOLEAN
__fastcall
AvmpHookIsWatchedProcessId(
  HANDLE ProcessId
  )
{
  for (ULONG Index = 0; Index < AvmHookWatchedProcessIdCount; Index++)
  {
    if (ProcessId == AvmHookWatchedProcessIdList[Index])
    {
      return TRUE;
    }
  }

  return FALSE;
}

NTSTATUS
NTAPI
AvmHookAddWatchedProcessId(
  HANDLE ProcessId
  )
{
  AvmHookWatchedProcessIdList[AvmHookWatchedProcessIdCount] = ProcessId;
  AvmHookWatchedProcessIdCount += 1;

  return STATUS_SUCCESS;
}

#define AvmpHookIsCurrentProcessWatched() (AvmHookWatchedProcessEnabled && AvmpHookIsWatchedProcessId(PsGetCurrentProcessId()))

ULONG
NTAPI
AvmpHookCreateEventCountParameterSize(
  va_list Args
  )
{
  ULONG Result = 0;
  ULONG CurrentToken;

  while ((CurrentToken = va_arg(Args, ULONG)) != AHEPT_VOID)
  {
    Result += sizeof(AVM_HOOK_EVENT_PARAMETER) + va_arg(Args, ULONG);
    va_arg(Args, PVOID);
  }

  return Result;
}

PAVM_HOOK_EVENT
AvmHookCreateEventVa(
  ULONG Function,
  va_list Args
  )
{
  ULONG EventParameterListSize;
  EventParameterListSize = AvmpHookCreateEventCountParameterSize(Args);

  PAVM_HOOK_EVENT Result;
  Result = ExAllocatePoolWithTag(
    NonPagedPool,
    sizeof(AVM_HOOK_EVENT) + EventParameterListSize,
    AVM_HOOK_MEMORY_TAG);

  Result->Id = AvmHookEventListId++;
  Result->Size = sizeof(AVM_HOOK_EVENT) + EventParameterListSize;
  Result->Function = Function;
  Result->ParameterCount = 0;

  PAVM_HOOK_EVENT_PARAMETER Parameter;
  Parameter = (PAVM_HOOK_EVENT_PARAMETER)((PUCHAR)Result + sizeof(AVM_HOOK_EVENT));

  ULONG CurrentToken;
  while ((CurrentToken = va_arg(Args, ULONG)) != AHEPT_VOID)
  {
    Parameter->Type = CurrentToken;
    Parameter->Size = va_arg(Args, ULONG);

    PVOID Value = va_arg(Args, PVOID);
    switch (CurrentToken)
    {
      case AHEPT_BOOL:
      case AHEPT_INTEGER:
      case AHEPT_UNSIGNED_INTEGER:
        RtlCopyMemory(Parameter->Data, &Value, Parameter->Size);
        break;

      case AHEPT_STRING:
      case AHEPT_UNICODE_STRING:
      case AHEPT_BINARY:
        RtlCopyMemory(Parameter->Data, Value, Parameter->Size);
        break;

      default:
        NT_ASSERT(0);
        break;
    }

    Parameter = (PAVM_HOOK_EVENT_PARAMETER)((PUCHAR)Parameter + sizeof(AVM_HOOK_EVENT_PARAMETER) + Parameter->Size);

    Result->ParameterCount += 1;
  }

  KIRQL Irql;
  KeAcquireSpinLock(&AvmHookEventListLock, &Irql);
  AvmDbgPrint("Adding event ID: %u\n", Result->Id);
  InsertTailList(&AvmHookEventList, &Result->ListEntry);
  KeReleaseSpinLock(&AvmHookEventListLock, Irql);

  KeReleaseSemaphore(&AvmDeviceExtension->EventQueueSemaphore, 0, 1, FALSE);

  return Result;
}

PAVM_HOOK_EVENT
AvmHookCreateEvent(
  ULONG Function,
  ...
  )
{
  va_list Args;
  va_start(Args, Function);

  PAVM_HOOK_EVENT Result;
  Result = AvmHookCreateEventVa(Function, Args);

  va_end(Args);

  return Result;
}

NTSTATUS
NTAPI
AvmHookNtCreateFile(
  __out PHANDLE FileHandle,
  __in ACCESS_MASK DesiredAccess,
  __in POBJECT_ATTRIBUTES ObjectAttributes,
  __out PIO_STATUS_BLOCK IoStatusBlock,
  __in_opt PLARGE_INTEGER AllocationSize,
  __in ULONG FileAttributes,
  __in ULONG ShareAccess,
  __in ULONG CreateDisposition,
  __in ULONG CreateOptions,
  __in_bcount_opt(EaLength) PVOID EaBuffer,
  __in ULONG EaLength
  )
{
  return ((pfnNtCreateFile)(AvmHookEntryNtCreateFile->OriginalRoutineAddress))(
    FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
    AllocationSize,
    FileAttributes,
    ShareAccess,
    CreateDisposition,
    CreateOptions,
    EaBuffer,
    EaLength);
}

NTSTATUS
NTAPI
AvmHookNtOpenFile(
  __out PHANDLE FileHandle,
  __in ACCESS_MASK DesiredAccess,
  __in POBJECT_ATTRIBUTES ObjectAttributes,
  __out PIO_STATUS_BLOCK IoStatusBlock,
  __in ULONG ShareAccess,
  __in ULONG OpenOptions
  )
{
  PWCHAR FileNameBuffer = NULL;
  USHORT FileNameLength = 0;

  if (ObjectAttributes && ObjectAttributes->ObjectName)
  {
    FileNameBuffer = ObjectAttributes->ObjectName->Buffer;
    FileNameLength = ObjectAttributes->ObjectName->Length;
  }

  AvmHookCreateEvent(
    AHF_NTOPENFILE,
    AHEPT_INTEGER, 4, DesiredAccess,
    AHEPT_INTEGER, 4, OpenOptions,
    AHEPT_UNICODE_STRING, FileNameLength, FileNameBuffer,
    AHEPT_VOID);

  return ((pfnNtOpenFile)(AvmHookEntryNtOpenFile->OriginalRoutineAddress))(
    FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
    ShareAccess,
    OpenOptions);
}

NTSTATUS
NTAPI
AvmHookNtReadVirtualMemory(
  __in HANDLE ProcessHandle,
  __in_opt PVOID BaseAddress,
  __out_bcount(BufferSize) PVOID Buffer,
  __in SIZE_T BufferSize,
  __out_opt PSIZE_T NumberOfBytesRead
  )
{
  return ((pfnNtReadVirtualMemory)(AvmHookEntryNtReadVirtualMemory->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    Buffer,
    BufferSize,
    NumberOfBytesRead);
}

NTSTATUS
NTAPI
AvmHookNtWriteVirtualMemory(
  __in HANDLE ProcessHandle,
  __in_opt PVOID BaseAddress,
  __in_bcount(BufferSize) CONST VOID *Buffer,
  __in SIZE_T BufferSize,
  __out_opt PSIZE_T NumberOfBytesWritten
  )
{
  return ((pfnNtWriteVirtualMemory)(AvmHookEntryNtWriteVirtualMemory->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    Buffer,
    BufferSize,
    NumberOfBytesWritten);
}

NTSTATUS
NTAPI
AvmHookEnable(
  VOID
  )
{
  if (IsListEmpty(&AvmHookList))
  {
    AvmDbgPrint("AvmHookEnable()\n");

    ANSI_STRING NtCreateFileRoutineName = RTL_CONSTANT_STRING("NtCreateFile");
    AvmHookSSDTHook(&NtCreateFileRoutineName, (PVOID)&AvmHookNtCreateFile, &AvmHookEntryNtCreateFile);

    ANSI_STRING NtOpenFileRoutineName = RTL_CONSTANT_STRING("NtOpenFile");
    AvmHookSSDTHook(&NtOpenFileRoutineName, (PVOID)&AvmHookNtOpenFile, &AvmHookEntryNtOpenFile);

    ANSI_STRING NtReadVirtualMemoryRoutineName = RTL_CONSTANT_STRING("NtReadVirtualMemory");
    AvmHookSSDTHook(&NtReadVirtualMemoryRoutineName, (PVOID)&AvmHookNtReadVirtualMemory, &AvmHookEntryNtReadVirtualMemory);

    ANSI_STRING NtWriteVirtualMemoryRoutineName = RTL_CONSTANT_STRING("NtWriteVirtualMemory");
    AvmHookSSDTHook(&NtWriteVirtualMemoryRoutineName, (PVOID)&AvmHookNtWriteVirtualMemory, &AvmHookEntryNtWriteVirtualMemory);

    InitializeListHead(&AvmHookEventList);
  }

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmHookDisable(
  VOID
  )
{
  AvmDbgPrint("AvmHookDisable()\n");

  //
  // Unhook all hooked functions (in reverse order).
  //
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

  //
  // Remove all events from the queue (in reverse order).
  //
  NextEntry = AvmHookEventList.Blink;
  while (NextEntry != &AvmHookEventList)
  {
    PAVM_HOOK_EVENT HookEvent = CONTAINING_RECORD(
      NextEntry,
      AVM_HOOK_EVENT,
      ListEntry);

    RemoveEntryList(NextEntry);
    ExFreePoolWithTag(HookEvent, AVM_HOOK_MEMORY_TAG);

    NextEntry = AvmHookEventList.Blink;
  }
}
