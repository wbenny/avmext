#include "entry.h"

#include "nt/ntinternal.h"
#include "dispatch.h"
#include "rdtsc/rdtscemu.h"
#include "hook/hook.h"

#pragma warning (disable : 4100)

typedef NTSTATUS (NTAPI * pfnNtCreateFile)(
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
    );

typedef NTSTATUS (NTAPI * pfnNtOpenFile)(
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG ShareAccess,
    __in ULONG OpenOptions
    );

typedef NTSTATUS (NTAPI * pfnNtReadVirtualMemory)(
    __in HANDLE ProcessHandle,
    __in_opt PVOID BaseAddress,
    __out_bcount(BufferSize) PVOID Buffer,
    __in SIZE_T BufferSize,
    __out_opt PSIZE_T NumberOfBytesRead
    );


typedef NTSTATUS (NTAPI * pfnNtWriteVirtualMemory)(
    __in HANDLE ProcessHandle,
    __in_opt PVOID BaseAddress,
    __in_bcount(BufferSize) CONST VOID *Buffer,
    __in SIZE_T BufferSize,
    __out_opt PSIZE_T NumberOfBytesWritten
    );

PAVM_HOOK_ENTRY AvmHookEntryNtCreateFile = NULL;
PAVM_HOOK_ENTRY AvmHookEntryNtOpenFile = NULL;
PAVM_HOOK_ENTRY AvmHookEntryNtReadVirtualMemory = NULL;
PAVM_HOOK_ENTRY AvmHookEntryNtWriteVirtualMemory = NULL;

NTSTATUS
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
AvmHookNtOpenFile(
  __out PHANDLE FileHandle,
  __in ACCESS_MASK DesiredAccess,
  __in POBJECT_ATTRIBUTES ObjectAttributes,
  __out PIO_STATUS_BLOCK IoStatusBlock,
  __in ULONG ShareAccess,
  __in ULONG OpenOptions
  )
{
  return ((pfnNtOpenFile)(AvmHookEntryNtOpenFile->OriginalRoutineAddress))(
    FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
    ShareAccess,
    OpenOptions);
}

NTSTATUS
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
AvmInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  NTSTATUS Status;

  Status = AvmHookInitialize(DriverObject);

  ANSI_STRING NtCreateFileRoutineName = RTL_CONSTANT_STRING("NtCreateFile");
  AvmHookSSDTHook(&NtCreateFileRoutineName, (PVOID)&AvmHookNtCreateFile, &AvmHookEntryNtCreateFile);

  ANSI_STRING NtOpenFileRoutineName = RTL_CONSTANT_STRING("NtOpenFile");
  AvmHookSSDTHook(&NtOpenFileRoutineName, (PVOID)&AvmHookNtOpenFile, &AvmHookEntryNtOpenFile);

  ANSI_STRING NtReadVirtualMemoryRoutineName = RTL_CONSTANT_STRING("NtReadVirtualMemory");
  AvmHookSSDTHook(&NtReadVirtualMemoryRoutineName, (PVOID)&AvmHookNtReadVirtualMemory, &AvmHookEntryNtReadVirtualMemory);

  ANSI_STRING NtWriteVirtualMemoryRoutineName = RTL_CONSTANT_STRING("NtWriteVirtualMemory");
  AvmHookSSDTHook(&NtWriteVirtualMemoryRoutineName, (PVOID)&AvmHookNtWriteVirtualMemory, &AvmHookEntryNtWriteVirtualMemory);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  Status = AvmDispatchInitialize(DriverObject);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  Status = AvmRdtscEmulationInitialize(DriverObject);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  return Status;
}

VOID
NTAPI
AvmDestroy(
  IN PDRIVER_OBJECT DriverObject
  )
{
  AvmRdtscEmulationDestroy(DriverObject);
  AvmDispatchDestroy(DriverObject);
  AvmHookDestroy(DriverObject);
}

NTSTATUS
NTAPI
DriverEntry(
  IN PDRIVER_OBJECT DriverObject,
  IN PUNICODE_STRING AvmgistryPath
  )
{
  UNREFERENCED_PARAMETER(AvmgistryPath);

  return AvmInitialize(DriverObject);
}