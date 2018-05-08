#pragma once
#include <ntifs.h>

#pragma warning (disable : 4200)

//
// Structures.
//

typedef enum _AVM_HOOK_FUNCTION
{
  AHF_NTCREATEFILE,
  AHF_NTOPENFILE,
} AVM_HOOK_FUNCTION, *PAVM_HOOK_FUNCTION;

typedef enum _AVM_HOOK_EVENT_PARAMETER_TYPE
{
  AHEPT_VOID,
  AHEPT_BOOL,
  AHEPT_INTEGER,
  AHEPT_UNSIGNED_INTEGER,
  // AHEPT_FLOAT,
  AHEPT_STRING,
  AHEPT_UNICODE_STRING,
  AHEPT_BINARY,
} AVM_HOOK_EVENT_PARAMETER_TYPE, *PAVM_HOOK_EVENT_PARAMETER_TYPE;

typedef struct _AVM_HOOK_EVENT_PARAMETER
{
  ULONG Size;
  ULONG Type;
  UCHAR Data[0];
} AVM_HOOK_EVENT_PARAMETER, *PAVM_HOOK_EVENT_PARAMETER;

typedef struct _AVM_HOOK_EVENT
{
  LIST_ENTRY ListEntry;

  ULONG Id;

  ULONG Size;
  ULONG Function;
  ULONG ParameterCount;

  // AVM_HOOK_EVENT_PARAMETER ParameterList[0];
} AVM_HOOK_EVENT, *PAVM_HOOK_EVENT;

extern ULONG AvmHookEventListId;
extern LIST_ENTRY AvmHookEventList;
extern KSPIN_LOCK AvmHookEventListLock;

//
// Prototypes.
//

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

//
// Public functions.
//

NTSTATUS
NTAPI
AvmHookAddWatchedProcessId(
  HANDLE ProcessId
  );
