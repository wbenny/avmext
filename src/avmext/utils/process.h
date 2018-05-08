#pragma once
#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

_Success_(return == STATUS_SUCCESS)
NTSTATUS
NTAPI
AvmHookGetProcessIdFromProcessHandle(
  _In_ HANDLE ProcessHandle,
  _Out_ PHANDLE ProcessId
  );

_Success_(return == STATUS_SUCCESS)
NTSTATUS
NTAPI
AvmHookGetThreadIdFromThreadHandle(
  _In_ HANDLE ThreadHandle,
  _Out_ PHANDLE ThreadId
  );

_Success_(return == STATUS_SUCCESS)
NTSTATUS
NTAPI
AvmHookGetProcessIdFromThreadHandle(
  _In_ HANDLE ThreadHandle,
  _Out_ PHANDLE ProcessId
  );

