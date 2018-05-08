#pragma once
#include <ntifs.h>

#include "event.h"

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmQueuePollingThread(
  _In_ PVOID Context
  );

NTSTATUS
NTAPI
AvmQueueFunctionCallEvent(
  _In_ PAVM_HOOK_DEFINITION FunctionDefinition,
  _In_ NTSTATUS ReturnValue,
  ...
  );

NTSTATUS
NTAPI
AvmQueueProcessEvent(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ParentProcessId,
  _In_opt_ PCUNICODE_STRING ImageFileName
  );

NTSTATUS
NTAPI
AvmQueueThreadEvent(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId
  );

NTSTATUS
NTAPI
AvmQueueLoadImageEvent(
  _In_ HANDLE ProcessId,
  _In_ PUNICODE_STRING FullImageName,
  _In_ PIMAGE_INFO ImageInfo
  );

VOID
NTAPI
AvmQueueFlush(
  VOID
  );

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmpQueueInsert(
  PAVM_EVENT Event
  );

NTSTATUS
NTAPI
AvmpQueueInsertEventOrFail(
  PAVM_EVENT Event
  );
