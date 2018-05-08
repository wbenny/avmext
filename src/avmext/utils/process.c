#include "process.h"

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

_Success_(return == STATUS_SUCCESS)
NTSTATUS
NTAPI
AvmHookGetProcessIdFromProcessHandle(
  _In_ HANDLE ProcessHandle,
  _Out_ PHANDLE ProcessId
  )
{
  if (ProcessHandle == NtCurrentProcess())
  {
    *ProcessId = PsGetCurrentProcessId();
    return STATUS_SUCCESS;
  }

  NTSTATUS Status;

  PEPROCESS ProcessObject;
  Status = ObReferenceObjectByHandle(
    ProcessHandle,
    PROCESS_ALL_ACCESS,
    NULL,
    UserMode,
    &ProcessObject,
    NULL);

  if (NT_SUCCESS(Status))
  {
    *ProcessId = PsGetProcessId(ProcessObject);
    ObDereferenceObject(ProcessObject);
  }

  return Status;
}

_Success_(return == STATUS_SUCCESS)
NTSTATUS
NTAPI
AvmHookGetThreadIdFromThreadHandle(
  _In_ HANDLE ThreadHandle,
  _Out_ PHANDLE ThreadId
  )
{
  if (ThreadHandle == NtCurrentThread())
  {
    *ThreadId = PsGetCurrentThreadId();
    return STATUS_SUCCESS;
  }

  NTSTATUS Status;

  PETHREAD ThreadObject;
  Status = ObReferenceObjectByHandle(
    ThreadHandle,
    PROCESS_ALL_ACCESS,
    NULL,
    UserMode,
    &ThreadObject,
    NULL);

  if (NT_SUCCESS(Status))
  {
    *ThreadId = PsGetThreadId(ThreadObject);
    ObDereferenceObject(ThreadObject);
  }

  return Status;
}

_Success_(return == STATUS_SUCCESS)
NTSTATUS
NTAPI
AvmHookGetProcessIdFromThreadHandle(
  _In_ HANDLE ThreadHandle,
  _Out_ PHANDLE ProcessId
  )
{
  if (ThreadHandle == NtCurrentThread())
  {
    *ProcessId = PsGetCurrentProcessId();
    return STATUS_SUCCESS;
  }

  NTSTATUS Status;

  PETHREAD ThreadObject;
  Status = ObReferenceObjectByHandle(
    ThreadHandle,
    THREAD_ALL_ACCESS,
    NULL,
    UserMode,
    &ThreadObject,
    NULL);

  if (NT_SUCCESS(Status))
  {
    *ProcessId = PsGetThreadProcessId(ThreadObject);
    ObDereferenceObject(ThreadObject);
  }

  return Status;
}

