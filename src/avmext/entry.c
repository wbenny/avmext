#include "entry.h"
#include "dispatch.h"
#include "ntinternal.h"
#include "rdtscemu.h"

#include <ntifs.h>

NTSTATUS
NTAPI
AvmInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  NTSTATUS Status;

  Status = AvmNtInternalInitialize(DriverObject);

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
  AvmNtInternalDestroy(DriverObject);
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