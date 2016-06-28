#include "ntinternal.h"

NTSTATUS
NTAPI
AvmNtInternalInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmNtInternalDestroy(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);
}
