#pragma once
#include <ntifs.h>

#define AVM_DEVICE_NAME    L"\\Device\\AvmExt"
#define AVM_SYMBOLIC_NAME  L"\\??\\AvmExt"

//
// Initialize & destroy routines.
//

NTSTATUS
NTAPI
AvmInitialize(
  IN PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AvmDestroy(
  IN PDRIVER_OBJECT DriverObject
  );

//
// Driver entry-point.
//

NTSTATUS
NTAPI
DriverEntry(
  IN PDRIVER_OBJECT DriverObject,
  IN PUNICODE_STRING AvmgistryPath
  );

