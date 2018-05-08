#pragma once
#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define NT_RETURN_FAIL(Status)    \
  do {                            \
    NTSTATUS __Status = (Status); \
    if (!NT_SUCCESS(__Status)) {  \
      return __Status;            \
    }                             \
  } while (0)


#define AVM_MAX_REGISTERED_COMPONENTS 16

#define AVM_DEBUG
#ifdef AVM_DEBUG
# define AvmDbgPrint(...) DbgPrint(__VA_ARGS__)
#else
# define AvmDbgPrint(...)
#endif

//////////////////////////////////////////////////////////////////////////
// Function type definitions.
//////////////////////////////////////////////////////////////////////////

typedef VOID (NTAPI *PAVM_DESTROY_COMPONENT_ROUTINE)(
  _In_ PDRIVER_OBJECT DriverObject
  );

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmInitialize(
  _In_ PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AvmDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AvmRegisterDestroyComponentRoutine(
  _In_ PAVM_DESTROY_COMPONENT_ROUTINE DestroyComponentRoutine
  );

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmpDriverDispatch(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  );

VOID
NTAPI
AvmpDbgPrintV(
  _In_z_ _Printf_format_string_ PCSTR Format,
  va_list Args
  );

VOID
__cdecl
AvmpDbgPrint(
  _In_z_ _Printf_format_string_ PCSTR Format,
  ...
  );

//////////////////////////////////////////////////////////////////////////
// Driver entry-point.
//////////////////////////////////////////////////////////////////////////

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
NTAPI
DriverEntry(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
  );

//////////////////////////////////////////////////////////////////////////
// Extern variables.
//////////////////////////////////////////////////////////////////////////

extern PDRIVER_OBJECT AvmDriverObject;
