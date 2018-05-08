#include "entry.h"

#include "patch/patch.h"
#include "device/device.h"

#pragma warning (disable : 4100)

//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

PAVM_DESTROY_COMPONENT_ROUTINE AvmpDestroyComponentRoutineList[AVM_MAX_REGISTERED_COMPONENTS];
LONG AvmpDestroyComponentRoutineCount = 0;

PDRIVER_OBJECT AvmDriverObject;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmInitialize(
  _In_ PDRIVER_OBJECT DriverObject
  )
{
  AvmDbgPrint("[INFO] AvmInitialize >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

#pragma prefast(push)
#pragma prefast(disable:__WARNING_INACCESSIBLE_MEMBER, "Usage of DriverObject members outside of the DriverEntry")

  for (ULONG Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++)
  {
    DriverObject->MajorFunction[Index] = &AvmpDriverDispatch;
  }

  DriverObject->DriverUnload = &AvmDestroy;

#pragma prefast(pop)

  return AvmDeviceInitialize(DriverObject);
}

VOID
NTAPI
AvmDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  )
{
  AvmDbgPrint("[INFO] AvmDestroy <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

  LONG Index = AvmpDestroyComponentRoutineCount;

  while (Index-- > 0)
  {
    AvmpDestroyComponentRoutineList[Index](DriverObject);
  }
}

VOID
NTAPI
AvmRegisterDestroyComponentRoutine(
  _In_ PAVM_DESTROY_COMPONENT_ROUTINE DestroyComponentRoutine
  )
{
  NT_ASSERT(AvmpDestroyComponentRoutineCount < AVM_MAX_REGISTERED_COMPONENTS);

  AvmpDestroyComponentRoutineList[AvmpDestroyComponentRoutineCount] = DestroyComponentRoutine;
  AvmpDestroyComponentRoutineCount += 1;
}

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmpDriverDispatch(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  )
{
  PDRIVER_DISPATCH* DispatchRoutines;
  DispatchRoutines = DeviceObject->DeviceExtension;

  if (DispatchRoutines)
  {
    PIO_STACK_LOCATION IoCurrentStack;
    IoCurrentStack = IoGetCurrentIrpStackLocation(Irp);

    if (DispatchRoutines[IoCurrentStack->MajorFunction])
    {
      return DispatchRoutines[IoCurrentStack->MajorFunction](DeviceObject, Irp);
    }
  }

  Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_INVALID_DEVICE_REQUEST;
}

VOID
NTAPI
AvmpDbgPrintV(
  _In_z_ _Printf_format_string_ PCSTR Format,
  va_list Args
  )
{

}

VOID
__cdecl
AvmpDbgPrint(
  _In_z_ _Printf_format_string_ PCSTR Format,
  ...
  )
{

}

//////////////////////////////////////////////////////////////////////////
// Driver entry-point.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
DriverEntry(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
  )
{
  UNREFERENCED_PARAMETER(RegistryPath);

  AvmDriverObject = DriverObject;

  return AvmInitialize(DriverObject);
}
