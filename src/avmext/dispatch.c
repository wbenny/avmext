#include "dispatch.h"
#include "entry.h"
#include "rdtscemu.h"

NTSTATUS
NTAPI
AvmDispatch_Create(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Irp);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmDispatch_Close(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Irp);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmDispatch_Read(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Irp);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmDispatch_Write(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Irp);

//   NTSTATUS Status = STATUS_SUCCESS;
//   PIO_STACK_LOCATION IoStackIrp = NULL;
//   PCHAR WriteDataBuffer;
// 
//   IoStackIrp = IoGetCurrentIrpStackLocation(Irp);
// 
//   if (IoStackIrp)
//   {
//     WriteDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
// 
//     if (WriteDataBuffer)
//     {
// 
//     }
//   }

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmDispatch_IoControl(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);

  NTSTATUS Status = STATUS_SUCCESS;
  PIO_STACK_LOCATION IoCurrentStack;
  ULONG InputBufferLength;
  ULONG OutputBufferLength;

  IoCurrentStack = IoGetCurrentIrpStackLocation(Irp);

  InputBufferLength  = IoCurrentStack->Parameters.DeviceIoControl.InputBufferLength;
  OutputBufferLength = IoCurrentStack->Parameters.DeviceIoControl.OutputBufferLength;

  Irp->IoStatus.Information = 0;
  Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;

  // if (Irp->MdlAddress)
  // {
  //   KdPrint(("User address: 0x%08x\n", MmGetMdlVirtualAddress(Irp->MdlAddress)));
  //   pBuf = (PCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
  // }

  KIRQL OldIrql;

  KeAcquireSpinLock(&AvmRdtscEmulationLogTableLock, &OldIrql);
  switch (IoCurrentStack->Parameters.DeviceIoControl.IoControlCode)
  {
    case IOCTL_AVM_RDTSC_EMULATION_ENABLE:
      AvmRdtscEmulationEnable();
      Irp->IoStatus.Status = STATUS_SUCCESS;
      break;

    case IOCTL_AVM_RDTSC_EMULATION_DISABLE:
      AvmRdtscEmulationDisable();
      Irp->IoStatus.Status = STATUS_SUCCESS;
      break;

    case IOCTL_AVM_RDTSC_EMULATION_GET_LOG_TABLE_SIZE_IN_BYTES:
      if (OutputBufferLength >= sizeof(AvmRdtscEmulationLogTableSizeInBytes))
      {
        RtlCopyMemory(
          Irp->AssociatedIrp.SystemBuffer,
          &AvmRdtscEmulationLogTableSizeInBytes,
          sizeof(AvmRdtscEmulationLogTableSizeInBytes));

        Irp->IoStatus.Information = sizeof(AvmRdtscEmulationLogTableSizeInBytes);
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      else
      {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
      }
      break;

    case IOCTL_AVM_RDTSC_EMULATION_GET_LOG_TABLE_ITEM_COUNT:
      if (OutputBufferLength >= sizeof(AvmRdtscEmulationLogTableItemCount))
      {
        RtlCopyMemory(
          Irp->AssociatedIrp.SystemBuffer,
          &AvmRdtscEmulationLogTableItemCount,
          sizeof(AvmRdtscEmulationLogTableItemCount));

        Irp->IoStatus.Information = sizeof(AvmRdtscEmulationLogTableItemCount);
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      else
      {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
      }
      break;

    case IOCTL_AVM_RDTSC_EMULATION_GET_LOG_TABLE_CONTENT:
      if (OutputBufferLength >= sizeof(AvmRdtscEmulationLogTable))
      {
        RtlCopyMemory(
          Irp->AssociatedIrp.SystemBuffer,
          AvmRdtscEmulationLogTable,
          sizeof(AvmRdtscEmulationLogTable));

        Irp->IoStatus.Information = sizeof(AvmRdtscEmulationLogTable);
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      else
      {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
      }
      break;

    case IOCTL_AVM_RDTSC_EMULATION_CLEAR_LOG_TABLE:
      RtlZeroMemory(
        AvmRdtscEmulationLogTable,
        sizeof(AvmRdtscEmulationLogTable));

      AvmRdtscEmulationLogTableItemCount = 0;

      Irp->IoStatus.Information = 0;
      Irp->IoStatus.Status = STATUS_SUCCESS;
      break;

    case IOCTL_AVM_RDTSC_EMULATION_GET_CONFIGURATION:
      if (OutputBufferLength >= sizeof(AvmRdtscEmulationConfiguration))
      {
        RtlCopyMemory(
          Irp->AssociatedIrp.SystemBuffer,
          &AvmRdtscEmulationConfiguration,
          sizeof(AvmRdtscEmulationConfiguration));

        Irp->IoStatus.Information = sizeof(AvmRdtscEmulationConfiguration);
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      else
      {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
      }
      break;

    case IOCTL_AVM_RDTSC_EMULATION_SET_CONFIGURATION:
      if (InputBufferLength >= sizeof(AvmRdtscEmulationConfiguration))
      {
        RtlCopyMemory(
          &AvmRdtscEmulationConfiguration,
          Irp->AssociatedIrp.SystemBuffer,
          sizeof(AvmRdtscEmulationConfiguration));

        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      else
      {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
      }
      break;
  }
  KeReleaseSpinLock(&AvmRdtscEmulationLogTableLock, OldIrql);

  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return Status;
}

NTSTATUS
NTAPI
AvmDispatchInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  NTSTATUS Status;

  UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(AVM_DEVICE_NAME);
  PDEVICE_OBJECT DeviceObject;
  Status = IoCreateDevice(
    DriverObject,
    0,
    &DeviceName,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &DeviceObject);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  DriverObject->MajorFunction[IRP_MJ_CREATE]         = &AvmDispatch_Create;
  DriverObject->MajorFunction[IRP_MJ_CLOSE]          = &AvmDispatch_Close;
  DriverObject->MajorFunction[IRP_MJ_READ]           = &AvmDispatch_Read;
  DriverObject->MajorFunction[IRP_MJ_WRITE]          = &AvmDispatch_Write;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &AvmDispatch_IoControl;
  DriverObject->DriverUnload                         = &AvmDestroy;

  DeviceObject->Flags |= DO_BUFFERED_IO;
  DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

  UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(AVM_SYMBOLIC_NAME);
  Status = IoCreateSymbolicLink(
    &SymbolicName,
    &DeviceName);

  return Status;
}

VOID
NTAPI
AvmDispatchDestroy(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(AVM_SYMBOLIC_NAME);

  IoDeleteSymbolicLink(&SymbolicName);
  IoDeleteDevice(DriverObject->DeviceObject);
}
