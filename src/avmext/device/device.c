#include "device.h"

#include "hook.h"
#include "entry.h"
#include "csq.h"
#include "queue.h"
#include "patch/patch.h"

//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

PAVM_DEVICE_EXTENSION AvmDeviceExtension = NULL;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmDeviceInitialize(
  _In_ PDRIVER_OBJECT DriverObject
  )
{
  PDEVICE_OBJECT DeviceObject;
  AvmpDeviceInitializeDevice(DriverObject, &DeviceObject);

  AvmpDeviceInitializeIrpQueue(DeviceObject);
  AvmpDeviceInitializeEventQueue(DeviceObject);
  AvmpDeviceInitializePollingThread(DeviceObject);
  AvmpDeviceInitializePatch(DeviceObject);
  AvmpDeviceInitializeHook(DeviceObject);

  AvmRegisterDestroyComponentRoutine(&AvmDeviceDestroy);

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmDeviceDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  )
{
  PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

  if (DeviceObject)
  {
    AvmpDeviceDestroyHook(DeviceObject);
    AvmpDeviceDestroyPatch(DeviceObject);
    AvmpDeviceDestroyPollingThread(DeviceObject);
    AvmpDeviceDestroyEventQueue(DeviceObject);
    AvmpDeviceDestroyIrpQueue(DeviceObject);
    AvmpDeviceDestroyDevice(DeviceObject);
  }
}

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

//
// Device init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeDevice(
  _In_ PDRIVER_OBJECT DriverObject,
  _Out_ PDEVICE_OBJECT* DeviceObject
  )
{
  NTSTATUS Status;

  //
  // Create device.
  //

  UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(AVM_DEVICE_NAME);
  Status = IoCreateDevice(
    DriverObject,
    sizeof(AVM_DEVICE_EXTENSION),
    &DeviceName,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    DeviceObject);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Make device extension globally available.
  //
  AvmDeviceExtension = (*DeviceObject)->DeviceExtension;

  AvmDeviceExtension->MajorFunction[IRP_MJ_CREATE]         = &AvmpDevice_Create;
  AvmDeviceExtension->MajorFunction[IRP_MJ_CLEANUP]        = &AvmpDevice_Cleanup;
  AvmDeviceExtension->MajorFunction[IRP_MJ_CLOSE]          = &AvmpDevice_Close;
  AvmDeviceExtension->MajorFunction[IRP_MJ_READ]           = &AvmpDevice_Read;
  AvmDeviceExtension->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &AvmpDevice_IoControl;

  (*DeviceObject)->Flags |= DO_DIRECT_IO;
  (*DeviceObject)->Flags &= (~DO_DEVICE_INITIALIZING);

  //
  // Create symbolic link.
  //

  UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(AVM_DEVICE_SYMBOLIC_NAME);
  Status = IoCreateSymbolicLink(
    &SymbolicName,
    &DeviceName);

  return Status;
}

VOID
NTAPI
AvmpDeviceDestroyDevice(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  //
  // Delete symbolic link.
  //

  UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(AVM_DEVICE_SYMBOLIC_NAME);
  IoDeleteSymbolicLink(&SymbolicName);

  //
  // Delete device.
  //

  IoDeleteDevice(DeviceObject);
}

//
// IRP queue init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeIrpQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension;
  DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Initialize CSQ.
  //

  IoCsqInitialize(
    &DeviceExtension->IrpQueue.Csq,
    &AvmCsqInsertIrp,
    &AvmCsqRemoveIrp,
    &AvmCsqPeekNextIrp,
    &AvmCsqAcquireLock,
    &AvmCsqReleaseLock,
    &AvmCsqCompleteCanceledIrp);

  KeInitializeSpinLock(&DeviceExtension->IrpQueue.CsqLock);

  InitializeListHead(&DeviceExtension->IrpQueue.Queue);
  KeInitializeSemaphore(&DeviceExtension->IrpQueue.QueueSemaphore, 0, MAXLONG);

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmpDeviceDestroyIrpQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);
}

//
// Event queue init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeEventQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Initialize event queue.
  //

  DeviceExtension->EventQueue.ActiveSources = 0;
  DeviceExtension->EventQueue.VariantSizeLimit = 10 * 1024 * 1024;
  DeviceExtension->EventQueue.ItemSizeLimit = MAXULONG;

  DeviceExtension->EventQueue.ItemCount = 0;
  DeviceExtension->EventQueue.ItemCountLimit = MAXULONG;

  DeviceExtension->EventQueue.Size = 0;
  DeviceExtension->EventQueue.SizeLimit = MAXULONG;

  InitializeListHead(&DeviceExtension->EventQueue.Queue);
  KeInitializeSpinLock(&DeviceExtension->EventQueue.QueueLock);
  KeInitializeEvent(&DeviceExtension->EventQueue.QueueEvent, NotificationEvent, FALSE);

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmpDeviceDestroyEventQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  UNREFERENCED_PARAMETER(DeviceExtension); // For release builds.

  NT_ASSERT(DeviceExtension->EventQueue.ActiveSources == 0);

  NT_ASSERT(DeviceExtension->EventQueue.ItemCount == 0);
  NT_ASSERT(DeviceExtension->EventQueue.Size == 0);
}

//
// Polling thread init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializePollingThread(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  NTSTATUS Status;

  PAVM_DEVICE_EXTENSION DeviceExtension;
  DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Initialize polling thread.
  //

  DeviceExtension->PollingThread.ShouldStop = FALSE;

  HANDLE ThreadHandle;
  Status = PsCreateSystemThread(
    &ThreadHandle,
    (ACCESS_MASK)0,
    NULL,
    (HANDLE)0,
    NULL,
    &AvmQueuePollingThread,
    DeviceObject);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  Status = ObReferenceObjectByHandle(
    ThreadHandle,
    THREAD_ALL_ACCESS,
    NULL,
    KernelMode,
    &DeviceExtension->PollingThread.ThreadObject,
    NULL);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  ZwClose(ThreadHandle);

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmpDeviceDestroyPollingThread(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject
    ? DeviceObject->DeviceExtension
    : NULL;

  //
  // Stop and destroy polling thread.
  //

  if (DeviceExtension && DeviceExtension->PollingThread.ThreadObject)
  {
    //
    // Signalize that polling thread should stop.
    //
    DeviceExtension->PollingThread.ShouldStop = TRUE;

    //
    // Wake up the polling thread.
    //
    KeReleaseSemaphore(
      &DeviceExtension->IrpQueue.QueueSemaphore,
      0,       // No priority boost
      1,       // Increment semaphore by 1
      FALSE);  // WaitForXxx after this call

    //
    // Wait until polling thread terminates.
    //
    KeWaitForSingleObject(
      DeviceExtension->PollingThread.ThreadObject,
      Executive,
      KernelMode,
      FALSE,
      NULL);

    ObDereferenceObject(DeviceExtension->PollingThread.ThreadObject);
  }
}

//
// Patch init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializePatch(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);

  return AvmPatchInitialize();
}

VOID
NTAPI
AvmpDeviceDestroyPatch(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);

  AvmPatchDestroy();
}

//
// Hook init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeHook(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  return AvmHookInitialize(DeviceObject);
}

VOID
NTAPI
AvmpDeviceDestroyHook(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  AvmHookDestroy(DeviceObject);
}

//////////////////////////////////////////////////////////////////////////
// Dispatch routines.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmpDevice_Create(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(Irp);

  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  if (InterlockedExchange(&DeviceExtension->Device.IsOpen, TRUE) == FALSE)
  {
    return STATUS_SUCCESS;
  }
  else
  {
    //
    // Device is already open.
    //
    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    return STATUS_UNSUCCESSFUL;
  }
}

NTSTATUS
NTAPI
AvmpDevice_Cleanup(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(Irp);

  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Flush the IRP queue.
  //
  PIRP CurrentIrp;

  while ((CurrentIrp = IoCsqRemoveNextIrp(&DeviceExtension->IrpQueue.Csq, 0)) != NULL)
  {
    CurrentIrp->IoStatus.Status = STATUS_CANCELLED;
    CurrentIrp->IoStatus.Information = 0;

    IoCompleteRequest(CurrentIrp, IO_NO_INCREMENT);
  }

  //
  // Unpatch SSDT and flush the event queue.
  //
  AvmHookDisable();

  //
  // Complete the IRP.
  //
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmpDevice_Close(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(Irp);

  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Previous state should always be TRUE,
  // because we can't close a device which wasn't successfully opened.
  //
  NT_ASSERT(DeviceExtension->Device.IsOpen);

  InterlockedExchange(&DeviceExtension->Device.IsOpen, FALSE);

  //
  // Complete the IRP.
  //
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmpDevice_Read(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Queue the IRP and return STATUS_PENDING after signalling the
  // polling thread.
  // Note: IoCsqInsertIrp marks the IRP pending.
  //
  IoCsqInsertIrp(&DeviceExtension->IrpQueue.Csq, Irp, NULL);

  //
  // A semaphore remains signaled as long as its count is greater than
  // zero, and non-signaled when the count is zero. Following function
  // increments the semaphore count by 1.
  //
  KeReleaseSemaphore(&AvmDeviceExtension->IrpQueue.QueueSemaphore, 0, 1, FALSE);

  return STATUS_PENDING;
}

NTSTATUS
NTAPI
AvmpDevice_IoControl(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(DeviceObject);

  PIO_STACK_LOCATION IoCurrentStack = IoGetCurrentIrpStackLocation(Irp);

  PVOID InputBuffer, OutputBuffer;
  ULONG InputBufferLength, OutputBufferLength;
  InputBuffer = OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
  InputBufferLength  = IoCurrentStack->Parameters.DeviceIoControl.InputBufferLength;
  OutputBufferLength = IoCurrentStack->Parameters.DeviceIoControl.OutputBufferLength;

  ULONG IoControlCode = IoCurrentStack->Parameters.DeviceIoControl.IoControlCode;

  Irp->IoStatus.Information = 0;
  Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

  switch (IoControlCode)
  {
    //
    // Enable hoooking engine.
    //
    case IOCTL_AVM_HOOK_ENABLE:
      Irp->IoStatus.Status = AvmHookEnable();
      break;

    //
    // Disable hooking engine.
    //

    case IOCTL_AVM_HOOK_DISABLE:
      AvmHookDisable();
      Irp->IoStatus.Status = STATUS_SUCCESS;
      break;

    //
    // Add PID(s) to watched process' list.
    //

    case IOCTL_AVM_HOOK_ADD_WATCHED_PROCESS_ID:
      if (
        //
        // Input buffer must carry at least one ProcessId.
        //
        InputBufferLength < sizeof(HANDLE) ||

        //
        // Input buffer length must be divisible by sizeof(HANDLE).
        //
        (InputBufferLength % sizeof(HANDLE)) != 0 ||

        //
        // If output buffer is specified, it should be big enough
        // to receive boolean value (1 byte) for each ProcessId provided.
        //
        (OutputBufferLength > 0 && OutputBufferLength < InputBufferLength / sizeof(HANDLE))
        )
      {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
      }
      else
      {
        PHANDLE ProcessIdList = (PHANDLE)InputBuffer;
        ULONG   ProcessIdCount = InputBufferLength / sizeof(HANDLE);

        PBOOLEAN ResultList = (PBOOLEAN)OutputBuffer;

        for (ULONG Index = 0; Index < ProcessIdCount; Index++)
        {
          NTSTATUS Status = AvmHookAddWatchedProcessId(ProcessIdList[Index], TRUE);

          if (OutputBufferLength > 0)
          {
            ResultList[Index] = NT_SUCCESS(Status);
          }
        }

        if (OutputBufferLength > 0)
        {
          Irp->IoStatus.Information = ProcessIdCount;
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      break;

    //
    // Remove PID(s) from watched process' list.
    //

    case IOCTL_AVM_HOOK_REMOVE_WATCHED_PROCESS_ID:
      if (
        //
        // Input buffer must carry at least one ProcessId.
        //
        InputBufferLength < sizeof(HANDLE) ||

        //
        // Input buffer length must be divisible by sizeof(HANDLE).
        //
        (InputBufferLength % sizeof(HANDLE)) != 0 ||

        //
        // If output buffer is specified, it should be big enough
        // to receive boolean value (1 byte) for each ProcessId provided.
        //
        (OutputBufferLength > 0 && OutputBufferLength < InputBufferLength / sizeof(HANDLE))
        )
      {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
      }
      else
      {
        PHANDLE ProcessIdList = (PHANDLE)InputBuffer;
        ULONG   ProcessIdCount = InputBufferLength / sizeof(HANDLE);

        PBOOLEAN ResultList = (PBOOLEAN)OutputBuffer;

        for (ULONG Index = 0; Index < ProcessIdCount; Index++)
        {
          NTSTATUS Status = AvmHookRemoveWatchedProcessId(ProcessIdList[Index]);

          if (OutputBufferLength > 0)
          {
            ResultList[Index] = NT_SUCCESS(Status);
          }
        }

        if (OutputBufferLength > 0)
        {
          Irp->IoStatus.Information = ProcessIdCount;
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      break;

    //
    // Remove all PIDs from watched process' list.
    //

    case IOCTL_AVM_HOOK_REMOVE_ALL_WATCHED_PROCESS_IDS:
      AvmHookRemoveAllWatchedProcessIds();
      Irp->IoStatus.Status = STATUS_SUCCESS;
      break;

    //
    // Set/unset hook on specified FunctionId(s).
    //

    case IOCTL_AVM_HOOK_SET:
    case IOCTL_AVM_HOOK_UNSET:
      if (
        //
        // Input buffer must carry at least one FunctionId.
        //
        InputBufferLength < sizeof(ULONG) ||

        //
        // Input buffer length must be divisible by sizeof(ULONG).
        //
        (InputBufferLength % sizeof(ULONG)) != 0 ||

        //
        // If output buffer is specified, it should be big enough
        // to receive boolean value (1 byte) for each FunctionId provided.
        //
        (OutputBufferLength > 0 && OutputBufferLength < InputBufferLength / sizeof(ULONG))
        )
      {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
      }
      else
      {
        PULONG FunctionIdList = (PULONG)InputBuffer;
        ULONG  FunctionIdCount = InputBufferLength / sizeof(ULONG);

        PBOOLEAN ResultList = (PBOOLEAN)OutputBuffer;

        for (ULONG Index = 0; Index < FunctionIdCount; Index++)
        {
          NTSTATUS Status = AvmHookSet(FunctionIdList[Index], IoControlCode == IOCTL_AVM_HOOK_SET);

          if (OutputBufferLength > 0)
          {
            ResultList[Index] = NT_SUCCESS(Status);
          }
        }

        if (OutputBufferLength > 0)
        {
          Irp->IoStatus.Information = FunctionIdCount;
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      break;

    //
    // Receive size in bytes of the function definition buffer.
    //

    case IOCTL_AVM_HOOK_GET_FUNCTION_DEFINITION_LIST_SIZE:
      if (OutputBufferLength < sizeof(ULONG))
      {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
      }
      else
      {
        *(PULONG)OutputBuffer = AvmDeviceExtension->Hook.FunctionDefinitionBufferSize;

        Irp->IoStatus.Information = sizeof(ULONG);
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      break;

    //
    // Receive the function definition buffer.
    //

    case IOCTL_AVM_HOOK_GET_FUNCTION_DEFINITION_LIST:
      if (OutputBufferLength < AvmDeviceExtension->Hook.FunctionDefinitionBufferSize)
      {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
      }
      else
      {
        RtlCopyMemory(OutputBuffer,
          AvmDeviceExtension->Hook.FunctionDefinitionBuffer,
          AvmDeviceExtension->Hook.FunctionDefinitionBufferSize);

        Irp->IoStatus.Information = AvmDeviceExtension->Hook.FunctionDefinitionBufferSize;
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
      break;

    default:
      NT_ASSERT(0);

      AvmDbgPrint("[WARNING] Unrecognized IOCTL code: 0x%08X\n", IoControlCode);
      Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
      break;
  }

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}
