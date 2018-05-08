#include "device.h"

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmCsqInsertIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension;

  DeviceExtension = CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, IrpQueue.Csq);
  InsertTailList(&DeviceExtension->IrpQueue.Queue, &Irp->Tail.Overlay.ListEntry);
}

VOID
NTAPI
AvmCsqRemoveIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(Csq);

  RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

PIRP
NTAPI
AvmCsqPeekNextIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp,
  _In_ PVOID PeekContext
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension;
  PIRP NextIrp = NULL;
  PLIST_ENTRY NextEntry;
  PLIST_ENTRY ListHead;
  PIO_STACK_LOCATION IoCurrentStack;

  DeviceExtension = CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, IrpQueue.Csq);
  ListHead = &DeviceExtension->IrpQueue.Queue;

  //
  // If the IRP is NULL, we will start peeking from the listhead, else
  // we will start from that IRP onwards. This is done under the
  // assumption that new IRPs are always inserted at the tail.
  //
  if (Irp == NULL)
  {
    NextEntry = ListHead->Flink;
  }
  else
  {
    NextEntry = Irp->Tail.Overlay.ListEntry.Flink;
  }

  while (NextEntry != ListHead)
  {
    NextIrp = CONTAINING_RECORD(NextEntry, IRP, Tail.Overlay.ListEntry);

    if (PeekContext)
    {
      IoCurrentStack = IoGetCurrentIrpStackLocation(NextIrp);

      if (IoCurrentStack->FileObject == (PFILE_OBJECT)PeekContext)
      {
        break;
      }
    }
    else
    {
      break;
    }

    NextIrp = NULL;
    NextEntry = NextEntry->Flink;
  }

  return NextIrp;
}

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, IrpQueue.Csq)->CsqLock)
VOID
NTAPI
AvmCsqAcquireLock(
  _In_ PIO_CSQ Csq,
  _Out_ PKIRQL Irql
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension;

  DeviceExtension = CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, IrpQueue.Csq);
  KeAcquireSpinLock(&DeviceExtension->IrpQueue.CsqLock, Irql);
}

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, IrpQueue.Csq)->CsqLock)
VOID
NTAPI
AvmCsqReleaseLock(
  _In_ PIO_CSQ Csq,
  _In_ _IRQL_restores_ KIRQL Irql
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension;

  DeviceExtension = CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, IrpQueue.Csq);
  KeReleaseSpinLock(&DeviceExtension->IrpQueue.CsqLock, Irql);
}

VOID
NTAPI
AvmCsqCompleteCanceledIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp
  )
{
  UNREFERENCED_PARAMETER(Csq);

  Irp->IoStatus.Status = STATUS_CANCELLED;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
}
