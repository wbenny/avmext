#include "queue.h"

#include "device.h"
#include "entry.h"
#include "patch/patch.h"

#include <stdarg.h>

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define AVM_QUEUE_MEMORY_TAG 'DmvA'

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _AVM_QUEUE_ENTRY
{
  LIST_ENTRY ListEntry;
  PAVM_EVENT Event;
} AVM_QUEUE_ENTRY, *PAVM_QUEUE_ENTRY;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmQueuePollingThread(
  _In_ PVOID Context
  )
{
  PDEVICE_OBJECT DeviceObject = Context;
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  for (;;)
  {
    //
    // Wait indefinitely for an IRP to appear in the work queue or for
    // the Unload routine to stop the thread. Every successful return
    // from the wait decrements the semaphore count by 1.
    //
    KeWaitForSingleObject(
      &DeviceExtension->IrpQueue.QueueSemaphore,
      Executive,
      KernelMode,
      FALSE,
      NULL);

    //
    // See if thread was awakened because driver is unloading itself.
    //
    if (DeviceExtension->PollingThread.ShouldStop)
    {
      AvmDbgPrint("[INFO] Polling thread terminated\n");
      PsTerminateSystemThread(STATUS_SUCCESS);
    }

    if (!AvmDeviceExtension->EventQueue.ActiveSources)
    {
      //
      // Event queue is empty and has no active sources.
      // This means we can never get an incoming event.
      // Without this check we could deadlock on waiting for EventQueueEvent.
      //

      NT_ASSERT(
        AvmDeviceExtension->EventQueue.ItemCount == 0 &&
        AvmDeviceExtension->EventQueue.Size == 0 &&
        IsListEmpty(&AvmDeviceExtension->EventQueue.Queue)
      );

      AvmDbgPrint("[WARNING] Event queue is empty and has no active sources\n");
      continue;
    }

    //
    // Wait indifinitely for an event to appear in the event queue.
    //
    KeWaitForSingleObject(
      &DeviceExtension->EventQueue.QueueEvent,
      Executive,
      KernelMode,
      FALSE,
      NULL);

    //
    // Remove a pending IRP from the queue.
    //
    PIRP Irp = IoCsqRemoveNextIrp(&DeviceExtension->IrpQueue.Csq, NULL);

    if (!Irp)
    {
      AvmDbgPrint("[WARNING] IRP queue is empty!\n");
      continue;
    }

    Irp->IoStatus.Status = STATUS_END_OF_FILE;

    KIRQL Irql;
    KeAcquireSpinLock(&DeviceExtension->EventQueue.QueueLock, &Irql);
    {
      //
      // Sanity check if we're correctly locking the EventQueue.
      // If EventQueueItemCount > 0, the EventQueue is really not empty, or
      // if EventQueueItemCount == 0, the EventQueue is really empty.
      //
      NT_ASSERT(
        ( IsListEmpty(&DeviceExtension->EventQueue.Queue) && DeviceExtension->EventQueue.ItemCount == 0) ||
        (!IsListEmpty(&DeviceExtension->EventQueue.Queue) && DeviceExtension->EventQueue.ItemCount >  0)
      );

      //
      // Check if there is any event in the queue.
      // The queue could be flushed.
      //
      if (IsListEmpty(&DeviceExtension->EventQueue.Queue))
      {
        AvmDbgPrint("[WARNING] Event queue is empty!\n");

        //NT_ASSERT(0 && "This shouldn't happen");
      }
      else
      {
        PIO_STACK_LOCATION IoCurrentStack = IoGetCurrentIrpStackLocation(Irp);

        //
        // Get access to the user buffer.
        //
        PVOID Buffer;
        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        ULONG BufferLength;
        BufferLength = IoCurrentStack->Parameters.Read.Length;

        do
        {
          //
          // Peek an event item.
          //
          PLIST_ENTRY ListEntry = DeviceExtension->EventQueue.Queue.Flink;

          PAVM_QUEUE_ENTRY EventEntry = CONTAINING_RECORD(
            ListEntry,
            AVM_QUEUE_ENTRY,
            ListEntry);

          PAVM_EVENT Event = EventEntry->Event;

          //
          // Check if we have enough space in the buffer.
          //
          if (Irp->IoStatus.Information + Event->Size > BufferLength)
          {
            if (Irp->IoStatus.Information == 0)
            {
              //
              // Not enough data to fill even a single event.
              //
              Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            }

            break;
          }

          //
          // Actually remove the event.
          //
          RemoveHeadList(&DeviceExtension->EventQueue.Queue);
          DeviceExtension->EventQueue.ItemCount -= 1;
          DeviceExtension->EventQueue.Size -= Event->Size;

          //
          // Copy the event.
          //
          RtlCopyMemory(Buffer, Event, Event->Size);
          Buffer = (PUCHAR)Buffer + Event->Size;

          //
          // Complete the IRP and return the number of bytes we actually put into the buffer.
          //
          Irp->IoStatus.Information += Event->Size;

          AvmEventFree(Event);
          ExFreePoolWithTag(EventEntry, AVM_QUEUE_MEMORY_TAG);
        } while (!IsListEmpty(&DeviceExtension->EventQueue.Queue));

        //
        // We've satisfied the IRP.
        //
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }

      KeResetEvent(&AvmDeviceExtension->EventQueue.QueueEvent);
    }
    KeReleaseSpinLock(&DeviceExtension->EventQueue.QueueLock, Irql);

    KeFlushIoBuffers(Irp->MdlAddress, TRUE, FALSE);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
  }
}

NTSTATUS
NTAPI
AvmQueueFunctionCallEvent(
  _In_ PAVM_HOOK_DEFINITION FunctionDefinition,
  _In_ NTSTATUS ReturnValue,
  ...
  )
{
  va_list Args;
  va_start(Args, ReturnValue);

  PAVM_EVENT Event = AvmEventFunctionCallCreate(
    FunctionDefinition,
    ReturnValue,
    Args);

  va_end(Args);

  return AvmpQueueInsertEventOrFail(Event);
}

NTSTATUS
NTAPI
AvmQueueProcessEvent(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ParentProcessId,
  _In_opt_ PCUNICODE_STRING ImageFileName
  )
{
  PAVM_EVENT Event = AvmEventProcessCreate(
    Created,
    ProcessId,
    ParentProcessId,
    ImageFileName);

  return AvmpQueueInsertEventOrFail(Event);
}

NTSTATUS
NTAPI
AvmQueueThreadEvent(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId
  )
{
  PAVM_EVENT Event = AvmEventThreadCreate(
    Created,
    ProcessId,
    ThreadId);

  return AvmpQueueInsertEventOrFail(Event);
}

NTSTATUS
NTAPI
AvmQueueLoadImageEvent(
  _In_ HANDLE ProcessId,
  _In_ PUNICODE_STRING FullImageName,
  _In_ PIMAGE_INFO ImageInfo
  )
{
  PAVM_EVENT Event = AvmEventLoadImageCreate(
    ProcessId,
    FullImageName,
    ImageInfo);

  return AvmpQueueInsertEventOrFail(Event);
}

VOID
NTAPI
AvmQueueFlush(
  VOID
  )
{
  KIRQL Irql;
  KeAcquireSpinLock(&AvmDeviceExtension->EventQueue.QueueLock, &Irql);
  {
    //
    // Free memory of all events.
    //
    PLIST_ENTRY NextEntry = AvmDeviceExtension->EventQueue.Queue.Blink;
    while (NextEntry != &AvmDeviceExtension->EventQueue.Queue)
    {
      PAVM_QUEUE_ENTRY EventEntry = CONTAINING_RECORD(
        NextEntry,
        AVM_QUEUE_ENTRY,
        ListEntry);

      RemoveEntryList(NextEntry);

      AvmEventFree(EventEntry->Event);
      ExFreePoolWithTag(EventEntry, AVM_QUEUE_MEMORY_TAG);

      NextEntry = AvmDeviceExtension->EventQueue.Queue.Blink;
    }

    //
    // Reset the queue size.
    //
    AvmDeviceExtension->EventQueue.ItemCount = 0;
    AvmDeviceExtension->EventQueue.Size = 0;

    AvmDbgPrint("[INFO] Event queue flushed\n");
  }
  KeReleaseSpinLock(&AvmDeviceExtension->EventQueue.QueueLock, Irql);
}

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmpQueueInsert(
  PAVM_EVENT Event
  )
{
  PAVM_QUEUE_ENTRY EventEntry = ExAllocatePoolWithTag(
    NonPagedPoolNx,
    sizeof(AVM_QUEUE_ENTRY),
    AVM_QUEUE_MEMORY_TAG);

  if (!EventEntry)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  EventEntry->Event = Event;

  NTSTATUS Status = STATUS_SUCCESS;

  KIRQL Irql;
  KeAcquireSpinLock(&AvmDeviceExtension->EventQueue.QueueLock, &Irql);
  do
  {
    if (!AvmDeviceExtension->EventQueue.ActiveSources)
    {
      //
      // Hooking is disabled! Throw away the event.
      // To prevent memory leaks when hooking is about to be disabled,
      // it is necessary to set EventQueueActiveSources = FALSE before calling AvmQueueFlush().
      //
      AvmDbgPrint(
        "[WARNING] EventId %u has been dropped (no ActiveSources available)\n",
        Event->SequenceId);

//       Status = STATUS_UNSUCCESSFUL;
//       break;
    }

    if (AvmDeviceExtension->EventQueue.Size + Event->Size > AvmDeviceExtension->EventQueue.SizeLimit)
    {
      //
      // This event cannot fit to the event queue. (total size)
      //
      AvmDbgPrint(
        "[WARNING] EventId %u has been dropped (event size: %u, queue size: %u, size limit: %u)\n",
        Event->SequenceId,
        Event->Size,
        AvmDeviceExtension->EventQueue.Size,
        AvmDeviceExtension->EventQueue.SizeLimit);

      Status = STATUS_UNSUCCESSFUL;
      break;
    }

    if (AvmDeviceExtension->EventQueue.ItemCount + 1 > AvmDeviceExtension->EventQueue.ItemCountLimit)
    {
      //
      // This event cannot fit to the event queue. (item count)
      //
      AvmDbgPrint(
        "[WARNING] EventId %u has been dropped (cannot fit event queue - queue item count: %u)\n",
        Event->SequenceId,
        AvmDeviceExtension->EventQueue.ItemCount);

      Status = STATUS_UNSUCCESSFUL;
      break;
    }

    InsertTailList(&AvmDeviceExtension->EventQueue.Queue, &EventEntry->ListEntry);
    AvmDeviceExtension->EventQueue.ItemCount += 1;
    AvmDeviceExtension->EventQueue.Size += Event->Size;

    //
    // Announce new event.
    //
    KeSetEvent(&AvmDeviceExtension->EventQueue.QueueEvent, 0, FALSE);
  } while (FALSE);
  KeReleaseSpinLock(&AvmDeviceExtension->EventQueue.QueueLock, Irql);

  if (!NT_SUCCESS(Status))
  {
    ExFreePoolWithTag(EventEntry, AVM_QUEUE_MEMORY_TAG);
  }

  return Status;
}

NTSTATUS
NTAPI
AvmpQueueInsertEventOrFail(
  PAVM_EVENT Event
  )
{
  if (!Event)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  NTSTATUS Status = AvmpQueueInsert(Event);

  if (!NT_SUCCESS(Status))
  {
    AvmEventFree(Event);
  }

  return Status;
}
