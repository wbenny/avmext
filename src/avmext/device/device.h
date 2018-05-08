#pragma once
#include <ntifs.h>
#include "event.h"

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define AVM_DEVICE_NAME           L"\\Device\\AvmExt"
#define AVM_DEVICE_SYMBOLIC_NAME  L"\\??\\AvmExt"

#define IOCTL_AVM_HOOK_ENABLE                                               \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_DISABLE                                              \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_ADD_WATCHED_PROCESS_ID                               \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_REMOVE_WATCHED_PROCESS_ID                            \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_REMOVE_ALL_WATCHED_PROCESS_IDS                       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_SET                                                  \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_GET_FUNCTION_DEFINITION_LIST                         \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_GET_FUNCTION_DEFINITION_LIST_SIZE                    \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AVM_HOOK_UNSET                                                  \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _AVM_DEVICE_EXTENSION
{
  //
  // Must be a first member.
  // Look at AvmpDriverDispatch().
  //
  PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

  struct _AVM_DEVICE_EXTENSION_DEVICE
  {
    //
    // Zero if device is not opened, non-zero otherwise.
    //
    volatile LONG IsOpen;
  } Device;

  struct _AVM_DEVICE_EXTENSION_EVENT_QUEUE_IRP_QUEUE
  {
    //
    // Cancel-safe queue.
    //
    IO_CSQ Csq;
    KSPIN_LOCK CsqLock;

    //
    // FIFO IRP queue. (IRP->Tail.Overlay.ListEntry)
    //
    LIST_ENTRY Queue;

    //
    // This semaphore is incremented whenever a device read IRP is put in the queue.
    //
    KSEMAPHORE QueueSemaphore;
  } IrpQueue;

  struct _AVM_DEVICE_EXTENSION_EVENT_QUEUE
  {
    //
    // FIFO event queue - the oldest enqueued event
    // resides on the head of the list. (AVM_QUEUE_ENTRY)
    //
    LIST_ENTRY Queue;

    //
    // This lock protects the event queue.
    //
    KSPIN_LOCK QueueLock;

    //
    // Auto-reset event which is signaled whenever a new item
    // is enqueued into the event queue.
    //
    KEVENT QueueEvent;

    //
    //
    //
#define  AVM_DEVICE_SOURCE_HOOK   0x00000001
#define  AVM_DEVICE_SOURCE_RDTSC  0x00000002

    LONG ActiveSources;

    //
    // Maximum size of a single EVENT_VARIANT buffer.
    //
    ULONG VariantSizeLimit;

    //
    // Maximum size of a single event in bytes.
    //
    ULONG ItemSizeLimit;

    //
    // Number of events in the event queue.
    //
    ULONG ItemCount;

    //
    // Maximum number of events in the event queue.
    //
    ULONG ItemCountLimit;

    //
    // Size of the queue in bytes.
    //
    ULONG Size;

    //
    // Maximum size of a whole event queue.
    //
    ULONG SizeLimit;
  } EventQueue;

  struct _AVM_DEVICE_EXTENSION_POLLING_THREAD
  {
    //
    // Polls IRPs from the CSQ.
    //
    PETHREAD ThreadObject;

    //
    // If this variable is set to TRUE, the polling thread will exit.
    //
    BOOLEAN ShouldStop;
  } PollingThread;

  struct _AVM_DEVICE_EXTENSION_HOOK
  {
    //
    // Locks enabling, disabling, setting and unsetting hooks.
    //
    KGUARDED_MUTEX Lock;

    //
    // Pointer to the first definition in AVM_HOOK_DEFINITION_SECTION_NAME section.
    //
    PAVM_HOOK_DEFINITION DefinitionList;
    PAVM_HOOK_DEFINITION* DefinitionIdToDefinitionMap;

    //
    // Count of descriptors.
    //
    ULONG DefinitionIndexOffset;
    ULONG DefinitionCount;
    ULONG DefinitionFunctionCount;

    //
    // Pointer to the buffer which describes functions.
    //
    PVOID FunctionDefinitionBuffer;
    ULONG FunctionDefinitionBufferSize;

    //
    // List of watched process IDs (AVM_HOOK_WATCHED_PROCESS).
    //
    LIST_ENTRY WatchedProcessIdList;

    //
    // Lock of the list above.
    //
    KSPIN_LOCK WatchedProcessIdListLock;

    //
    // Actual count of watched processes.
    //
    LONG WatchedProcessCount;
  } Hook;
} AVM_DEVICE_EXTENSION, *PAVM_DEVICE_EXTENSION;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmDeviceInitialize(
  _In_ PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AvmDeviceDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  );

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
  );

VOID
NTAPI
AvmpDeviceDestroyDevice(
  _In_ PDEVICE_OBJECT DeviceObject
  );

//
// IRP queue init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeIrpQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  );

VOID
NTAPI
AvmpDeviceDestroyIrpQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  );

//
// Event queue init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeEventQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  );

VOID
NTAPI
AvmpDeviceDestroyEventQueue(
  _In_ PDEVICE_OBJECT DeviceObject
  );

//
// Polling thread init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializePollingThread(
  _In_ PDEVICE_OBJECT DeviceObject
  );

VOID
NTAPI
AvmpDeviceDestroyPollingThread(
  _In_ PDEVICE_OBJECT DeviceObject
  );

//
// Patch init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializePatch(
  _In_ PDEVICE_OBJECT DeviceObject
  );

VOID
NTAPI
AvmpDeviceDestroyPatch(
  _In_ PDEVICE_OBJECT DeviceObject
  );

//
// Hook init & destroy.
//

NTSTATUS
NTAPI
AvmpDeviceInitializeHook(
  _In_ PDEVICE_OBJECT DeviceObject
  );

VOID
NTAPI
AvmpDeviceDestroyHook(
  _In_ PDEVICE_OBJECT DeviceObject
  );


//////////////////////////////////////////////////////////////////////////
// Dispatch functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmpDevice_Create(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  );

NTSTATUS
NTAPI
AvmpDevice_Cleanup(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  );

NTSTATUS
NTAPI
AvmpDevice_Close(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  );

NTSTATUS
NTAPI
AvmpDevice_Read(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  );

NTSTATUS
NTAPI
AvmpDevice_IoControl(
  _In_ PDEVICE_OBJECT DeviceObject,
  _In_ PIRP Irp
  );

//////////////////////////////////////////////////////////////////////////
// Extern variables.
//////////////////////////////////////////////////////////////////////////

extern PAVM_DEVICE_EXTENSION AvmDeviceExtension;
