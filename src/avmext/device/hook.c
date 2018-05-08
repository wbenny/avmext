#include "hook.h"

#include "entry.h"
#include "device.h"
#include "queue.h"
#include "patch/patch.h"
#include "nt/psapi.h"
#include "nt/rtlapi.h"
#include "utils/image.h"
#include "utils/process.h" // Needed in hook_function.inl

#pragma prefast(disable:__WARNING_SIZEOF_POINTER)

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define AVM_HOOK_MEMORY_TAG 'HmvA'

//
// Note down the first ID of the definition,
// include all definition files and
// note down the "last ID + 1" of the definition.
//
// N.B.
//   It is extremely important to not include anything in the .inl
//   files, as they may use the __COUNTER__ macro, which would result
//   in breaking our counting system.
//
//   Instead, include all headers needed in the .inl files in THIS file.
//
#define AVM_HOOK_DEFINITION_SECTION_NAME ".hdef"

#pragma section(AVM_HOOK_DEFINITION_SECTION_NAME, read, write)

CONST ULONG AvmpHookDefinitionFirst = __COUNTER__ + 1;
#include "hookdef/hook_enum.inl"
#include "hookdef/hook_function.inl"
CONST ULONG AvmpHookDefinitionLast  = __COUNTER__;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _AVM_HOOK_WATCHED_PROCESS
{
  LIST_ENTRY ListEntry;
  HANDLE ProcessId;
  BOOLEAN FollowChildrenProcesses; // NOT FULLY IMPLEMENTED
} AVM_HOOK_WATCHED_PROCESS, *PAVM_HOOK_WATCHED_PROCESS;

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmpCreateProcessNotifyRoutineEx(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
  )
{
  UNREFERENCED_PARAMETER(Process);

  if (CreateInfo && AvmHookIsProcessIdWatched(CreateInfo->ParentProcessId))
  {
    AvmHookAddWatchedProcessId(ProcessId, TRUE);

    AvmQueueProcessEvent(
      TRUE,
      ProcessId,
      CreateInfo->ParentProcessId,
      CreateInfo->ImageFileName);
  }
  else if (!CreateInfo && AvmHookIsProcessIdWatched(ProcessId))
  {
    AvmHookRemoveWatchedProcessId(ProcessId);

    AvmQueueProcessEvent(
      FALSE,
      ProcessId,
      0,
      NULL);
  }
}

VOID
NTAPI
AvmpCreateThreadNofityRoutine(
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId,
  _In_ BOOLEAN Create
  )
{
  if (AvmHookIsProcessIdWatched(ProcessId))
  {
    AvmQueueThreadEvent(
      Create,
      ProcessId,
      ThreadId);
  }
}

VOID
NTAPI
AvmpLoadImageNotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_ HANDLE ProcessId,
  _In_ PIMAGE_INFO ImageInfo
  )
{
  if (AvmHookIsProcessIdWatched(ProcessId))
  {
    AvmQueueLoadImageEvent(
      ProcessId,
      FullImageName,
      ImageInfo);
  }
}

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmHookInitialize(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  KeInitializeGuardedMutex(&DeviceExtension->Hook.Lock);

  //
  // For hook definitions we use __COUNTER__ macro to assign them unique ID.
  // But we have no guarantee that the __COUNTER__ macro wasn't used before us.
  // Therefore we mark our first and last __COUNTER__ use, so that we know the range of numbers
  // which were generated.
  //
  // N.B.
  //   It also means that the Definition->Id does not neccessary start from the number .
  //   This is fixed in the AvmpHookCreateFunctionDefinitionBuffer() function,
  //   by substraction DefinitionIndexOffset from the ID.
  //
  DeviceExtension->Hook.DefinitionIndexOffset = AvmpHookDefinitionFirst;
  DeviceExtension->Hook.DefinitionCount       = AvmpHookDefinitionLast - AvmpHookDefinitionFirst;
  DeviceExtension->Hook.DefinitionFunctionCount = 0;

  //
  // Hook definitions are located in separate RW section
  // with name defined by AVM_HOOK_DEFINITION_SECTION_NAME.
  //
  PIMAGE_SECTION_HEADER Section = AvmSectionTableFromSectionName(
    RtlImageNtHeader(AvmDriverObject->DriverStart),
    AVM_HOOK_DEFINITION_SECTION_NAME);

  DeviceExtension->Hook.DefinitionList = (PAVM_HOOK_DEFINITION)((PUCHAR)AvmDriverObject->DriverStart + Section->VirtualAddress);

  DeviceExtension->Hook.DefinitionIdToDefinitionMap = ExAllocatePoolWithTag(
    NonPagedPoolNx,
    sizeof(PAVM_HOOK_DEFINITION) * DeviceExtension->Hook.DefinitionCount,
    AVM_HOOK_MEMORY_TAG);

  if (!DeviceExtension->Hook.DefinitionIdToDefinitionMap)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  //
  // This call will determine the required size of the buffer.
  //
  AvmpHookCreateFunctionDefinitionBuffer(TRUE);

  //
  // Allocate memory.
  //
  DeviceExtension->Hook.FunctionDefinitionBuffer = ExAllocatePoolWithTag(
    NonPagedPoolNx,
    DeviceExtension->Hook.FunctionDefinitionBufferSize,
    AVM_HOOK_MEMORY_TAG);

  if (!DeviceExtension->Hook.FunctionDefinitionBuffer)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  //
  // This call will fill the buffer.
  //
  AvmpHookCreateFunctionDefinitionBuffer(FALSE);

  //
  // Initialize WatchedProcessId list.
  //
  InitializeListHead(&DeviceExtension->Hook.WatchedProcessIdList);
  KeInitializeSpinLock(&DeviceExtension->Hook.WatchedProcessIdListLock);
  DeviceExtension->Hook.WatchedProcessCount = 0;

  AvmDbgPrint("[DEBUG] Hook initialized\n");

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmHookDestroy(
  _In_ PDEVICE_OBJECT DeviceObject
  )
{
  PAVM_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

  //
  // Disable hooks first.
  //
  AvmHookDisable();

  const LARGE_INTEGER OneSecond = { (ULONG)(-1 * 1000 * 1000 * 10), -1 };
  while (AvmpHookActualFunctionCallCount > 0)
  {
    AvmDbgPrint("[INFO] AvmpHookActualFunctionCallCount: %u\n", AvmpHookActualFunctionCallCount);
    KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&OneSecond);
  }

  if (DeviceExtension->Hook.FunctionDefinitionBuffer)
  {
    ExFreePoolWithTag(DeviceExtension->Hook.FunctionDefinitionBuffer, AVM_HOOK_MEMORY_TAG);
    DeviceExtension->Hook.FunctionDefinitionBuffer = NULL;
    DeviceExtension->Hook.FunctionDefinitionBufferSize = 0;
  }

  if (DeviceExtension->Hook.DefinitionIdToDefinitionMap)
  {
    ExFreePoolWithTag(DeviceExtension->Hook.DefinitionIdToDefinitionMap, AVM_HOOK_MEMORY_TAG);
    DeviceExtension->Hook.DefinitionIdToDefinitionMap = NULL;
  }

  AvmDbgPrint("[INFO] Hook destroyed\n");
}

NTSTATUS
NTAPI
AvmHookEnable(
  VOID
  )
{
  NTSTATUS Status;

  KeAcquireGuardedMutex(&AvmDeviceExtension->Hook.Lock);
  do
  {
    if (AvmDeviceExtension->EventQueue.ActiveSources & AVM_DEVICE_SOURCE_HOOK)
    {
      //
      // Hook engine has been already enabled.
      //
      AvmDbgPrint("[WARNING] Trying to enable hook engine which is already enabled\n");

      Status = STATUS_ALREADY_COMPLETE;
      break;
    }

    //
    // Set Create/Exit Process notify routine.
    //
    Status = PsSetCreateProcessNotifyRoutineEx(&AvmpCreateProcessNotifyRoutineEx, FALSE);

    if (!NT_SUCCESS(Status))
    {
      break;
    }

    //
    // Set Create/Exit Thread notify routine.
    //
    Status = PsSetCreateThreadNotifyRoutine(&AvmpCreateThreadNofityRoutine);

    if (!NT_SUCCESS(Status))
    {
      break;
    }

    //
    // Set LoadImage notify routine.
    //
    Status = PsSetLoadImageNotifyRoutine(&AvmpLoadImageNotifyRoutine);

    if (!NT_SUCCESS(Status))
    {
      break;
    }

    //
    // Set DescriptionSent = FALSE to all definitions.
    //
    AvmpHookResetDescriptionSentStatus();

    AvmDeviceExtension->EventQueue.ActiveSources |= AVM_DEVICE_SOURCE_HOOK;
  } while (FALSE);
  KeReleaseGuardedMutex(&AvmDeviceExtension->Hook.Lock);

  return Status;
}

VOID
NTAPI
AvmHookDisable(
  VOID
  )
{
  KeAcquireGuardedMutex(&AvmDeviceExtension->Hook.Lock);
  do
  {
    if (!(AvmDeviceExtension->EventQueue.ActiveSources & AVM_DEVICE_SOURCE_HOOK))
    {
      //
      // Hook engine was not enabled.
      //
      AvmDbgPrint("[WARNING] Trying to disable hook engine which is already disabled\n");

      break;
    }

    //
    // Unpatch all functions.
    //
    AvmHookUnsetAll();

    //
    // Remove notify routines.
    //
    PsRemoveLoadImageNotifyRoutine(&AvmpLoadImageNotifyRoutine);
    PsRemoveCreateThreadNotifyRoutine(&AvmpCreateThreadNofityRoutine);
    PsSetCreateProcessNotifyRoutineEx(&AvmpCreateProcessNotifyRoutineEx, TRUE);

    //
    // Flush EventQueue.
    //
    // REVIEW: This should be eventually moved somewhere else,
    //         because we don't want to flush queue here if more
    //         sources are still active.
    //
    AvmQueueFlush();

    //
    // Fire an EventQueue event.
    //
    // There can be race between check of "EventQueueActiveSources"
    // and waiting for EventQueueEvent in the PollingThread.
    // Setting this event will result in unlocking the wait.
    //
    KeSetEvent(&AvmDeviceExtension->EventQueue.QueueEvent, 0, FALSE);

    //
    // Clean watched ProcessId list.
    //
    AvmHookRemoveAllWatchedProcessIds();

    AvmDeviceExtension->EventQueue.ActiveSources &= ~AVM_DEVICE_SOURCE_HOOK;

    AvmDbgPrint("[INFO] Hook disabled\n");
  } while (FALSE);
  KeReleaseGuardedMutex(&AvmDeviceExtension->Hook.Lock);
}

NTSTATUS
NTAPI
AvmHookSet(
  ULONG FunctionId,
  BOOLEAN Enable
  )
{
  if (FunctionId >= AvmDeviceExtension->Hook.DefinitionCount)
  {
    //
    // Index out of range.
    //
    AvmDbgPrint(
      "[WARNING] Request to set function hook with invalid ID: %u\n",
      FunctionId);

    return STATUS_INVALID_PARAMETER;
  }

  PAVM_HOOK_DEFINITION FunctionDefinition = AvmDeviceExtension->Hook.DefinitionIdToDefinitionMap[FunctionId];

  if (FunctionDefinition->Type != AHDT_FUNCTION)
  {
    //
    // Trying to hook non-function object.
    //
    AvmDbgPrint(
      "[WARNING] Request to set function hook on non-function definition (ID: %u)\n",
      FunctionId);

    return STATUS_INVALID_PARAMETER;
  }

  NTSTATUS Status = STATUS_SUCCESS;

  KeAcquireGuardedMutex(&FunctionDefinition->Function.PatchLock);
  {
    AvmDbgPrint(
      "[INFO] %s hook for FunctionId: %u (%Z)\n",
      Enable ? "Setting" : "Unsetting",
      FunctionId,
      FunctionDefinition->Name);

    if (Enable)
    {
      if (!FunctionDefinition->Function.PatchEnabled)
      {
        Status = AvmPatchSSDTHook(
          &FunctionDefinition->Name,
          FunctionDefinition->Function.NewFunctionAddress,
          &FunctionDefinition->Function.SSDTEntry);
      }
      else
      {
        AvmDbgPrint(
          "[WARNING] Trying to hook already hooked function (id: %u, name: %Z)\n",
          FunctionId,
          FunctionDefinition->Name);
      }
    }
    else
    {
      if (FunctionDefinition->Function.PatchEnabled)
      {
        Status = AvmPatchSSDTUnhook(FunctionDefinition->Function.SSDTEntry);
      }
      else
      {
        AvmDbgPrint(
          "[WARNING] Trying to unhook already unhooked function (id: %u, name: %Z)\n",
          FunctionId,
          FunctionDefinition->Name);
      }
    }

    if (NT_SUCCESS(Status))
    {
      FunctionDefinition->Function.PatchEnabled = Enable;
    }
    else
    {
      AvmDbgPrint(
        "[ERROR] Error 0x%08X while patching function (id: %u, name: %Z)\n",
        Status,
        FunctionId,
        FunctionDefinition->Name);
    }
  }
  KeReleaseGuardedMutex(&FunctionDefinition->Function.PatchLock);

  return Status;
}

VOID
NTAPI
AvmHookUnsetAll(
  VOID
  )
{
  for (ULONG Index = 0; Index < AvmDeviceExtension->Hook.DefinitionCount; Index++)
  {
    PAVM_HOOK_DEFINITION FunctionDefinition = &AvmDeviceExtension->Hook.DefinitionList[Index];

    if (FunctionDefinition->Type != AHDT_FUNCTION)
    {
      continue;
    }

    KeAcquireGuardedMutex(&FunctionDefinition->Function.PatchLock);
    {
      if (FunctionDefinition->Function.PatchEnabled)
      {
        NTSTATUS Status = AvmPatchSSDTUnhook(FunctionDefinition->Function.SSDTEntry);

        if (!NT_SUCCESS(Status))
        {
          AvmDbgPrint(
            "[WARNING] Error 0x%08X while unhooking function (id: %u, name: %Z)\n",
            Status,
            FunctionDefinition->Id,
            FunctionDefinition->Name);
        }
      }

      FunctionDefinition->Function.PatchEnabled = FALSE;
    }
    KeReleaseGuardedMutex(&FunctionDefinition->Function.PatchLock);
  }

  AvmDbgPrint("[INFO] Unpatched all functions\n");

  NT_ASSERT(IsListEmpty(&AvmPatchSSDTList));
}

NTSTATUS
AvmHookAddWatchedProcessId(
  HANDLE ProcessId,
  BOOLEAN FollowChildrenProcesses
  )
{
  PAVM_HOOK_WATCHED_PROCESS NewWatchedProcess = ExAllocatePoolWithTag(
    NonPagedPoolNx,
    sizeof(AVM_HOOK_WATCHED_PROCESS),
    AVM_HOOK_MEMORY_TAG);

  if (!NewWatchedProcess)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  KIRQL OldIrql;
  KeAcquireSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, &OldIrql);
  {
    PLIST_ENTRY NextEntry = AvmDeviceExtension->Hook.WatchedProcessIdList.Blink;
    while (NextEntry != &AvmDeviceExtension->Hook.WatchedProcessIdList)
    {
      PAVM_HOOK_WATCHED_PROCESS WatchedProcess = CONTAINING_RECORD(
        NextEntry,
        AVM_HOOK_WATCHED_PROCESS,
        ListEntry);

      if (WatchedProcess->ProcessId == ProcessId)
      {
        AvmDbgPrint(
          "[WARNING] Attempt to add already watched PID: %u (WatchedProcessCount: %u)\n",
          ProcessId,
          AvmDeviceExtension->Hook.WatchedProcessCount);

        ExFreePoolWithTag(NewWatchedProcess, AVM_HOOK_MEMORY_TAG);
        goto ProcessIdAlreadyWatched;
      }

      NextEntry = NextEntry->Blink;
    }

    //
    // If we're here, the Process ID is not watched yet.
    //
    NewWatchedProcess->ProcessId = ProcessId;
    NewWatchedProcess->FollowChildrenProcesses = FollowChildrenProcesses;
    InsertTailList(&AvmDeviceExtension->Hook.WatchedProcessIdList, &NewWatchedProcess->ListEntry);
    AvmDeviceExtension->Hook.WatchedProcessCount += 1;

    AvmDbgPrint(
      "[INFO] Added watched PID: %u (WatchedProcessCount: %u)\n",
      ProcessId,
      AvmDeviceExtension->Hook.WatchedProcessCount);

  ProcessIdAlreadyWatched:
    NOTHING;
  }
  KeReleaseSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, OldIrql);

  return STATUS_SUCCESS;
}

NTSTATUS
AvmHookRemoveWatchedProcessId(
  HANDLE ProcessId
  )
{
  NTSTATUS Status = STATUS_NOT_FOUND;

  KIRQL OldIrql;
  KeAcquireSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, &OldIrql);
  {
    PLIST_ENTRY NextEntry = AvmDeviceExtension->Hook.WatchedProcessIdList.Blink;
    while (NextEntry != &AvmDeviceExtension->Hook.WatchedProcessIdList)
    {
      PAVM_HOOK_WATCHED_PROCESS WatchedProcess = CONTAINING_RECORD(
        NextEntry,
        AVM_HOOK_WATCHED_PROCESS,
        ListEntry);

      if (WatchedProcess->ProcessId == ProcessId)
      {
        RemoveEntryList(NextEntry);
        ExFreePoolWithTag(WatchedProcess, AVM_HOOK_MEMORY_TAG);

        AvmDeviceExtension->Hook.WatchedProcessCount -= 1;

        AvmDbgPrint(
          "[INFO] Removed watched PID: %u (WatchedProcessCount: %u)\n",
          ProcessId,
          AvmDeviceExtension->Hook.WatchedProcessCount);

        Status = STATUS_SUCCESS;
        break;
      }

      NextEntry = NextEntry->Blink;
    }
  }
  KeReleaseSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, OldIrql);

  return Status;
}

BOOLEAN
NTAPI
AvmHookIsProcessIdWatched(
  HANDLE ProcessId
  )
{
  BOOLEAN Result = FALSE;

  KIRQL OldIrql;
  KeAcquireSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, &OldIrql);
  {
    PLIST_ENTRY NextEntry = AvmDeviceExtension->Hook.WatchedProcessIdList.Blink;
    while (NextEntry != &AvmDeviceExtension->Hook.WatchedProcessIdList)
    {
      PAVM_HOOK_WATCHED_PROCESS WatchedProcess = CONTAINING_RECORD(
        NextEntry,
        AVM_HOOK_WATCHED_PROCESS,
        ListEntry);

      if (WatchedProcess->ProcessId == ProcessId)
      {
        Result = TRUE;
        break;
      }

      NextEntry = NextEntry->Blink;
    }
  }
  KeReleaseSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, OldIrql);

  return Result;
}

VOID
NTAPI
AvmHookRemoveAllWatchedProcessIds(
  VOID
  )
{
  KIRQL OldIrql;
  KeAcquireSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, &OldIrql);
  {
    PLIST_ENTRY NextEntry = AvmDeviceExtension->Hook.WatchedProcessIdList.Blink;
    while (NextEntry != &AvmDeviceExtension->Hook.WatchedProcessIdList)
    {
      PAVM_HOOK_WATCHED_PROCESS WatchedProcess = CONTAINING_RECORD(
        NextEntry,
        AVM_HOOK_WATCHED_PROCESS,
        ListEntry);

      RemoveEntryList(NextEntry);
      ExFreePoolWithTag(WatchedProcess, AVM_HOOK_MEMORY_TAG);

      NextEntry = AvmDeviceExtension->Hook.WatchedProcessIdList.Blink;
    }

    AvmDbgPrint(
      "[INFO] Removed all watched PIDs (previous WatchedProcessCount: %u)\n",
      AvmDeviceExtension->Hook.WatchedProcessCount);

    AvmDeviceExtension->Hook.WatchedProcessCount = 0;
  }
  KeReleaseSpinLock(&AvmDeviceExtension->Hook.WatchedProcessIdListLock, OldIrql);
}

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmpHookCreateFunctionDefinitionBuffer(
  _In_ BOOLEAN Simulate
  )
{
  PVOID Data = Simulate
    ? NULL
    : AvmDeviceExtension->Hook.FunctionDefinitionBuffer;

  PVOID DataBegin = Data;

  //
  // Function count.
  //
  AvmpEventBufferWrite(
    &Data,
    AEVT_INTEGER,
    sizeof(ULONG),
    (PVOID)AvmDeviceExtension->Hook.DefinitionFunctionCount,
    Simulate);

  for (ULONG Index = 0; Index < AvmDeviceExtension->Hook.DefinitionCount; Index++)
  {
    //
    // If we're simulating the write, the DefinitionIdToDefinitionMap is not initialized yet.
    // If we're not simulating, write the definitions ordered by ID.
    //
    PAVM_HOOK_DEFINITION Definition = Simulate
      ? &AvmDeviceExtension->Hook.DefinitionList[Index]
      : AvmDeviceExtension->Hook.DefinitionIdToDefinitionMap[Index];

    if (Simulate)
    {
      //
      // Simulate == TRUE means we're doing a first run.
      // Let's take this oportunity to initialize few stuff.
      //
      KeInitializeGuardedMutex(&Definition->DescriptionSentLock);
      Definition->DescriptionSent = FALSE;

      switch (Definition->Type)
      {
        case AHDT_ENUM:
          NOTHING;
          break;

        case AHDT_FUNCTION:
          KeInitializeGuardedMutex(&Definition->Function.PatchLock);
          Definition->Function.PatchEnabled = FALSE;
          break;

        default:
          NT_ASSERT(0);
          break;
      }

      //
      // Fix definition ID, so it begins from the 0.
      //
      Definition->Id -= AvmDeviceExtension->Hook.DefinitionIndexOffset;

      //
      // Map the definition ID to the array index in the DefinitionIdToDefinitionMap.
      // The definitions are randomly distributed throughout the section,
      // this map will help us to quickly lookup definition by index.
      //
      AvmDeviceExtension->Hook.DefinitionIdToDefinitionMap[Definition->Id] = Definition;
    }
    else
    {
      NT_ASSERT(Definition->Id == Index);
    }

    if (Definition->Type == AHDT_FUNCTION)
    {
      if (Simulate)
      {
        AvmDeviceExtension->Hook.DefinitionFunctionCount += 1;
      }
      else
      {
        AvmDbgPrint(
          "[INFO] Creating function definition (ID: %u, Function name: %Z, Category: %Z)\n",
          Definition->Id,
          &Definition->Name,
          &Definition->Function.CategoryName);
      }

      //
      // Category name.
      //
      AvmpEventBufferWrite(
        &Data,
        AEVT_STRING,
        Definition->Function.CategoryName.Length,
        Definition->Function.CategoryName.Buffer,
        Simulate);

      //
      // Function name.
      //
      AvmpEventBufferWrite(
        &Data,
        AEVT_STRING,
        Definition->Name.Length,
        Definition->Name.Buffer,
        Simulate);

      //
      // Function ID.
      //
      AvmpEventBufferWrite(&Data,
        AEVT_INTEGER,
        sizeof(Definition->Id),
        (PVOID)Definition->Id,
        Simulate);
    }
  }

  if (Simulate)
  {
    AvmDeviceExtension->Hook.FunctionDefinitionBufferSize = (ULONG)((ULONG_PTR)Data - (ULONG_PTR)DataBegin);

    AvmDbgPrint(
      "[INFO] Function definition buffer size: %u bytes\n",
      AvmDeviceExtension->Hook.FunctionDefinitionBufferSize);
  }
}

VOID
NTAPI
AvmpHookResetDescriptionSentStatus(
  VOID
  )
{
  for (ULONG Index = 0; Index < AvmDeviceExtension->Hook.DefinitionCount; Index++)
  {
    AvmDeviceExtension->Hook.DefinitionList[Index].DescriptionSent = FALSE;
  }

  AvmDbgPrint("[DEBUG] DescriptionSent resetted\n");
}
