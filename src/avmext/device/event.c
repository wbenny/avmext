#include "event.h"
#include "queue.h"
#include "device.h"
#include "entry.h"

#include "nt/mmapi.h"
#include "utils/memory.h"

#include <stdarg.h>

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define AVM_EVENT_MEMORY_TAG 'DmvA'

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

PAVM_EVENT
NTAPI
AvmEventAllocate(
  ULONG EventType,
  ULONG EventDataSize
  )
{
  //
  // Compute real sizes.
  //
  ULONG EventSize = sizeof(AVM_EVENT) + EventDataSize;

  if (EventSize > AvmDeviceExtension->EventQueue.ItemSizeLimit)
  {
    //
    // Event entry too big!
    //
    AvmDbgPrint(
      "[WARNING] Trying to allocate too big event (%u, size limit: %u)\n",
      EventSize,
      AvmDeviceExtension->EventQueue.ItemSizeLimit);

    return NULL;
  }

  PAVM_EVENT Event;
  Event = ExAllocatePoolWithTag(
    NonPagedPoolNx,
    EventSize,
    AVM_EVENT_MEMORY_TAG);

  if (!Event)
  {
    // return STATUS_INSUFFICIENT_RESOURCES;
    return NULL;
  }

  static volatile ULONG AvmHookEventListId = -1;
  Event->SequenceId = InterlockedIncrement(&AvmHookEventListId);
  Event->Size = EventSize;
  Event->Type = EventType;

  return Event;
}

VOID
NTAPI
AvmEventFree(
  PAVM_EVENT Event
  )
{
  ExFreePoolWithTag(Event, AVM_EVENT_MEMORY_TAG);
}

PAVM_EVENT
NTAPI
AvmEventFunctionCallCreate(
  _In_ PAVM_HOOK_DEFINITION FunctionDefinition,
  _In_ NTSTATUS ReturnValue,
  _In_ va_list Args
  )
{
  //
  // Check if we already sent function description or not.
  //
  PAVM_EVENT Event;

  KeAcquireGuardedMutex(&FunctionDefinition->DescriptionSentLock);
  do
  {
    //
    // Ask for a size of EventData.
    //
    ULONG EventParameterListSize = AvmpEventFunctionCallWrite(
      FunctionDefinition,
      NULL,
      NULL,
      Args);

    //
    // Build event.
    //
    ULONG EventDataSize = sizeof(AVM_EVENT_FUNCTION_CALL) + EventParameterListSize;

    Event = AvmEventAllocate(AET_FUNCTION_CALL, EventDataSize);

    if (!Event)
    {
      break;
    }

    //
    // Build event data.
    //
    PAVM_EVENT_FUNCTION_CALL EventData = (PAVM_EVENT_FUNCTION_CALL)Event->EventData;
    EventData->FunctionId              = FunctionDefinition->Id;
    EventData->FunctionParameterCount  = 0;
    EventData->FunctionDescription     = !FunctionDefinition->DescriptionSent;
    EventData->ReturnValue             = ReturnValue;
    EventData->ProcessId               = PsGetCurrentProcessId();
    EventData->ThreadId                = PsGetCurrentThreadId();

    PVOID EventPosition = (PVOID)((PUCHAR)EventData + sizeof(AVM_EVENT_FUNCTION_CALL));

    //
    // Write the description.
    //
    AvmpEventFunctionCallWrite(
      FunctionDefinition,
      EventData,
      &EventPosition,
      Args);

  } while (FALSE);
  KeReleaseGuardedMutex(&FunctionDefinition->DescriptionSentLock);

  return Event;
}

PAVM_EVENT
NTAPI
AvmEventProcessCreate(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ParentProcessId,
  _In_opt_ PCUNICODE_STRING ImageFileName
  )
{
  ULONG EventDataSize = sizeof(AVM_EVENT_PROCESS);

  if (Created && ImageFileName)
  {
    EventDataSize += sizeof(AVM_EVENT_VARIANT) + ImageFileName->Length;
  }

  PAVM_EVENT Event = AvmEventAllocate(AET_PROCESS, EventDataSize);

  if (!Event)
  {
    return NULL;
  }

  //
  // Build event data.
  //
  PAVM_EVENT_PROCESS EventData = (PAVM_EVENT_PROCESS)Event->EventData;
  EventData->Created = Created;
  EventData->ProcessId = ProcessId;
  EventData->ParentProcessId = ParentProcessId;

  if (Created && ImageFileName)
  {
    PVOID ImageFileNameBuffer = (PAVM_EVENT_VARIANT)((PUCHAR)EventData + sizeof(AVM_EVENT_PROCESS));
    AvmpEventBufferWrite(&ImageFileNameBuffer, AEVT_UNICODE_STRING, ImageFileName->Length, ImageFileName->Buffer, FALSE);
  }

  return Event;
}

PAVM_EVENT
NTAPI
AvmEventThreadCreate(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId
  )
{
  ULONG EventDataSize = sizeof(AVM_EVENT_THREAD);

  PAVM_EVENT Event = AvmEventAllocate(AET_THREAD, EventDataSize);

  if (!Event)
  {
    return NULL;
  }

  //
  // Build event data.
  //
  PAVM_EVENT_THREAD EventData = (PAVM_EVENT_THREAD)Event->EventData;
  EventData->Created = Created;
  EventData->ProcessId = ProcessId;
  EventData->ThreadId = ThreadId;

  return Event;
}

PAVM_EVENT
NTAPI
AvmEventLoadImageCreate(
  _In_ HANDLE ProcessId,
  _In_ PUNICODE_STRING FullImageName,
  _In_ PIMAGE_INFO ImageInfo
  )
{
  //
  // If FullImageName == NULL, redirect it to the empty string.
  //
  static UNICODE_STRING EmptyUnicodeString = RTL_CONSTANT_STRING(L"");
  FullImageName = FullImageName ? FullImageName : &EmptyUnicodeString;

  ULONG EventDataSize = sizeof(AVM_EVENT_LOAD_IMAGE) + FullImageName->Length;

  PAVM_EVENT Event = AvmEventAllocate(AET_LOAD_IMAGE, EventDataSize);

  if (!Event)
  {
    return NULL;
  }

  //
  // Build event data.
  //
  PAVM_EVENT_LOAD_IMAGE EventData = (PAVM_EVENT_LOAD_IMAGE)Event->EventData;
  EventData->ProcessId = ProcessId;
  EventData->ImageBase = ImageInfo ? ImageInfo->ImageBase : NULL;
  EventData->ImageSize = ImageInfo ? ImageInfo->ImageSize : 0;

  PVOID ImageFileNameVariantAddress = &EventData->ImageFileName;
  AvmpEventBufferWrite(&ImageFileNameVariantAddress, AEVT_UNICODE_STRING, FullImageName->Length, FullImageName->Buffer, FALSE);

  return Event;
}

VOID
NTAPI
AvmpEventBufferWrite(
  PVOID* EventData,
  ULONG Type,
  ULONG Size,
  PVOID Data,
  BOOLEAN Simulate
  )
{
  NT_ASSERT((Type & (AEVT_HINT_INDIRECT | AEVT_HINT_INDIRECT_PROCESS)) == 0);

  PAVM_EVENT_VARIANT EventBuffer = *EventData;

  ULONG RequestedSize = Size;
  Size = min(Size, AvmDeviceExtension->EventQueue.VariantSizeLimit);

  if (!Simulate)
  {
    EventBuffer->Type = Type;
    EventBuffer->RequestedSize = RequestedSize;
    EventBuffer->Size = Size;

    switch (Type & AEVT_TYPE_MASK)
    {
      case AEVT_BOOL:
      case AEVT_INTEGER:
      case AEVT_UNSIGNED_INTEGER:
      case AEVT_FLOAT:
        if (Type & AEVT_HINT_PROBE)
        {
          if (!Data)
          {
            RtlZeroMemory(EventBuffer->Buffer, Size);

            EventBuffer->Type |= AEVT_HINT_ERROR;
          }
          else
          {
            __try
            {
              RtlCopyMemory(EventBuffer->Buffer, Data, Size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
              RtlZeroMemory(EventBuffer->Buffer, Size);

              EventBuffer->Type |= AEVT_HINT_ERROR;
            }
          }
        }
        else
        {
          RtlCopyMemory(EventBuffer->Buffer, &Data, Size);
        }
        break;

      case AEVT_BINARY:
      case AEVT_STRING:
      case AEVT_UNICODE_STRING:
        if (Data)
        {
          BOOLEAN ExceptionAddressConfirmed = FALSE;
          ULONG_PTR BadVa = 0;

          __try
          {
            RtlCopyMemory(EventBuffer->Buffer, Data, Size);
          }
          __except (AvmMiGetExceptionInfo(GetExceptionInformation(),
                                          &ExceptionAddressConfirmed,
                                          &BadVa))
          {
            if (ExceptionAddressConfirmed)
            {
              Size = EventBuffer->Size = (ULONG)(BadVa - (ULONG_PTR)Data);
            }
            else
            {
              Size = EventBuffer->Size = 0;
            }

            EventBuffer->Type |= AEVT_HINT_ERROR;
          }
        }
        break;

      case AEVT_ENUM:
        break;

      default:
        NT_ASSERT(0 && "Invalid variant type!");
        break;
    }
  }

  //
  // Advance the pointer.
  //
  *EventData = (PVOID)((PUCHAR)EventBuffer + sizeof(AVM_EVENT_VARIANT) + Size);
}

VOID
NTAPI
AvmpEventBufferIndirectWrite(
  PVOID* EventData,
  ULONG Type,
  ULONG Size,
  PVOID Data,
  HANDLE ProcessHandle,
  BOOLEAN Simulate
  )
{
  NT_ASSERT((Type & (AEVT_HINT_INDIRECT | AEVT_HINT_INDIRECT_PROCESS)) != 0);

  PAVM_EVENT_VARIANT EventBuffer = *EventData;

  ULONG RequestedSize = Size;
  Size = min(Size, AvmDeviceExtension->EventQueue.VariantSizeLimit);

  if (!Simulate)
  {
    EventBuffer->Type = Type;
    EventBuffer->RequestedSize = RequestedSize;
    EventBuffer->Size = 0;

    NTSTATUS Status;
    PEPROCESS ProcessObject;
    Status = ObReferenceObjectByHandle(
      ProcessHandle,
      PROCESS_ALL_ACCESS,
      NULL,
      KernelMode,
      &ProcessObject,
      NULL);

    if (NT_SUCCESS(Status))
    {
      SIZE_T NumberOfBytesRead = 0;
      switch (Type & AEVT_TYPE_MASK)
      {
        case AEVT_BINARY:
        case AEVT_STRING:
        case AEVT_UNICODE_STRING:
          Status = MmCopyVirtualMemory(
            ProcessObject,
            Data,
            PsGetCurrentProcess(),
            EventBuffer->Buffer,
            Size,
            KernelMode,
            &NumberOfBytesRead);
          break;

        default:
          NT_ASSERT(0);
          break;
      }

      Size = EventBuffer->Size = (ULONG)NumberOfBytesRead;

      //
      // Dereference the process object.
      //
      ObDereferenceObject(ProcessObject);
    }
  }

  //
  // Advance the pointer.
  //
  *EventData = (PVOID)((PUCHAR)EventBuffer + sizeof(AVM_EVENT_VARIANT) + Size);
}

VOID
NTAPI
AvmpEventEnumWrite(
  PVOID* EventData,
  PAVM_HOOK_DEFINITION EnumDefinition,
  BOOLEAN Simulate
  )
{
  //
  // Announce incoming enum definition.
  //
  AvmpEventBufferWrite(
    EventData,
    AEVT_ENUM,
    0,
    NULL,
    Simulate);

  //
  // Serialize.
  //
  ULONG EnumElementCount = 0;

  while (EnumDefinition->Enum.Items[EnumElementCount].Name.Buffer)
  {
    EnumElementCount += 1;
  };

  AvmpEventBufferWrite(
    EventData,
    AEVT_STRING,
    (ULONG)EnumDefinition->Name.Length,
    EnumDefinition->Name.Buffer,
    Simulate);

  AvmpEventBufferWrite(
    EventData,
    AEVT_INTEGER,
    sizeof(ULONG),
    (PVOID)EnumDefinition->Id,
    Simulate);

  AvmpEventBufferWrite(
    EventData,
    AEVT_INTEGER,
    sizeof(ULONG),
    (PVOID)EnumDefinition->Enum.EnumType,
    Simulate);

  AvmpEventBufferWrite(
    EventData,
    AEVT_INTEGER,
    sizeof(ULONG),
    (PVOID)EnumDefinition->Enum.EnumTypeSize,
    Simulate);

  AvmpEventBufferWrite(
    EventData,
    AEVT_INTEGER,
    sizeof(ULONG),
    (PVOID)EnumElementCount,
    Simulate);

  for (ULONG Index = 0; Index < EnumElementCount; Index++)
  {
    AvmpEventBufferWrite(
      EventData,
      AEVT_STRING,
      (ULONG)EnumDefinition->Enum.Items[Index].Name.Length,
      EnumDefinition->Enum.Items[Index].Name.Buffer,
      Simulate);

    AvmpEventBufferWrite(
      EventData,
      AEVT_INTEGER,
      sizeof(ULONG),
      (PVOID)EnumDefinition->Enum.Items[Index].Value,
      Simulate);
  }
}

ULONG
NTAPI
AvmpEventFunctionCallWrite(
  _In_ PAVM_HOOK_DEFINITION FunctionDefinition,
  PAVM_EVENT_FUNCTION_CALL EventData,
  PVOID* EventPosition,
  va_list Args
  )
{
  //
  // Capture value of the EventPosition.
  // If the EventPosition is NULL,
  // we're going to simulate the write
  // in order to get the required size of the buffer.
  //
  PVOID CapturedEventPosition = EventPosition
    ? *EventPosition
    : NULL;

  //
  // Save the current position.
  //
  PVOID EventPositionStart = CapturedEventPosition;

  //
  // If no EventPosition was provided,
  // we're going to simulate.
  //
  BOOLEAN Simulate = CapturedEventPosition == NULL;

  //
  // Check if this function description has already been sent.
  //
  BOOLEAN DescriptionSent = FunctionDefinition->DescriptionSent;

  if (!DescriptionSent)
  {
    //
    // Send function name.
    //
    AvmpEventBufferWrite(
      &CapturedEventPosition,
      AEVT_STRING,
      (ULONG)FunctionDefinition->Name.Length,
      FunctionDefinition->Name.Buffer,
      Simulate);

    //
    // Send parameter names.
    //
    AvmpEventFunctionCallEnumerateParameters(
      Args,
      &AvmpEventFunctionCallWriteParameterDescription,
      &CapturedEventPosition,
      Simulate);

    //
    // Mark this function as sent on the real write.
    //
    if (!Simulate)
    {
      AvmDbgPrint(
        "[DEBUG] Description of id %u sent (name: %Z, type: AHDT_FUNCTION)\n",
        FunctionDefinition->Id,
        &FunctionDefinition->Name);

      FunctionDefinition->DescriptionSent = TRUE;
    }
  }

  //
  // Write the parameter values.
  //
  ULONG NumberOfParameters = AvmpEventFunctionCallEnumerateParameters(
    Args,
    &AvmpEventFunctionCallWriteParameters,
    &CapturedEventPosition,
    Simulate);

  if (EventData)
  {
    EventData->FunctionParameterCount = NumberOfParameters;
  }

  return (ULONG)((ULONG_PTR)CapturedEventPosition - (ULONG_PTR)EventPositionStart);
}

ULONG
NTAPI
AvmpEventFunctionCallEnumerateParameters(
  _In_ va_list Args,
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER_ROUTINE EnumRoutine,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  )
{
  ULONG NumberOfParameters = 0;
  ULONG CurrentToken;
  while ((CurrentToken = va_arg(Args, ULONG)) != AEVT_VOID)
  {
    AVM_EVENT_FUNCTION_CALL_PARAMETER ParameterStruct = { 0 };

    //
    // 1st parameter is always type.
    //
    ParameterStruct.ParameterType = CurrentToken;
    ParameterStruct.ProcessHandle = NtCurrentProcess();

    if ((CurrentToken & AEVT_TYPE_MASK) == AEVT_ENUM)
    {
      //
      // If type is enum, the definition is specified
      // immediately after.
      //
      ParameterStruct.EnumDefinition = va_arg(Args, PVOID);
    }
    else
    {
      if (CurrentToken & AEVT_HINT_INDIRECT_PROCESS)
      {
        //
        // If type is a buffer which should be read from another process,
        // then process handle follows after it.
        //
        ParameterStruct.ProcessHandle = va_arg(Args, HANDLE);
      }

      ParameterStruct.ParameterSize = va_arg(Args, ULONG);
    }

    ParameterStruct.ParameterName = va_arg(Args, PCHAR);
    ParameterStruct.ParameterValue = va_arg(Args, PVOID);

    EnumRoutine(&ParameterStruct, EventPosition, Simulate);

    NumberOfParameters += 1;
  }

  return NumberOfParameters;
}

VOID
NTAPI
AvmpEventFunctionCallWriteParameterDescription(
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER ParameterStruct,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  )
{
  if ((ParameterStruct->ParameterType & AEVT_TYPE_MASK) == AEVT_ENUM)
  {
    BOOLEAN EnumDescription = ParameterStruct->EnumDefinition->DescriptionSent;

    //
    // Check if this enum description has been sent.
    //
    if (!EnumDescription)
    {
      AvmpEventEnumWrite(
        EventPosition,
        ParameterStruct->EnumDefinition,
        Simulate);

      if (!Simulate)
      {
        //
        // Mark this enum description and do not send it again.
        //
        AvmDbgPrint(
          "[DEBUG] Description of id %u sent (name: %Z, type: AHDT_ENUM)\n",
          ParameterStruct->EnumDefinition->Id,
          &ParameterStruct->EnumDefinition->Name);

        ParameterStruct->EnumDefinition->DescriptionSent = TRUE;
      }
    }
  }

  //
  // Write name of the parameter.
  //
  AvmpEventBufferWrite(
    EventPosition,
    AEVT_STRING,
    (ULONG)strlen(ParameterStruct->ParameterName),
    ParameterStruct->ParameterName,
    Simulate);
}

VOID
NTAPI
AvmpEventFunctionCallWriteParameters(
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER ParameterStruct,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  )
{
  //
  // Write all parameter values to the provided EventPosition.
  //
  if ((ParameterStruct->ParameterType & AEVT_TYPE_MASK) == AEVT_ENUM)
  {
    AvmpEventBufferWrite(
      EventPosition,
      ParameterStruct->EnumDefinition->Enum.EnumType | (ParameterStruct->ParameterType & AEVT_HINT_FLAGS) | AEVT_SET_ENUM(ParameterStruct->EnumDefinition->Id),
      ParameterStruct->EnumDefinition->Enum.EnumTypeSize,
      ParameterStruct->ParameterValue,
      Simulate);
  }
  else
  {
    if (ParameterStruct->ParameterType & (AEVT_HINT_INDIRECT | AEVT_HINT_INDIRECT_PROCESS))
    {
      AvmpEventBufferIndirectWrite(
        EventPosition,
        ParameterStruct->ParameterType,
        ParameterStruct->ParameterSize,
        ParameterStruct->ParameterValue,
        ParameterStruct->ProcessHandle,
        Simulate);
    }
    else
    {
      AvmpEventBufferWrite(
        EventPosition,
        ParameterStruct->ParameterType,
        ParameterStruct->ParameterSize,
        ParameterStruct->ParameterValue,
        Simulate);
    }
  }
}
