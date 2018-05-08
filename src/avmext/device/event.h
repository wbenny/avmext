#pragma once
#include "hook.h"                 // AVM_HOOK_DEFINITION.

#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _AVM_EVENT_TYPE
{
  AET_FUNCTION_CALL,
  AET_PROCESS,
  AET_THREAD,
  AET_LOAD_IMAGE,
} AVM_EVENT_TYPE, *PAVM_EVENT_TYPE;

typedef enum _AVM_EVENT_VARIANT_TYPE
{
  //
  // Types. (max 16)
  //
  AEVT_VOID                  = 0,
  AEVT_BOOL                  = 1,
  AEVT_INTEGER               = 2,
  AEVT_UNSIGNED_INTEGER      = 3,
  AEVT_FLOAT                 = 4,
  AEVT_BINARY                = 5, // Implies AEVT_HINT_PROBE.
  AEVT_STRING                = 6, // Implies AEVT_HINT_PROBE.
  AEVT_UNICODE_STRING        = 7, // Implies AEVT_HINT_PROBE.
  AEVT_ENUM                  = 8,

  //
  // Hints. (max 8)
  //
  AEVT_HINT_POINTER          = 1 << 4,
  AEVT_HINT_HEX              = 1 << 5,
  AEVT_HINT_FLAGS            = 1 << 6,
  AEVT_HINT_PROBE            = 1 << 7,
  AEVT_HINT_INDIRECT         = 1 << 8, // Deprecated.
  AEVT_HINT_INDIRECT_PROCESS = 1 << 9,
  AEVT_HINT_ERROR            = 1 << 10,

  //
  // Custom number from bit 12.
  // This allows any integer in range 0-1048575.
  // Currently, this number represents an Enum ID.
  //

  //
  // Masks.
  //
  AEVT_TYPE_MASK          = 0x0000000F,
  AEVT_HINT_MASK          = 0x00000FF0,
  AEVT_ENUM_MASK          = 0xFFFFF000,
} AVM_EVENT_VARIANT_TYPE, *PAVM_EVENT_VARIANT_TYPE;

#define AEVT_SET_ENUM(EnumId)      ((EnumId)      << 12)
#define AEVT_GET_ENUM(VariantType) ((VariantType) >> 12)

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _AVM_EVENT_VARIANT
{
  ULONG  RequestedSize;
  ULONG  Size;
  ULONG  Type; // AVM_EVENT_VARIANT_TYPE
  UCHAR  Buffer[];
} AVM_EVENT_VARIANT, *PAVM_EVENT_VARIANT;

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef struct _AVM_EVENT_FUNCTION_CALL
{
  ULONG    FunctionId;
  ULONG    FunctionParameterCount;
  ULONG    FunctionDescription;
  NTSTATUS ReturnValue;

  HANDLE   ProcessId;
  HANDLE   ThreadId;

  //
  // if (FunctionDescription)
  // {
  //   AVM_EVENT_VARIANT FunctionName;
  //   for (i .. FunctionParameterCount)
  //   {
  //     if (ParameterName->Type == AEVT_ENUM)
  //     {
  //       AVM_EVENT_VARIANT EnumName;
  //       AVM_EVENT_VARIANT EnumId;
  //       AVM_EVENT_VARIANT EnumType;
  //       AVM_EVENT_VARIANT EnumTypeSize;
  //       AVM_EVENT_VARIANT EnumElementCount;
  //
  //       struct
  //       {
  //         AVM_EVENT_VARIANT Name;
  //         AVM_EVENT_VARIANT Value;
  //       } Items[EnumElementCount];
  //     }
  //
  //     AVM_EVENT_VARIANT ParameterName;
  //   }
  // }
  //
  // for (i .. FunctionParameterCount)
  // {
  //   AVM_EVENT_VARIANT ParameterValue;
  // }
  //
} AVM_EVENT_FUNCTION_CALL, *PAVM_EVENT_FUNCTION_CALL;

//
// Process create and exit.
//
typedef struct _AVM_EVENT_PROCESS
{
  BOOLEAN Created;
  HANDLE ProcessId;
  HANDLE ParentProcessId;

  //
  // if (Created)
  // {
  //   AVM_EVENT_VARIANT ImageFileName;
  // }
  //
} AVM_EVENT_PROCESS, *PAVM_EVENT_PROCESS;

typedef struct _AVM_EVENT_THREAD
{
  BOOLEAN Created;
  HANDLE ProcessId;
  HANDLE ThreadId;
} AVM_EVENT_THREAD, *PAVM_EVENT_THREAD;

typedef struct _AVM_EVENT_LOAD_IMAGE
{
  HANDLE ProcessId;
  PVOID ImageBase;
  SIZE_T ImageSize;
  AVM_EVENT_VARIANT ImageFileName;
} AVM_EVENT_LOAD_IMAGE, *PAVM_EVENT_LOAD_IMAGE;

typedef struct _AVM_EVENT
{
  //
  // Total size of this AVM_EVENT object.
  //
  ULONG Size;

  //
  // Sequence ID of this event.
  //
  ULONG SequenceId;

  //
  // Type of this event (AVM_EVENT_TYPE).
  //
  ULONG Type;

  //
  // Event data follows.
  //
  UCHAR EventData[];
} AVM_EVENT, *PAVM_EVENT;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

PAVM_EVENT
NTAPI
AvmEventAllocate(
  ULONG EventType,
  ULONG EventSize
  );

VOID
NTAPI
AvmEventFree(
  PAVM_EVENT Event
  );

//
// Event types.
//

PAVM_EVENT
NTAPI
AvmEventFunctionCallCreate(
  _In_ PAVM_HOOK_DEFINITION FunctionDefinition,
  _In_ NTSTATUS ReturnValue,
  _In_ va_list Args
  );

PAVM_EVENT
NTAPI
AvmEventProcessCreate(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ParentProcessId,
  _In_opt_ PCUNICODE_STRING ImageFileName
  );

PAVM_EVENT
NTAPI
AvmEventThreadCreate(
  _In_ BOOLEAN Created,
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId
  );

PAVM_EVENT
NTAPI
AvmEventLoadImageCreate(
  _In_ HANDLE ProcessId,
  _In_ PUNICODE_STRING FullImageName,
  _In_ PIMAGE_INFO ImageInfo
  );

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

//
// Buffer manipulation.
//

VOID
NTAPI
AvmpEventBufferWrite(
  PVOID* EventData,
  ULONG Type,
  ULONG Size,
  PVOID Data,
  BOOLEAN Simulate
  );

VOID
NTAPI
AvmpEventBufferIndirectWrite(
  PVOID* EventData,
  ULONG Type,
  ULONG Size,
  PVOID Data,
  HANDLE ProcessHandle,
  BOOLEAN Simulate
  );

//
// Functions description.
//

typedef struct _AVM_EVENT_FUNCTION_CALL_PARAMETER
{
  ULONG ParameterType;

  union
  {
    ULONG ParameterSize;
    PAVM_HOOK_DEFINITION EnumDefinition;
  };

  PCHAR ParameterName;
  PCHAR ParameterValue;
  HANDLE ProcessHandle;
} AVM_EVENT_FUNCTION_CALL_PARAMETER, *PAVM_EVENT_FUNCTION_CALL_PARAMETER;

typedef VOID (NTAPI *PAVM_EVENT_FUNCTION_CALL_PARAMETER_ROUTINE)(
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER ParameterStruct,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  );

VOID
NTAPI
AvmpEventEnumWrite(
  PVOID* EventData,
  PAVM_HOOK_DEFINITION EnumDefinition,
  BOOLEAN Simulate
  );

ULONG
NTAPI
AvmpEventFunctionCallWrite(
  _In_ PAVM_HOOK_DEFINITION FunctionDefinition,
  PAVM_EVENT_FUNCTION_CALL EventData,
  PVOID* EventPosition,
  va_list Args
  );

ULONG
NTAPI
AvmpEventFunctionCallEnumerateParameters(
  _In_ va_list Args,
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER_ROUTINE EnumRoutine,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  );

VOID
NTAPI
AvmpEventFunctionCallWriteParameterDescription(
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER ParameterStruct,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  );

VOID
NTAPI
AvmpEventFunctionCallWriteParameters(
  _In_ PAVM_EVENT_FUNCTION_CALL_PARAMETER ParameterStruct,
  _Inout_ PVOID* EventPosition,
  _In_ BOOLEAN Simulate
  );
