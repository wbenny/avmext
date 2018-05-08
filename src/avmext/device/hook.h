#pragma once
#include "patch/patch.h"          // AVM_PATCH_SSDT_ENTRY

#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _AVM_HOOK_DEFINITION_TYPE
{
  AHDT_ENUM,
  AHDT_FUNCTION,
} AVM_HOOK_DEFINITION_TYPE, *PAVM_HOOK_DEFINITION_TYPE;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _AVM_HOOK_DEFINITION_ENUM_NAME_VALUE
{
  ANSI_STRING Name;
  ULONG Value;
} AVM_HOOK_DEFINITION_ENUM_NAME_VALUE, *PAVM_HOOK_DEFINITION_ENUM_NAME_VALUE;

typedef __declspec(align(16)) struct _AVM_HOOK_DEFINITION
{
  //
  // ID of the definition.
  //
  ULONG Id;

  //
  // Type of the definition.
  //
  AVM_HOOK_DEFINITION_TYPE Type;

  //
  // Name of the definition.
  //
  ANSI_STRING Name;

  //
  // Marker which will be set once the description
  // of this object will be sent to the client.
  //
  KGUARDED_MUTEX DescriptionSentLock;
  BOOLEAN DescriptionSent;

  union
  {
    struct
    {
      ULONG EnumType; // AVM_EVENT_VARIANT_TYPE
      ULONG EnumTypeSize;
      ULONG ItemCount;
      PAVM_HOOK_DEFINITION_ENUM_NAME_VALUE Items;
    } Enum;

    struct
    {
      ANSI_STRING CategoryName;
      PAVM_PATCH_SSDT_ENTRY SSDTEntry;
      PVOID NewFunctionAddress;

      //
      // Determines if the function is currently patched.
      //
      KGUARDED_MUTEX PatchLock;
      BOOLEAN PatchEnabled;
    } Function;
  };
} AVM_HOOK_DEFINITION, *PAVM_HOOK_DEFINITION;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmHookInitialize(
  _In_ PDEVICE_OBJECT DeviceObject
  );

VOID
NTAPI
AvmHookDestroy(
  _In_ PDEVICE_OBJECT DeviceObject
  );

NTSTATUS
NTAPI
AvmHookEnable(
  VOID
  );

VOID
NTAPI
AvmHookDisable(
  VOID
  );

NTSTATUS
NTAPI
AvmHookSet(
  ULONG FunctionId,
  BOOLEAN Enable
  );

VOID
NTAPI
AvmHookUnsetAll(
  VOID
  );

//
// Watched processes.
//

NTSTATUS
NTAPI
AvmHookAddWatchedProcessId(
  HANDLE ProcessId,
  BOOLEAN FollowChildrenProcesses
  );

NTSTATUS
NTAPI
AvmHookRemoveWatchedProcessId(
  HANDLE ProcessId
  );

BOOLEAN
NTAPI
AvmHookIsProcessIdWatched(
  HANDLE ProcessId
  );

VOID
NTAPI
AvmHookRemoveAllWatchedProcessIds(
  VOID
  );

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmpHookCreateFunctionDefinitionBuffer(
  _In_ BOOLEAN Simulate
  );

VOID
NTAPI
AvmpHookResetDescriptionSentStatus(
  VOID
  );
