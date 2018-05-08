#if 0 // Dead code

#include "filter.h"
#include "entry.h"

CONST FLT_CONTEXT_REGISTRATION FilterContexts[] = {
  { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION FilterCallbacks[] = {
  { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
  sizeof(FLT_REGISTRATION),               //  Size
  FLT_REGISTRATION_VERSION,               //  Version
  0,                                      //  Flags

  FilterContexts,                         //  Context
  FilterCallbacks,                        //  Operation callbacks

  &AvmFilterUnload,                      //  FilterUnload

  NULL,                                   //  InstanceSetup
  NULL,                                   //  InstanceQueryTeardown
  NULL,                                   //  InstanceTeardownStart
  NULL,                                   //  InstanceTeardownComplete

  NULL,                                   //  GenerateFileName
  NULL,                                   //  GenerateDestinationFileName
  NULL                                    //  NormalizeNameComponent
};

AVM_FILTER AvmFilterData;

NTSTATUS
NTAPI
AvmFilterUnload(
  FLT_FILTER_UNLOAD_FLAGS Flags
  )
{
  UNREFERENCED_PARAMETER(Flags);

  AvmDestroy(AvmFilterData.DriverObject);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmFilterConnect(
  _In_ PFLT_PORT ClientPort,
  _In_ PVOID ServerPortCookie,
  _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
  _In_ ULONG SizeOfContext,
  _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
  )
{
  UNREFERENCED_PARAMETER(ServerPortCookie);
  UNREFERENCED_PARAMETER(ConnectionContext);
  UNREFERENCED_PARAMETER(SizeOfContext);
  UNREFERENCED_PARAMETER(ConnectionCookie);

  FLT_ASSERT(AvmFilterData.ClientPort == NULL);

  AvmFilterData.ClientPort = ClientPort;

  return STATUS_SUCCESS;
}

VOID
NTAPI
AvmFilterDisconnect(
  _In_opt_ PVOID ConnectionCookie
 )
{
  UNREFERENCED_PARAMETER(ConnectionCookie);

  FltCloseClientPort(AvmFilterData.Filter, &AvmFilterData.ClientPort);
}

NTSTATUS
NTAPI
AvmFilterMessage(
  _In_ PVOID ConnectionCookie,
  _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
  _In_ ULONG InputBufferSize,
  _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
  _In_ ULONG OutputBufferSize,
  _Out_ PULONG ReturnOutputBufferLength
  )
{
  UNREFERENCED_PARAMETER(ConnectionCookie);
  UNREFERENCED_PARAMETER(InputBuffer);
  UNREFERENCED_PARAMETER(InputBufferSize);
  UNREFERENCED_PARAMETER(OutputBuffer);
  UNREFERENCED_PARAMETER(OutputBufferSize);
  UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AvmFilterInitialize(
  IN PDRIVER_OBJECT DriverObject
  )
{
  NTSTATUS Status;

  Status = FltRegisterFilter(
    DriverObject,
    &FilterRegistration,
    &AvmFilterData.Filter);

  if (!NT_SUCCESS(Status))
  {
    goto Exit;
  }

  PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
  Status = FltBuildDefaultSecurityDescriptor(
    &SecurityDescriptor,
    FLT_PORT_ALL_ACCESS);

  if (!NT_SUCCESS(Status))
  {
    goto Exit;
  }

  UNICODE_STRING PortName = RTL_CONSTANT_STRING(AVM_PORT_NAME);

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(
    &ObjectAttributes,
    &PortName,
    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
    NULL,
    SecurityDescriptor);

  Status = FltCreateCommunicationPort(
    AvmFilterData.Filter,
    &AvmFilterData.ServerPort,
    &ObjectAttributes,
    NULL,
    &AvmFilterConnect,
    &AvmFilterDisconnect,
    &AvmFilterMessage,
    1);

  FltFreeSecurityDescriptor(SecurityDescriptor);

  if (!NT_SUCCESS(Status))
  {
    goto Exit;
  }

  AvmRegisterDestroyComponentRoutine(&AvmFilterDestroy);

  return FltStartFiltering(AvmFilterData.Filter);

Exit:
  AvmFilterDestroy(NULL);
  return Status;
}

VOID
NTAPI
AvmFilterDestroy(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  if (AvmFilterData.ServerPort != NULL)
  {
    FltCloseCommunicationPort(AvmFilterData.ServerPort);
  }

  if (AvmFilterData.Filter != NULL)
  {
    FltUnregisterFilter(AvmFilterData.Filter);
  }
}

#endif
