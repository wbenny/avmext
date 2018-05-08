#pragma once
#include <fltKernel.h>

#define AVM_PORT_NAME      L"\\AvmExtPort"

typedef struct _AVM_FILTER
{
  PDRIVER_OBJECT DriverObject;
  PFLT_FILTER Filter;
  PFLT_PORT ServerPort;
  PFLT_PORT ClientPort;
} AVM_FILTER, *PAVM_FILTER;

extern AVM_FILTER AvmFilterData;

NTSTATUS
NTAPI
AvmFilterConnect(
  _In_ PFLT_PORT ClientPort,
  _In_ PVOID ServerPortCookie,
  _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
  _In_ ULONG SizeOfContext,
  _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
  );

VOID
NTAPI
AvmFilterDisconnect(
  _In_opt_ PVOID ConnectionCookie
 );

NTSTATUS
NTAPI
AvmFilterMessage(
  _In_ PVOID ConnectionCookie,
  _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
  _In_ ULONG InputBufferSize,
  _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
  _In_ ULONG OutputBufferSize,
  _Out_ PULONG ReturnOutputBufferLength
  );

NTSTATUS
NTAPI
AvmFilterInitialize(
  IN PDRIVER_OBJECT DriverObject
  );


VOID
NTAPI
AvmFilterDestroy(
  IN PDRIVER_OBJECT DriverObject
  );

NTSTATUS
NTAPI
AvmFilterUnload(
  FLT_FILTER_UNLOAD_FLAGS Flags
  );
