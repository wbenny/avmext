#pragma once
#include <ntifs.h>

//
// Structures and function prototypes which are not included
// in WDK.
//

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

NTSYSAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
  _In_ PEPROCESS FromProcess,
  _In_ CONST VOID *FromAddress,
  _In_ PEPROCESS ToProcess,
  _Out_ PVOID ToAddress,
  _In_ SIZE_T BufferSize,
  _In_ KPROCESSOR_MODE PreviousMode,
  _Out_ PSIZE_T NumberOfBytesCopied
  );
