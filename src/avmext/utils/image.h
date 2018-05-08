#pragma once
#include <ntifs.h>
#include <ntimage.h>

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

_Success_(return != NULL)
PIMAGE_SECTION_HEADER
NTAPI
AvmSectionTableFromVirtualAddress(
  _In_ PIMAGE_NT_HEADERS NtHeaders,
  _In_ ULONG Address
  );

_Success_(return != NULL)
PIMAGE_SECTION_HEADER
NTAPI
AvmSectionTableFromSectionName(
  _In_ PIMAGE_NT_HEADERS NtHeaders,
  _In_ PCHAR SectionName
  );

_Success_(return != NULL)
PVOID
NTAPI
AvmFindEndOfSectionFromAddress(
  _In_ PVOID Address,
  _In_ PVOID BaseAddress,
  _Out_ PULONG SizeOfSection
  );

