#pragma once
#include <ntifs.h>
#include <ntimage.h>

PIMAGE_SECTION_HEADER
NTAPI
AvmSectionTableFromVirtualAddress(
  IN PIMAGE_NT_HEADERS NtHeaders,
  IN ULONG Address
  );

PVOID
NTAPI
AvmFindEndOfSectionFromAddress(
  IN  PVOID Address,
  IN  PVOID BaseAddress,
  OUT PULONG SizeOfSection
  );

