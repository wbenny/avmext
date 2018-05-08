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
PVOID
NTAPI
RtlImageDirectoryEntryToData(
  _In_ PVOID BaseOfImage,
  _In_ BOOLEAN MappedAsImage,
  _In_ USHORT DirectoryEntry,
  _Out_ PULONG Size
  );

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
  _In_ PVOID Base
  );

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
  _In_ PVOID PcValue,
  _Out_ PVOID *BaseOfImage
  );

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    IN PVOID PcValue,
    OUT PVOID *BaseOfImage
  );
