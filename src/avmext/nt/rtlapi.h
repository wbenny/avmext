#pragma once
#include <ntifs.h>

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
  PVOID BaseOfImage,
  BOOLEAN MappedAsImage,
  USHORT DirectoryEntry,
  PULONG Size
  );

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
  PVOID Base
  );
