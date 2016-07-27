#include "image.h"

#include "nt/rtlapi.h"

PIMAGE_SECTION_HEADER
NTAPI
AvmSectionTableFromVirtualAddress(
  IN PIMAGE_NT_HEADERS NtHeaders,
  IN ULONG Address
  )
{
  PIMAGE_SECTION_HEADER NtSection = IMAGE_FIRST_SECTION(NtHeaders);

  for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
  {
    if (
      (ULONG)Address >= NtSection->VirtualAddress &&
      (ULONG)Address  < NtSection->VirtualAddress + NtSection->SizeOfRawData
      )
    {
      return NtSection;
    }

    NtSection++;
  }

  return NULL;
}

PVOID
NTAPI
AvmFindEndOfSectionFromAddress(
  IN  PVOID Address,
  IN  PVOID BaseAddress,
  OUT PULONG SizeOfSection
  )
{
  ULONG_PTR VirtualAddress = ((PUCHAR)Address - (PUCHAR)BaseAddress);

  PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(BaseAddress);
  PIMAGE_SECTION_HEADER SectionHeader = AvmSectionTableFromVirtualAddress(NtHeaders, (ULONG)VirtualAddress);

  if (SectionHeader == NULL)
  {
    return NULL;
  }

  *SizeOfSection = SectionHeader->SizeOfRawData;
  return (PVOID)((PUCHAR)BaseAddress + SectionHeader->VirtualAddress);
}
