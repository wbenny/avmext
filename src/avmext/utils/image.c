#include "image.h"

#include "nt/rtlapi.h"

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

_Success_(return != NULL)
PIMAGE_SECTION_HEADER
NTAPI
AvmSectionTableFromVirtualAddress(
  _In_ PIMAGE_NT_HEADERS NtHeaders,
  _In_ ULONG Address
  )
{
  //
  // RtlSectionTableFromVirtualAddress
  //

  PIMAGE_SECTION_HEADER NtSection = IMAGE_FIRST_SECTION(NtHeaders);

  for (ULONG Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; Index++)
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

_Success_(return != NULL)
PIMAGE_SECTION_HEADER
NTAPI
AvmSectionTableFromSectionName(
  _In_ PIMAGE_NT_HEADERS NtHeaders,
  _In_ PCHAR SectionName
  )
{
  //
  // RtlSectionTableFromSectionName
  //

  PIMAGE_SECTION_HEADER NtSection = IMAGE_FIRST_SECTION(NtHeaders);

  for (ULONG Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; Index++)
  {
    if (!strcmp((PCHAR)NtSection->Name, SectionName))
    {
      return NtSection;
    }

    NtSection++;
  }

  return NULL;
}

_Success_(return != NULL)
PVOID
NTAPI
AvmFindEndOfSectionFromAddress(
  _In_ PVOID Address,
  _In_ PVOID BaseAddress,
  _Out_ PULONG SizeOfSection
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
