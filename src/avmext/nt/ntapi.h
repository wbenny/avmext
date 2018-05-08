#pragma once
#include <ntifs.h>

//
// Structures and function prototypes which are not included
// in WDK.
//

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _SECTION_INFORMATION_CLASS
{
  SectionBasicInformation,
  SectionImageInformation,
  SectionRelocationInformation,
  MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _SECTION_IMAGE_INFORMATION
{
  PVOID TransferAddress;
  ULONG ZeroBits;
  SIZE_T MaximumStackSize;
  SIZE_T CommittedStackSize;
  ULONG SubSystemType;
  union
  {
    struct
    {
      USHORT SubSystemMinorVersion;
      USHORT SubSystemMajorVersion;
    };
    ULONG SubSystemVersion;
  };
  ULONG GpValue;
  USHORT ImageCharacteristics;
  USHORT DllCharacteristics;
  USHORT Machine;
  BOOLEAN ImageContainsCode;
  BOOLEAN Spare1;
  ULONG LoaderFlags;
  ULONG ImageFileSize;
  ULONG Reserved[1];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySection(
  _In_ HANDLE SectionHandle,
  _In_ SECTION_INFORMATION_CLASS SectionInformationClass,
  _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
  _In_ SIZE_T SectionInformationLength,
  _Out_opt_ PSIZE_T ReturnLength
  );
