#pragma once
#include <ntifs.h>

typedef enum _SECTION_INFORMATION_CLASS
{
  SectionBasicInformation,
  SectionImageInformation,
  SectionRelocationInformation,
  MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

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

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenSection(
  PHANDLE SectionHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes
  );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySection(
  HANDLE SectionHandle,
  SECTION_INFORMATION_CLASS SectionInformationClass,
  PVOID SectionInformation,
  SIZE_T SectionInformationLength,
  PSIZE_T ReturnLength
  );
