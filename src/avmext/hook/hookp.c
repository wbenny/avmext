#include "hook.h"

#include "nt/ntapi.h"
#include "nt/rtlapi.h"
#include "utils/image.h"

PVOID
NTAPI
AvmpHookFindExportedRoutineByName(
  IN PVOID DllBase,
  IN PANSI_STRING AnsiRoutineName
  )
{
  ULONG ExportSize;
  PIMAGE_EXPORT_DIRECTORY ExportDirectory = RtlImageDirectoryEntryToData(
    DllBase,
    TRUE,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    &ExportSize);

  if (ExportDirectory == NULL)
  {
    return NULL;
  }

  //
  // Initialize the pointer to the array of RVA-based ansi export strings.
  //
  PULONG NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

  //
  // Initialize the pointer to the array of USHORT ordinal numbers.
  //
  PUSHORT NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

  //
  // Lookup the desired name in the name table using a binary search.
  //
  LONG Low = 0;
  LONG Middle = 0;
  LONG High = ExportDirectory->NumberOfNames - 1;
  LONG Result;

  while (High >= Low)
  {
    //
    // Compute the next probe index and compare the import name
    // with the export name entry.
    //
    Middle = (Low + High) >> 1;

    Result = strcmp(AnsiRoutineName->Buffer, (PCHAR)DllBase + NameTableBase[Middle]);

    if (Result < 0)
    {
      High = Middle - 1;
    }
    else if (Result > 0)
    {
      Low = Middle + 1;
    }
    else
    {
      break;
    }
  }

  //
  // If the high index is less than the low index, then a matching
  // table entry was not found. Otherwise, get the ordinal number
  // from the ordinal table.
  //
  if (High < Low)
  {
    return NULL;
  }

  USHORT OrdinalNumber = NameOrdinalTableBase[Middle];

  //
  // If the OrdinalNumber is not within the Export Address Table,
  // then this image does not implement the function.  Return not found.
  //
  if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
  {
    return NULL;
  }

  //
  // Index into the array of RVA export addresses by ordinal number.
  //
  PULONG Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);

  PVOID FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

  //
  // Forwarders are not used by the kernel and HAL to each other.
  //
  // ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
  //         (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

  return FunctionAddress;
}

NTSTATUS
NTAPI
AvmpHookFindSyscallNumberByRoutineName(
  IN PANSI_STRING AnsiRoutineName,
  OUT PULONG SyscallNumber
  )
{
  NTSTATUS Status;

  UNICODE_STRING NtdllPath = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(
    &ObjectAttributes,
    &NtdllPath,
    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
    NULL,
    NULL);

  HANDLE NtdllSection;
  if (!NT_SUCCESS(Status = ZwOpenSection(
    &NtdllSection,
    SECTION_QUERY,
    &ObjectAttributes)))
  {
    goto Exit;
  }

  SECTION_IMAGE_INFORMATION SectionInformation;
  if (!NT_SUCCESS(Status = ZwQuerySection(
    NtdllSection,
    SectionImageInformation,
    &SectionInformation,
    sizeof(SectionInformation),
    0)))
  {
    goto Exit;
  }

  PVOID NtdllBase = SectionInformation.TransferAddress;
  PVOID ExportedRoutine = AvmpHookFindExportedRoutineByName(NtdllBase, AnsiRoutineName);

  if (ExportedRoutine)
  {
    *SyscallNumber = *((PULONG)((PUCHAR)ExportedRoutine + AVM_HOOK_SYSCALL_OFFSET));
  }
  else
  {
    Status = STATUS_NOT_FOUND;
  }

Exit:
  if (NtdllSection)
  {
    ZwClose(NtdllSection);
  }

  return Status;
}

PVOID
NTAPI
AvmpHookFindNtoskrnlBase(
  VOID
  )
{
  UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"DbgPrint");
  PVOID NtoskrnlBase = MmGetSystemRoutineAddress(&RoutineName);

  return RtlPcToFileHeader(NtoskrnlBase, &NtoskrnlBase);
}

PAVM_SERVICE_TABLE_DESCRIPTOR
NTAPI
AvmpHookFindSSDT(
  PVOID NtoskrnlBaseAddress
  )
{
  PAVM_SERVICE_TABLE_DESCRIPTOR SSDT = NULL;

#if defined (_X86_)

  UNREFERENCED_PARAMETER(NtoskrnlBaseAddress);

  UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(L"KeServiceDescriptorTable");
  SSDT = MmGetSystemRoutineAddress(&SymbolName);

#elif defined (_AMD64_)

  UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(L"KeAddSystemServiceTable");
  PUCHAR KeAddSystemServiceTableRoutine = (PUCHAR)MmGetSystemRoutineAddress(&SymbolName);

  if (!KeAddSystemServiceTableRoutine)
  {
    return NULL;
  }

  //
  // 000000014050EA4A 48 C1 E0 05                shl rax, 5
  // 000000014050EA4E 48 83 BC 18 80 3A 36 00 00 cmp qword ptr [rax+rbx+363A80h], 0 <- we are looking for this instruction
  // 000000014050EA57 0F 85 B2 5C 0A 00          jnz loc_1405B470F
  // 000000014050EA5D 48 8D 8B C0 3A 36 00       lea rcx, rva KeServiceDescriptorTableShadow[rbx]
  // 000000014050EA64 48 03 C8                   add rcx, rax
  // 000000014050EA67 48 83 39 00                cmp qword ptr [rcx], 0
  //
  LONG RvaSSDT = 0;

  for (
    ULONG Offset = 0;

    //
    // Check for 'ret' instruction.
    //

    KeAddSystemServiceTableRoutine[Offset] != 0xC3;
    Offset++
    )
  {
    //
    // 4?83bc?? ???????? 00 cmp qword ptr [r?+r?+????????h],0
    //
    if (
      ((*(PULONG)(KeAddSystemServiceTableRoutine + Offset)) & 0x00FFFFF0) == 0xBC8340 &&
       !*(PUCHAR)(KeAddSystemServiceTableRoutine + Offset + 8)
      )
    {
      RvaSSDT = *(PLONG)(KeAddSystemServiceTableRoutine + Offset + 4);
      break;
    }
  }

  if (RvaSSDT)
  {
    SSDT = (PAVM_SERVICE_TABLE_DESCRIPTOR)((PUCHAR)NtoskrnlBaseAddress + RvaSSDT);
  }
  else
  {
    //
    // Windows 10 Technical Preview:
    // fffff800e21b30ec 757f             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
    // fffff800e21b30ee 48833deafee4ff00 cmp qword ptr [nt!KeServiceDescriptorTable+0x20 (fffff800e2002fe0)],0 <- we are looking for this instruction
    // fffff800e21b30f6 7575             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
    // fffff800e21b30f8 48833da0fee4ff00 cmp qword ptr [nt!KeServiceDescriptorTableShadow+0x20 (fffff800e2002fa0)],0
    // fffff800e21b3100 756b             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
    //
    for (
      ULONG Offset = 0;

      //
      // Check for 'ret' instruction.
      //

      KeAddSystemServiceTableRoutine[Offset] != 0xC3;
      Offset++
      )
    {
      //
      // 48833d ???????? 00 cmp qword ptr [X],0
      //
      if (
        ((*(PULONG)(KeAddSystemServiceTableRoutine + Offset)) & 0x00FFFFFF) == 0x3D8348 &&
         !*(PUCHAR)(KeAddSystemServiceTableRoutine + Offset + 7)
        )
      {
        RvaSSDT = *(PLONG)(KeAddSystemServiceTableRoutine + 2*Offset + 3);
        break;
      }
    }

    //
    // Sanity check SSDT & contents.
    //
    if (RvaSSDT)
    {
      __try
      {
        SSDT = (PAVM_SERVICE_TABLE_DESCRIPTOR)((ULONG_PTR)KeAddSystemServiceTableRoutine + RvaSSDT + 8 - 0x20);
        ULONG_PTR KeAddSystemServiceTableRoutineBase = (ULONG_PTR)KeAddSystemServiceTableRoutine & 0xFFFFFFFF00000000ull;

        if (((ULONG_PTR)SSDT         & 0xFFFFFFFF00000000ull) != KeAddSystemServiceTableRoutineBase ||
            ((ULONG_PTR)SSDT->Base   & 0xFFFFFFFF00000000ull) != KeAddSystemServiceTableRoutineBase ||
            ((ULONG_PTR)SSDT->Limit  & 0xFFFFFFFFFFFF0000ull) != 0                                  ||
            ((ULONG_PTR)SSDT->Number & 0xFFFFFFFF00000000ull) != KeAddSystemServiceTableRoutineBase)
        {
          return NULL;
        }
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        return NULL;
      }
    }
  }

#endif

  return SSDT;
}

#if defined (_AMD64_)

PVOID
NTAPI
AvmpHookFindCaveAddress(
  PVOID AddressBegin,
  PVOID AddressEnd,
  ULONG DesiredSize
  )
{
  PUCHAR Begin = (PUCHAR)AddressBegin;
  PUCHAR End   = (PUCHAR)AddressEnd;

  ULONG CurrentSize = 0;
  while (Begin < End)
  {
    //
    // 'nop' or 'int 3'
    //
    if (*Begin == 0x90 || *Begin == 0xCC)
    {
      CurrentSize++;
    }
    else
    {
      CurrentSize = 0;
    }

    if (CurrentSize == DesiredSize)
    {
      return (PVOID)((ULONG_PTR)Begin - DesiredSize + 1);
    }

    Begin++;
  }

  return NULL;
}

#endif
