#include "memory.h"

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmCopyMemoryViaMdl(
  _Inout_updates_all_(Length) PVOID Destination,
  _In_ PVOID Source,
  _In_ ULONG Length
  )
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;

  PMDL Mdl = IoAllocateMdl(Destination, Length, FALSE, FALSE, NULL);
  if (!Mdl)
  {
    goto Exit;
  }

  MmBuildMdlForNonPagedPool(Mdl);

  PVOID Mapped = MmMapLockedPages(Mdl, KernelMode);
  if (!Mapped)
  {
    goto Exit;
  }

  KIRQL Irql = KeRaiseIrqlToDpcLevel();
  RtlCopyMemory(Mapped, Source, Length);
  KeLowerIrql(Irql);

  MmUnmapLockedPages(Mapped, Mdl);

  Status = STATUS_SUCCESS;

Exit:
  if (Mdl)
  {
    IoFreeMdl(Mdl);
  }

  return Status;
}

NTSTATUS
NTAPI
AvmInterlockedExchangeViaMdl(
  _Inout_ PLONG Target,
  _In_ LONG Value
  )
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;

  PMDL Mdl = IoAllocateMdl(Target, sizeof(LONG), 0, 0, NULL);
  if (!Mdl)
  {
    goto Exit;
  }

  MmBuildMdlForNonPagedPool(Mdl);

  PVOID Mapped = MmMapLockedPages(Mdl, KernelMode);
  if (!Mapped)
  {
    goto Exit;
  }

  InterlockedExchange(Mapped, Value);

  MmUnmapLockedPages(Mapped, Mdl);

  Status = STATUS_SUCCESS;

Exit:
  if (Mdl)
  {
    IoFreeMdl(Mdl);
  }

  return Status;
}

ULONG
NTAPI
AvmMiGetExceptionInfo(
  _In_ PEXCEPTION_POINTERS ExceptionPointers,
  _Inout_ PBOOLEAN ExceptionAddressConfirmed,
  _Inout_ PULONG_PTR BadVa
  )
{
  PEXCEPTION_RECORD ExceptionRecord;
  PAGED_CODE();

  //
  // Assume default
  //
  *ExceptionAddressConfirmed = FALSE;

  //
  // Get the exception record
  //
  ExceptionRecord = ExceptionPointers->ExceptionRecord;

  //
  // Look at the exception code
  //
  if ((ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) ||
      (ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) ||
      (ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR))
  {
    //
    // We can tell the address if we have more than one parameter
    //
    if (ExceptionRecord->NumberParameters > 1)
    {
      //
      // Return the address
      //
      *ExceptionAddressConfirmed = TRUE;
      *BadVa = ExceptionRecord->ExceptionInformation[1];
    }
  }

  //
  // Continue executing the next handler
  //
  return EXCEPTION_EXECUTE_HANDLER;
}
