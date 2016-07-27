#include "memory.h"

NTSTATUS
NTAPI
AvmpCopyMemoryViaMdl(
  void* Destination,
  const void* Source,
  ULONG Length
  )
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;

  PMDL Mdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
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
AvmpInterlockedExchangeViaMdl(
  LONG* Target,
  LONG Value
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
