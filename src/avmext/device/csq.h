#pragma once
#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AvmCsqInsertIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp
  );

VOID
NTAPI
AvmCsqRemoveIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp
  );

PIRP
NTAPI
AvmCsqPeekNextIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp,
  _In_ PVOID PeekContext
  );

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, Csq)->CsqLock)
VOID
NTAPI
AvmCsqAcquireLock(
  _In_ PIO_CSQ Csq,
  _Out_ PKIRQL Irql
  );

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(CONTAINING_RECORD(Csq, AVM_DEVICE_EXTENSION, Csq)->CsqLock)
VOID
NTAPI
AvmCsqReleaseLock(
  _In_ PIO_CSQ Csq,
  _In_ _IRQL_restores_ KIRQL Irql
  );

VOID
NTAPI
AvmCsqCompleteCanceledIrp(
  _In_ PIO_CSQ Csq,
  _In_ PIRP Irp
  );
