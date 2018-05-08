#pragma once
#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#if defined(_AMD64_)

#define PointerToByteArray(ptr)               \
  (UCHAR)((((ULONG_PTR)(ptr)) >>  0) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >>  8) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 16) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 24) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 32) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 40) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 48) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 56) & 0xff)

#elif defined(_X86_)

#define PointerToByteArray(ptr)               \
  (UCHAR)((((ULONG_PTR)(ptr)) >>  0) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >>  8) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 16) & 0xff), \
  (UCHAR)((((ULONG_PTR)(ptr)) >> 24) & 0xff)

#endif

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AvmCopyMemoryViaMdl(
  _Inout_updates_all_(Length) PVOID Destination,
  _In_ PVOID Source,
  _In_ ULONG Length
  );

NTSTATUS
NTAPI
AvmInterlockedExchangeViaMdl(
  _Inout_ PLONG Target,
  _In_ LONG Value
  );

ULONG
NTAPI
AvmMiGetExceptionInfo(
  _In_ PEXCEPTION_POINTERS ExceptionPointers,
  _Inout_ PBOOLEAN ExceptionAddressConfirmed,
  _Inout_ PULONG_PTR BadVa
  );
