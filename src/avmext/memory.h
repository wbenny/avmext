#pragma once
#include <ntifs.h>

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

NTSTATUS
NTAPI
AvmpCopyMemoryViaMdl(
  void* Destination,
  const void* Source,
  ULONG Length
  );

NTSTATUS
NTAPI
AvmpInterlockedExchangeViaMdl(
  LONG* Target,
  LONG Value
  );


