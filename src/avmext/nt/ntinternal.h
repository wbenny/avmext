#pragma once
#include <ntifs.h>
#include <ndis.h>

//
// Inspired by WRK.
//

#define CR4_TSD             0x00000004              // Time stamp disable

#define ReadTSC()           __rdtsc()
#define ReadTSCP(data)      __rdtscp(data)

#define ReadCR4()           __readcr4()
#define WriteCR4(data)      __writecr4(data)

#define ReadIDT(data)       __sidt(data)
#define WriteIDT(data)      __lidt(data)

#define EnableInterrupts()  _enable()               // sti instruction
#define DisableInterrupts() _disable()              // cli instruction

//
// IDT descriptor.
//

struct _AVM_KDESCRIPTOR32
{
  USHORT  Pad;
  USHORT  Limit;
  ULONG   Base;
};

struct _AVM_KDESCRIPTOR64
{
  union
  {
    struct  
    {
      USHORT Pad[3];
      USHORT Limit;
    };

    ULONG_PTR LowPart;
  };
  union
  {
    ULONG_PTR Base;
    ULONG_PTR HighPart;
  };
};

//
// Entry of Interrupt Descriptor Table (IDTENTRY)
//

struct _AVM_KIDTENTRY32
{
  USHORT Offset;
  USHORT Selector;
  USHORT Access;
  USHORT ExtendedOffset;
};

struct _AVM_KIDTENTRY64
{
  union
  {
    struct
    {
      USHORT OffsetLow;
      USHORT Selector;
      USHORT IstIndex : 3;
      USHORT Reserved0 : 5;
      USHORT Type : 5;
      USHORT Dpl : 2;
      USHORT Present : 1;
      USHORT OffsetMiddle;
      ULONG OffsetHigh;
      ULONG Reserved1;
    };

    ULONG64 Alignment;
  };
};

//
// Trap frame
//

struct _AVM_KTRAP_FRAME32
{

  //
  //  Segment registers
  //

  ULONG   SegGs;
  ULONG   SegEs;
  ULONG   SegDs;

  //
  //  Volatile registers
  //

  ULONG   Edx;
  ULONG   Ecx;
  ULONG   Eax;

  //
  //  FS is TIB/PCR pointer, is here to make save sequence easy
  //

  ULONG   SegFs;

  //
  //  Non-volatile registers
  //

  ULONG   Edi;
  ULONG   Esi;
  ULONG   Ebx;
  ULONG   Ebp;

  //
  //  Control registers
  //

  ULONG   ErrCode;
  ULONG   Eip;
  ULONG   SegCs;
  ULONG   EFlags;

  ULONG   HardwareEsp;    // WARNING - segSS:esp are only here for stacks
  ULONG   HardwareSegSs;  // that involve a ring transition.

};

struct _AVM_KTRAP_FRAME64
{

  //
  //  Volatile registers.
  //
  // N.B. These registers are only saved on exceptions and interrupts. They
  //      are not saved for system calls.
  //

  ULONG64 Rax;
  ULONG64 Rcx;
  ULONG64 Rdx;
  ULONG64 R8;
  ULONG64 R9;
  ULONG64 R10;
  ULONG64 R11;

  //
  // Saved nonvolatile registers RBX, RDI and RSI. These registers are only
  // saved in system service trap frames.
  //

  ULONG64 Rbx;
  ULONG64 Rdi;
  ULONG64 Rsi;

  //
  // Saved nonvolatile register RBP. This register is used as a frame
  // pointer during trap processing and is saved in all trap frames.
  //

  ULONG64 Rbp;

  //
  // Information pushed by hardware.
  //
  // N.B. The error code is not always pushed by hardware. For those cases
  //      where it is not pushed by hardware a dummy error code is allocated
  //      on the stack.
  //

  union
  {
    ULONG64 ErrorCode;
    ULONG64 ExceptionFrame;
  };

  ULONG64 Rip;
  USHORT SegCs;
  USHORT Fill1[3];
  ULONG EFlags;
  ULONG Fill2;
  ULONG64 Rsp;
  USHORT SegSs;
  USHORT Fill3[1];
};

#if defined(_X86_)
typedef struct _AVM_KDESCRIPTOR32 AVM_KDESCRIPTOR, *PAVM_KDESCRIPTOR;
typedef struct _AVM_KIDTENTRY32   AVM_KIDTENTRY,   *PAVM_KIDTENTRY;
typedef struct _AVM_KTRAP_FRAME32 AVM_KTRAP_FRAME, *PAVM_KTRAP_FRAME;
#elif defined(_AMD64_)
typedef struct _AVM_KDESCRIPTOR64 AVM_KDESCRIPTOR, *PAVM_KDESCRIPTOR;
typedef struct _AVM_KIDTENTRY64   AVM_KIDTENTRY,   *PAVM_KIDTENTRY;
typedef struct _AVM_KTRAP_FRAME64 AVM_KTRAP_FRAME, *PAVM_KTRAP_FRAME;
#endif
