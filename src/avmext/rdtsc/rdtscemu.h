#pragma once
#include <ntifs.h>

#include "nt/ntinternal.h"

typedef enum _AVM_RDTSC_EMULATION_METHOD_TYPE
{
  AvmRdtscEmulationConstantMethodType,
  AvmRdtscEmulationIncreasingMethodType,
} AVM_RDTSC_EMULATION_METHOD_TYPE;

typedef enum _AVM_RDTSC_EMULATION_INSTRUCTION_TYPE
{
  AvmRdtscType,
  AvmRdtscpType,
} AVM_RDTSC_EMULATION_INSTRUCTION_TYPE;

typedef struct _AVM_RDTSC_EMULATION_LOG_TABLE_ITEM
{
  ULONG ProcessId;
  ULONG ReturnedEax;
  ULONG ReturnedEdx;
  ULONG ReturnedEcx;
  PVOID Eip;
  AVM_RDTSC_EMULATION_INSTRUCTION_TYPE Instruction;
} AVM_RDTSC_EMULATION_LOG_TABLE_ITEM, *PAVM_RDTSC_EMULATION_LOG_TABLE_ITEM;

typedef struct _AVM_RDTSC_EMULATION_CONFIGURATION
{
  AVM_RDTSC_EMULATION_METHOD_TYPE Method;
  ULONG ProcessId;

  ULONGLONG TscValue;
  ULONG TscAux;

  ULONG DeltaFrom;
  ULONG DeltaTo;
} AVM_RDTSC_EMULATION_CONFIGURATION, *PAVM_RDTSC_EMULATION_CONFIGURATION;

//
// RDTSC table.
//
#define AVM_RDTSC_EMULATION_LOG_TABLE_SIZE (2048)

extern AVM_RDTSC_EMULATION_LOG_TABLE_ITEM AvmRdtscEmulationLogTable[AVM_RDTSC_EMULATION_LOG_TABLE_SIZE];
extern ULONG AvmRdtscEmulationLogTableSizeInBytes;
extern ULONG AvmRdtscEmulationLogTableItemCount;
extern KSPIN_LOCK AvmRdtscEmulationLogTableLock;

extern AVM_RDTSC_EMULATION_CONFIGURATION AvmRdtscEmulationConfiguration;

//
// Binary representation of 'rdtsc' instruction.
//
static const UCHAR AvmOpRdtsc[] = { 0x0F, 0x31 };

//
// Binary representation of 'rdtscp' instruction.
//
static const UCHAR AvmOpRdtscp[] = { 0x0F, 0x01, 0xF9 };

//
// Private functions.
//

//
// New Trap0D handler.
//

extern ULONG_PTR AvmpRdtscEmulationTrap0DOriginalHandler;

extern
VOID __cdecl
AvmpRdtscEmulationTrap0D(
  VOID
  );

BOOLEAN
NTAPI
AvmRdtscEmulationTrap0D(
  IN PAVM_KTRAP_FRAME UserFrame
  );

VOID
NTAPI
AvmpRdtscEmulationSetTimeStampDisableFlag(
  VOID
  );

VOID
NTAPI
AvmpRdtscEmulationUnsetTimeStampDisableFlag(
  VOID
  );

VOID
NTAPI
AvmpRdtscEmulationSwitchToProcessor(
  IN UCHAR ProcessorIndex
  );

VOID
NTAPI
AvmpRdtscEmulationHookInterruptEntry(
  IN  UCHAR Index,
  IN  ULONG_PTR NewRoutineAddress,
  OUT ULONG_PTR* OldRoutineAddress
  );

//
// Public functions.
//

VOID
NTAPI
AvmRdtscEmulationEnable(
  VOID
  );

VOID
NTAPI
AvmRdtscEmulationDisable(
  VOID
  );

//
// Initialize & destroy routines.
//

NTSTATUS
NTAPI
AvmRdtscEmulationInitialize(
  IN PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AvmRdtscEmulationDestroy(
  IN PDRIVER_OBJECT DriverObject
  );
