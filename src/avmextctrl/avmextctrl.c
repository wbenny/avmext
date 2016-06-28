#include "avmextctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

HANDLE AvmDeviceHandle = INVALID_HANDLE_VALUE;

VOID
AvmRdtscTest(
  VOID
  )
{
  ULONG64 tsc1;
  ULONG64 tsc2;
  ULONG tsc_aux1, tsc_aux2;
  ULONG diff;

  tsc1 = __rdtsc();
  tsc2 = __rdtsc();
  diff = (ULONG)(tsc2 - tsc1);
  printf("\t rdtsc  diff: %u\n", diff);

  tsc1 = __rdtscp(&tsc_aux1);
  tsc2 = __rdtscp(&tsc_aux2);
  diff = (ULONG)(tsc2 - tsc1);
  printf("\t rdtscp diff: %u\n", diff);
  printf("\t tsc_aux1:    %u\n", tsc_aux1);
  printf("\t tsc_aux2:    %u\n", tsc_aux2);
}

BOOL
AvmInitialize(
  VOID
  )
{
  AvmDeviceHandle = CreateFile(
    TEXT("\\\\.\\AvmExt"),
    GENERIC_WRITE | GENERIC_READ,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL);

  return AvmDeviceHandle != INVALID_HANDLE_VALUE;
}

VOID
AvmDestroy(
  VOID
  )
{
  if (AvmDeviceHandle != INVALID_HANDLE_VALUE)
  {
    CloseHandle(AvmDeviceHandle);
  }
}

BOOL
AvmGetConfiguration(
  PAVM_RDTSC_EMULATION_CONFIGURATION Configuration
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_GET_CONFIGURATION,
    NULL,
    0,
    Configuration,
    sizeof(*Configuration),
    &BytesReturned,
    NULL);

  return TRUE;
}

BOOL
AvmSetConfiguration(
  PAVM_RDTSC_EMULATION_CONFIGURATION Configuration
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_SET_CONFIGURATION,
    Configuration,
    sizeof(*Configuration),
    NULL,
    0,
    &BytesReturned,
    NULL);

  return TRUE;
}

BOOL
AvmEmulationEnable(
  VOID
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_ENABLE,
    NULL,
    0,
    NULL,
    0,
    &BytesReturned,
    NULL);

  return TRUE;
}

BOOL
AvmEmulationDisable(
  VOID
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_DISABLE,
    NULL,
    0,
    NULL,
    0,
    &BytesReturned,
    NULL);

  return TRUE;
}

BOOL
AvmGetLogTable(
  PULONG LogTableSizeInBytes,
  PULONG LogTableItemCount,
  PAVM_RDTSC_EMULATION_LOG_TABLE_ITEM LogTable
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_GET_LOG_TABLE_SIZE_IN_BYTES,
    NULL,
    0,
    LogTableSizeInBytes,
    sizeof(*LogTableSizeInBytes),
    &BytesReturned,
    NULL);

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_GET_LOG_TABLE_ITEM_COUNT,
    NULL,
    0,
    LogTableItemCount,
    sizeof(*LogTableItemCount),
    &BytesReturned,
    NULL);

  if (LogTable != NULL)
  {
    DeviceIoControl(
      AvmDeviceHandle,
      IOCTL_AVM_RDTSC_EMULATION_GET_LOG_TABLE_CONTENT,
      NULL,
      0,
      LogTable,
      *LogTableSizeInBytes,
      &BytesReturned,
      NULL);
  }

  return TRUE;
}

BOOL
AvmClearLogTable(
  VOID
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_RDTSC_EMULATION_CLEAR_LOG_TABLE,
    NULL,
    0,
    NULL,
    0,
    &BytesReturned,
    NULL);

  return TRUE;
}

VOID
AvmPrintHelp(
  VOID
  )
{
  printf("Usage:\n");
  printf("  avmextctrl.exe [--enable] [--disable] [--test] [--clear-table]\n");
  printf("      [--print-table] [--print-config] [--tsc-value N] [--tsc-aux N]\n");
  printf("      [--method M] [--delta-from N] [--delta-to N]\n");
  printf("\n");
  printf("  --enable            Enable RDTSC hooking\n");
  printf("  --disable           Disable RDTSC hooking\n");
  printf("  --test              Perform RDTSC hooking\n");
  printf("  --clear-table       Clear RDTSC log table\n");
  printf("  --print-table       Print current RDTSC log table\n");
  printf("  --method M          Set RDTSC hooking method [constant|increasing]\n");
  printf("  --tsc-value N       Set initial TSC value\n");
  printf("  --tsc-aux N         Set TSC_AUX value (returned by RDTSCP)\n");
  printf("  --delta-from N      Set minimal delta between two RDTSC calls\n");
  printf("  --delta-to N        Set maximal delta between two RDTSC calls\n");
  printf("  --print-config      Print final cofig\n");
  printf("\n");
}

int
main(
  int Argc,
  char** Argv
  )
{
  if (Argc == 1)
  {
    AvmPrintHelp();
    exit(0);
  }

  if (!AvmInitialize())
  {
    printf("Cannot initialize AVM!\n");
    exit(-1);
  }

  int CurrentArgc = 0;
  BOOL DoEnable         = FALSE;
  BOOL DoDisable        = FALSE;
  BOOL DoTest           = FALSE;
  BOOL DoClearTable     = FALSE;
  BOOL DoPrintTable     = FALSE;
  BOOL DoPrintConfig    = FALSE;
  AVM_RDTSC_EMULATION_CONFIGURATION Configuration = { 0 };

  AvmGetConfiguration(&Configuration);

  while (++CurrentArgc < Argc)
  {
    if (strcmp(Argv[CurrentArgc], "--enable") == 0)
    {
      DoEnable = TRUE;
    }
    else if (strcmp(Argv[CurrentArgc], "--disable") == 0)
    {
      DoDisable = TRUE;
    }
    else if (strcmp(Argv[CurrentArgc], "--test") == 0)
    {
      DoTest = TRUE;
    }
    else if (strcmp(Argv[CurrentArgc], "--clear-table") == 0)
    {
      DoClearTable = TRUE;
    }
    else if (strcmp(Argv[CurrentArgc], "--print-table") == 0)
    {
      DoPrintTable = TRUE;
    }
    else if (strcmp(Argv[CurrentArgc], "--print-config") == 0)
    {
      DoPrintConfig = TRUE;
    }
    else if (strcmp(Argv[CurrentArgc], "--method") == 0)
    {
      const char* Method = Argv[++CurrentArgc];

      if (strcmp(Method, "constant") == 0)
      {
        Configuration.Method = AvmRdtscEmulationConstantMethodType;
      }
      else if (strcmp(Method, "increasing") == 0)
      {
        Configuration.Method = AvmRdtscEmulationIncreasingMethodType;
      }
      else
      {
        printf("Ivalid method type!\n");
        exit(-1);
      }
    }
    else if (strcmp(Argv[CurrentArgc], "--tsc-value") == 0)
    {
      const char* TscValue = Argv[++CurrentArgc];

      Configuration.TscValue = atoll(TscValue);
    }
    else if (strcmp(Argv[CurrentArgc], "--tsc-aux") == 0)
    {
      const char* TscAux = Argv[++CurrentArgc];

      Configuration.TscAux = atol(TscAux);
    }
    else if (strcmp(Argv[CurrentArgc], "--delta-from") == 0)
    {
      const char* DeltaFrom = Argv[++CurrentArgc];

      Configuration.DeltaFrom = atoi(DeltaFrom);
    }
    else if (strcmp(Argv[CurrentArgc], "--delta-to") == 0)
    {
      const char* DeltaTo = Argv[++CurrentArgc];

      Configuration.DeltaTo = atoi(DeltaTo);
    }
    else
    {
      printf("Invalid argument '%s'!\n", Argv[CurrentArgc]);
      exit(-1);
    }
  }

  AvmSetConfiguration(&Configuration);

  if (DoEnable)
  {
    printf("[+] Enabling...\n");
    AvmEmulationEnable();
  }

  if (DoClearTable)
  {
    printf("[+] Clearing LogTable...\n");
    AvmClearLogTable();
  }

  if (DoTest)
  {
    printf("[+] Performing test...\n");
    AvmRdtscTest();
  }

  if (DoDisable)
  {
    printf("[+] Disabling...\n");
    AvmEmulationDisable();
  }

  if (DoPrintConfig)
  {
    printf("[+] Current configuration:\n");
    printf("\t Method: %s\n", Configuration.Method == AvmRdtscEmulationConstantMethodType ? "constant" : "increasing");
    printf("\t TscValue: %" PRIu64 "\n", Configuration.TscValue);
    printf("\t TscAux: %u\n", Configuration.TscAux);
    printf("\t DeltaFrom: %u\n", Configuration.DeltaFrom);
    printf("\t DeltaTo: %u\n", Configuration.DeltaTo);
    printf("\n");
  }

  if (DoPrintTable)
  {
    printf("[+] Current LogTable:\n");

    ULONG LogTableSizeInBytes;
    ULONG LogTableItemCount;
    AvmGetLogTable(&LogTableSizeInBytes, &LogTableItemCount, NULL);

    PAVM_RDTSC_EMULATION_LOG_TABLE_ITEM LogTable = (PAVM_RDTSC_EMULATION_LOG_TABLE_ITEM)calloc(LogTableSizeInBytes, 1);
    AvmGetLogTable(&LogTableSizeInBytes, &LogTableItemCount, LogTable);

    printf("\t LogTableSizeInBytes:     %u\n", LogTableSizeInBytes);
    printf("\t LogTableItemCount:       %u\n", LogTableItemCount);
    printf("\n");

    for (ULONG i = 0; i < LogTableItemCount; i++)
    {
      printf("\t LogTable[%u].ProcessId:   %u\n", i, LogTable[i].ProcessId);
      printf("\t LogTable[%u].Instruction: %s\n", i, LogTable[i].Instruction == AvmRdtscType ? "AvmRdtscType" : "AvmRdtscpType");
      printf("\t LogTable[%u].Eip:         %p\n", i, LogTable[i].Eip);
      printf("\n");
    }

    free(LogTable);
  }

  AvmDestroy();

  return 0;
}
