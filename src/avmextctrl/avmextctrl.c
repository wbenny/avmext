#include "avmextctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

HANDLE AvmDeviceHandle = INVALID_HANDLE_VALUE;

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
AvmHookEnable(
  VOID
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_HOOK_ENABLE,
    NULL,
    0,
    NULL,
    0,
    &BytesReturned,
    NULL);

  return TRUE;
}

BOOL
AvmHookDisable(
  VOID
  )
{
  DWORD BytesReturned;

  DeviceIoControl(
    AvmDeviceHandle,
    IOCTL_AVM_HOOK_DISABLE,
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
  printf("\n");
}

VOID
AvmPrintEventFunctionCall(
  PAVM_EVENT_FUNCTION_CALL EventData
  )
{
  switch (EventData->FunctionId)
  {
    case AEF_NTCREATEFILE: printf("\tFunction: NtCreateFile\n"); break;
    case AEF_NTOPENFILE: printf("\tFunction: NtOpenFile\n"); break;
    case AEF_NTCREATEMUTANT: printf("\tFunction: NtCreateMutant\n"); break;
    case AEF_NTOPENMUTANT: printf("\tFunction: NtOpenMutant\n"); break;
    case AEF_NTREADVIRTUALMEMORY: printf("\tFunction: NtReadVirtualMemory\n"); break;
    case AEF_NTWRITEVIRTUALMEMORY: printf("\tFunction: NtWriteVirtualMemory\n"); break;
    case AEF_NTCLOSE: printf("\tFunction: NtClose\n"); break;
    default:
      break;
  }

  printf("\tPID:         %p\n", EventData->ProcessId);
  printf("\tTID:         %p\n", EventData->ThreadId);
  printf("\tReturnValue: %u\n", EventData->ReturnValue);

  PAVM_EVENT_FUNCTION_PARAMETER Parameter = (PAVM_EVENT_FUNCTION_PARAMETER)((PBYTE)EventData + sizeof(AVM_EVENT_FUNCTION_CALL));

  for (DWORD Index = 0; Index < EventData->FunctionParameterCount; Index++)
  {
    WCHAR Buffer[1024] = { 0 };
    printf("\tParameter%i: ", Index);

    switch (Parameter->Type)
    {
      case AEFPT_BOOL:
      case AEFPT_INTEGER:
      case AEFPT_UNSIGNED_INTEGER:
        printf("%08x", *(PDWORD)Parameter->Data);
        break;

      case AEFPT_STRING:
      case AEFPT_UNICODE_STRING:
      case AEFPT_BINARY:
        memcpy(Buffer, Parameter->Data, Parameter->Size);
        printf("%S", Buffer);
        break;

      default:
        break;
    }

    printf("\n");

    Parameter = (PAVM_EVENT_FUNCTION_PARAMETER)((PBYTE)Parameter + sizeof(AVM_EVENT_FUNCTION_PARAMETER) + Parameter->Size);
  }
}

VOID
AvmPrintEvent(
  PAVM_EVENT Event
  )
{
  printf("SequenceId: %u\n", Event->SequenceId);

  PVOID EventData = (PBYTE)Event + sizeof(AVM_EVENT);

  switch (Event->Type)
  {
    case AET_FUNCTION_CALL:
      AvmPrintEventFunctionCall(EventData);
      break;

    default:
      break;
  }

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

  while (1)
  {
    BYTE Buffer[4096] = { 0 };
    DWORD BytesRead = 0;
    (void)ReadFile(AvmDeviceHandle, Buffer, sizeof(Buffer), &BytesRead, NULL);
    if (BytesRead == 0) __debugbreak();
    DWORD Position = 0;
    while (Position < BytesRead)
    {
      PAVM_EVENT Event = (PAVM_EVENT)&Buffer[Position];
      AvmPrintEvent(Event);
      Position += Event->Size;
    }
  }

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
    else
    {
      printf("Invalid argument '%s'!\n", Argv[CurrentArgc]);
      exit(-1);
    }
  }

  if (DoEnable)
  {
    printf("[+] Enabling...\n");
    AvmHookEnable();
  }

  if (DoDisable)
  {
    printf("[+] Disabling...\n");
    AvmHookDisable();
  }

  AvmDestroy();

  return 0;
}
