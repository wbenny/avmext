#include "filter.h"

#define AVM_PORT_NAME      L"\\AvmExtPort"

HANDLE AvmFilterPort = INVALID_HANDLE_VALUE;

BOOL
AvmFilterInitialize(
  VOID
  )
{
  HRESULT Result;
  __debugbreak();
  Result = FilterConnectCommunicationPort(
    AVM_PORT_NAME,
    0,
    NULL,
    0,
    NULL,
    &AvmFilterPort);

  return Result == S_OK;
}

VOID
AvmFilterDestroy(
  VOID
  )
{
  if (AvmFilterPort != INVALID_HANDLE_VALUE)
  {
    CloseHandle(AvmFilterPort);
  }
}

