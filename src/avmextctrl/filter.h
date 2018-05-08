#pragma once
#include <windows.h>
#include <Fltuser.h>

#define AVM_PORT_NAME      L"\\AvmExtPort"

BOOL
AvmFilterInitialize(
  VOID
  );

VOID
AvmFilterDestroy(
  VOID
  );
