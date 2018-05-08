//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define AVM_FUNCTION_DEFINE(Category, ReturnType, FunctionName, ...)            \
  typedef ReturnType (NTAPI * pfn##FunctionName)(                               \
    __VA_ARGS__                                                                 \
    );                                                                          \
                                                                                \
  ReturnType                                                                    \
  NTAPI                                                                         \
  AvmpHook##FunctionName(                                                       \
    __VA_ARGS__                                                                 \
    );                                                                          \
                                                                                \
  __declspec(allocate(AVM_HOOK_DEFINITION_SECTION_NAME))                        \
  AVM_HOOK_DEFINITION AvmpHookFunction_##FunctionName = {                       \
    .Id = __COUNTER__,                                                          \
    .Type = AHDT_FUNCTION,                                                      \
    .Name = RTL_CONSTANT_STRING(#FunctionName),                                 \
    .Function = {                                                               \
      .CategoryName = RTL_CONSTANT_STRING(Category),                            \
      .SSDTEntry = NULL,                                                        \
      .NewFunctionAddress = (PVOID)&AvmpHook##FunctionName                      \
    }                                                                           \
  };                                                                            \
                                                                                \
  ReturnType                                                                    \
  NTAPI                                                                         \
  AvmpHook##FunctionName(                                                       \
    __VA_ARGS__                                                                 \
    )

#define AvmpTryToFetchInt(DestinationInt, SourceInt)                            \
  do                                                                            \
  {                                                                             \
    if (!(SourceInt))                                                           \
    {                                                                           \
      *(DestinationInt) = 0;                                                    \
      break;                                                                    \
    }                                                                           \
                                                                                \
    __try                                                                       \
    {                                                                           \
      *(DestinationInt) = *(SourceInt);                                         \
    }                                                                           \
    __except (EXCEPTION_EXECUTE_HANDLER)                                        \
    {                                                                           \
      *(DestinationInt) = 0;                                                    \
    }                                                                           \
  } while (0)

#define AvmpTryToFetchString(DestinationString, SourceString, AdditionalFlags)  \
  do                                                                            \
  {                                                                             \
    *(AdditionalFlags) = AEVT_HINT_PROBE;                                       \
    (DestinationString)->Buffer = NULL;                                         \
    (DestinationString)->Length = 0;                                            \
    (DestinationString)->MaximumLength = 0;                                     \
                                                                                \
    __try                                                                       \
    {                                                                           \
      if ((SourceString) && (SourceString)->Buffer)                             \
      {                                                                         \
        (DestinationString)->Buffer = (SourceString)->Buffer;                   \
        (DestinationString)->Length = (SourceString)->Length;                   \
        (DestinationString)->MaximumLength = (SourceString)->MaximumLength;     \
      }                                                                         \
    }                                                                           \
    __except (EXCEPTION_EXECUTE_HANDLER)                                        \
    {                                                                           \
      *(AdditionalFlags) = AEVT_HINT_ERROR;                                     \
    }                                                                           \
  } while (0)


#define AvmpTryToFetchObjectName(DestinationString, ObjectAttributes, AdditionalFlags)\
  do                                                                            \
  {                                                                             \
    *(AdditionalFlags) = AEVT_HINT_PROBE;                                       \
    (DestinationString)->Buffer = NULL;                                         \
    (DestinationString)->Length = 0;                                            \
    (DestinationString)->MaximumLength = 0;                                     \
                                                                                \
    __try                                                                       \
    {                                                                           \
      if ((ObjectAttributes) && (ObjectAttributes)->ObjectName && (ObjectAttributes)->ObjectName->Buffer)\
      {                                                                         \
        (DestinationString)->Buffer = (ObjectAttributes)->ObjectName->Buffer;   \
        (DestinationString)->Length = (ObjectAttributes)->ObjectName->Length;   \
        (DestinationString)->MaximumLength = (ObjectAttributes)->ObjectName->MaximumLength;\
      }                                                                         \
    }                                                                           \
    __except (EXCEPTION_EXECUTE_HANDLER)                                        \
    {                                                                           \
      *(AdditionalFlags)  = AEVT_HINT_ERROR;                                    \
    }                                                                           \
  } while (0)

#define AvmpReturnIfNotWatched(ReturnValue)                                     \
  do                                                                            \
  {                                                                             \
    if (ExGetPreviousMode() == KernelMode ||                                    \
        !AvmHookIsProcessIdWatched(PsGetCurrentProcessId()))                    \
    {                                                                           \
      InterlockedDecrement(&AvmpHookActualFunctionCallCount);                   \
      return ReturnValue;                                                       \
    }                                                                           \
  } while (0)

volatile LONG AvmpHookActualFunctionCallCount = 0;

#pragma region Special

//////////////////////////////////////////////////////////////////////////
// AvmpHookRegisterEnums
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Special",
NTSTATUS,
RegisterEnums,
  VOID
  )
{
  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_RegisterEnums,
    0,
    AEVT_ENUM, &AvmpHookEnum_NTSTATUS, "Status", 0,
    AEVT_VOID);

  return STATUS_SUCCESS;
}

#pragma endregion Special

#pragma region IO

//////////////////////////////////////////////////////////////////////////
// NtCreateFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtCreateFile,
  _Out_ PHANDLE FileHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_opt_ PLARGE_INTEGER AllocationSize,
  _In_ ULONG FileAttributes,
  _In_ ULONG ShareAccess,
  _In_ ULONG CreateDisposition,
  _In_ ULONG CreateOptions,
  _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
  _In_ ULONG EaLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateFile)(AvmpHookFunction_NtCreateFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
    AllocationSize,
    FileAttributes,
    ShareAccess,
    CreateDisposition,
    CreateOptions,
    EaBuffer,
    EaLength);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedFileName;
  ULONG CapturedFileNameFlags;
  AvmpTryToFetchObjectName(&CapturedFileName, ObjectAttributes, &CapturedFileNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateFile,
    ReturnValue,

    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", *FileHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_FILE_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedFileNameFlags, CapturedFileName.Length, "FileName", CapturedFileName.Buffer,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_FILE_ATTRIBUTES, "FileAttributes", FileAttributes,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_SHARE_ACCESS, "ShareAccess", ShareAccess,
    AEVT_ENUM, &AvmpHookEnum_CREATE_DISPOSITION, "CreateDisposition", CreateDisposition,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_CREATE_OPTIONS, "CreateOptions", CreateOptions,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtOpenFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtOpenFile,
  _Out_ PHANDLE FileHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_ ULONG ShareAccess,
  _In_ ULONG OpenOptions
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtOpenFile)(AvmpHookFunction_NtOpenFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
    ShareAccess,
    OpenOptions);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedFileName;
  ULONG CapturedFileNameFlags;
  AvmpTryToFetchObjectName(&CapturedFileName, ObjectAttributes, &CapturedFileNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtOpenFile,
    ReturnValue,

    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),              "FileHandle",        *FileHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS,      &AvmpHookEnum_FILE_ACCESS_MASK,        "DesiredAccess",     DesiredAccess,
    AEVT_UNICODE_STRING | CapturedFileNameFlags, CapturedFileName.Length, "FileName", CapturedFileName.Buffer,
    AEVT_ENUM | AEVT_HINT_FLAGS,      &AvmpHookEnum_SHARE_ACCESS,       "ShareAccess",       ShareAccess,
    AEVT_ENUM | AEVT_HINT_FLAGS,      &AvmpHookEnum_CREATE_OPTIONS,     "OpenOptions",       OpenOptions,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtReadFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtReadFile,
  _In_ HANDLE FileHandle,
  _In_opt_ HANDLE Event,
  _In_opt_ PIO_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcContext,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _Out_writes_bytes_(Length) PVOID Buffer,
  _In_ ULONG Length,
  _In_opt_ PLARGE_INTEGER ByteOffset,
  _In_opt_ PULONG Key
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtReadFile)(AvmpHookFunction_NtReadFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    Event,
    ApcRoutine,
    ApcContext,
    IoStatusBlock,
    Buffer,
    Length,
    ByteOffset,
    Key);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtReadFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BufferPointer", Buffer,
    AEVT_BINARY, Length, "Buffer", Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtWriteFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtWriteFile,
  _In_ HANDLE FileHandle,
  _In_opt_ HANDLE Event,
  _In_opt_ PIO_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcContext,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_reads_bytes_(Length) PVOID Buffer,
  _In_ ULONG Length,
  _In_opt_ PLARGE_INTEGER ByteOffset,
  _In_opt_ PULONG Key
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtWriteFile)(AvmpHookFunction_NtWriteFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    Event,
    ApcRoutine,
    ApcContext,
    IoStatusBlock,
    Buffer,
    Length,
    ByteOffset,
    Key);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtWriteFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BufferPointer", Buffer,
    AEVT_BINARY, Length, "Buffer", Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtDeleteFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtDeleteFile,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtDeleteFile)(AvmpHookFunction_NtDeleteFile.Function.SSDTEntry->OriginalRoutineAddress))(
    ObjectAttributes);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedFileName;
  ULONG CapturedFileNameFlags;
  AvmpTryToFetchObjectName(&CapturedFileName, ObjectAttributes, &CapturedFileNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtDeleteFile,
    ReturnValue,
    AEVT_UNICODE_STRING | CapturedFileNameFlags, CapturedFileName.Length, "FileName", CapturedFileName.Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueryInformationFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtQueryInformationFile,
  _In_ HANDLE FileHandle,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _Out_writes_bytes_(Length) PVOID FileInformation,
  _In_ ULONG Length,
  _In_ FILE_INFORMATION_CLASS FileInformationClass
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueryInformationFile)(AvmpHookFunction_NtQueryInformationFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    IoStatusBlock,
    FileInformation,
    Length,
    FileInformationClass);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueryInformationFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_ENUM, &AvmpHookEnum_FILE_INFORMATION_CLASS, "FileInformationClass", FileInformationClass,
    AEVT_BINARY, Length, "FileInformation", FileInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueryInformationFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtSetInformationFile,
  _In_ HANDLE FileHandle,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_reads_bytes_(Length) PVOID FileInformation,
  _In_ ULONG Length,
  _In_ FILE_INFORMATION_CLASS FileInformationClass
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSetInformationFile)(AvmpHookFunction_NtSetInformationFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    IoStatusBlock,
    FileInformation,
    Length,
    FileInformationClass);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSetInformationFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_ENUM, &AvmpHookEnum_FILE_INFORMATION_CLASS, "FileInformationClass", FileInformationClass,
    AEVT_BINARY, Length, "FileInformation", FileInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtDeviceIoControlFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtDeviceIoControlFile,
  _In_ HANDLE FileHandle,
  _In_opt_ HANDLE Event,
  _In_opt_ PIO_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcContext,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_ ULONG IoControlCode,
  _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
  _In_ ULONG InputBufferLength,
  _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
  _In_ ULONG OutputBufferLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtDeviceIoControlFile)(AvmpHookFunction_NtDeviceIoControlFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    Event,
    ApcRoutine,
    ApcContext,
    IoStatusBlock,
    IoControlCode,
    InputBuffer,
    InputBufferLength,
    OutputBuffer,
    OutputBufferLength);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtDeviceIoControlFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),     "FileHandle",          FileHandle,
    AEVT_INTEGER | AEVT_HINT_HEX,     sizeof(ULONG),      "IoControlCode",       IoControlCode,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID),      "InputBufferPointer",  InputBuffer,
    AEVT_BINARY,                      InputBufferLength,  "InputBuffer",         InputBuffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID),      "OutputBufferPointer", OutputBuffer,
    AEVT_BINARY,                      OutputBufferLength, "OutputBuffer",        OutputBuffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtFsControlFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtFsControlFile,
  _In_ HANDLE FileHandle,
  _In_opt_ HANDLE Event,
  _In_opt_ PIO_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcContext,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_ ULONG FsControlCode,
  _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
  _In_ ULONG InputBufferLength,
  _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
  _In_ ULONG OutputBufferLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtFsControlFile)(AvmpHookFunction_NtFsControlFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    Event,
    ApcRoutine,
    ApcContext,
    IoStatusBlock,
    FsControlCode,
    InputBuffer,
    InputBufferLength,
    OutputBuffer,
    OutputBufferLength);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtFsControlFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_INTEGER | AEVT_HINT_HEX, sizeof(ULONG), "FsControlCode", FsControlCode,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "InputBufferPointer", InputBuffer,
    AEVT_BINARY, InputBufferLength, "InputBuffer", InputBuffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "OutputBufferPointer", OutputBuffer,
    AEVT_BINARY, OutputBufferLength, "OutputBuffer", OutputBuffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueryVolumeInformationFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtQueryVolumeInformationFile,
  _In_ HANDLE FileHandle,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _Out_writes_bytes_(Length) PVOID FsInformation,
  _In_ ULONG Length,
  _In_ FS_INFORMATION_CLASS FsInformationClass
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueryVolumeInformationFile)(AvmpHookFunction_NtQueryVolumeInformationFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    IoStatusBlock,
    FsInformation,
    Length,
    FsInformationClass);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueryVolumeInformationFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_ENUM, &AvmpHookEnum_FS_INFORMATION_CLASS, "FsInformationClass", FsInformationClass,
    AEVT_BINARY, Length, "FsInformation", FsInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSetVolumeInformationFile
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtSetVolumeInformationFile,
  _In_ HANDLE FileHandle,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_reads_bytes_(Length) PVOID FsInformation,
  _In_ ULONG Length,
  _In_ FS_INFORMATION_CLASS FsInformationClass
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSetVolumeInformationFile)(AvmpHookFunction_NtSetVolumeInformationFile.Function.SSDTEntry->OriginalRoutineAddress))(
    FileHandle,
    IoStatusBlock,
    FsInformation,
    Length,
    FsInformationClass);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSetVolumeInformationFile,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "FileHandle", FileHandle,
    AEVT_ENUM, &AvmpHookEnum_FS_INFORMATION_CLASS, "FsInformationClass", FsInformationClass,
    AEVT_BINARY, Length, "FsInformation", FsInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtLoadDriver
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtLoadDriver,
  _In_ PUNICODE_STRING DriverServiceName
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtLoadDriver)(AvmpHookFunction_NtLoadDriver.Function.SSDTEntry->OriginalRoutineAddress))(
    DriverServiceName);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedDriverServiceName;
  ULONG CapturedDriverServiceNameFlags;
  AvmpTryToFetchString(&CapturedDriverServiceName, DriverServiceName, &CapturedDriverServiceNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtLoadDriver,
    ReturnValue,
    AEVT_UNICODE_STRING | CapturedDriverServiceNameFlags, CapturedDriverServiceName.Length, "DriverServiceName", CapturedDriverServiceName.Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtUnloadDriver
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("IO",
NTSTATUS,
NtUnloadDriver,
  _In_ PUNICODE_STRING DriverServiceName
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtUnloadDriver)(AvmpHookFunction_NtUnloadDriver.Function.SSDTEntry->OriginalRoutineAddress))(
    DriverServiceName);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedDriverServiceName;
  ULONG CapturedDriverServiceNameFlags;
  AvmpTryToFetchString(&CapturedDriverServiceName, DriverServiceName, &CapturedDriverServiceNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtUnloadDriver,
    ReturnValue,
    AEVT_UNICODE_STRING | CapturedDriverServiceNameFlags, CapturedDriverServiceName.Length, "DriverServiceName", CapturedDriverServiceName.Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

#pragma endregion IO

#pragma region Registry

//////////////////////////////////////////////////////////////////////////
// NtQueryValueKey
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Registry",
NTSTATUS,
NtQueryValueKey,
  _In_ HANDLE KeyHandle,
  _In_ PUNICODE_STRING ValueName,
  _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
  _In_ ULONG Length,
  _Out_ PULONG ResultLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueryValueKey)(AvmpHookFunction_NtQueryValueKey.Function.SSDTEntry->OriginalRoutineAddress))(
    KeyHandle,
    ValueName,
    KeyValueInformationClass,
    KeyValueInformation,
    Length,
    ResultLength);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedValueName;
  ULONG CapturedValueNameFlags;
  AvmpTryToFetchString(&CapturedValueName, ValueName, &CapturedValueNameFlags);

  ULONG CapturedResultLength;
  AvmpTryToFetchInt(&CapturedResultLength, ResultLength);

  if (
    !NT_SUCCESS(ReturnValue) &&

    //
    // These two errors mean that partial data has been written
    // and ResultLength is valid.
    //
    ReturnValue != STATUS_BUFFER_OVERFLOW &&
    ReturnValue != STATUS_BUFFER_TOO_SMALL
    )
  {
    CapturedResultLength = 0;
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueryValueKey,
    ReturnValue,

    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),                       "KeyHandle",                KeyHandle,
    AEVT_UNICODE_STRING | CapturedValueNameFlags, CapturedValueName.Length,                      "ValueName", CapturedValueName.Buffer,
    AEVT_ENUM,                        &AvmpHookEnum_KEY_VALUE_INFORMATION_CLASS, "KeyValueInformationClass", KeyValueInformationClass,
    AEVT_BINARY, CapturedResultLength, "KeyValueInformation", KeyValueInformation,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSetValueKey
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Registry",
NTSTATUS,
NtSetValueKey,
  _In_ HANDLE KeyHandle,
  _In_ PUNICODE_STRING ValueName,
  _In_opt_ ULONG TitleIndex,
  _In_ ULONG Type,
  _In_reads_bytes_opt_(DataSize) PVOID Data,
  _In_ ULONG DataSize
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSetValueKey)(AvmpHookFunction_NtSetValueKey.Function.SSDTEntry->OriginalRoutineAddress))(
    KeyHandle,
    ValueName,
    TitleIndex,
    Type,
    Data,
    DataSize);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedValueName;
  ULONG CapturedValueNameFlags;
  AvmpTryToFetchString(&CapturedValueName, ValueName, &CapturedValueNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSetValueKey,
    ReturnValue,

    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),                       "KeyHandle",                KeyHandle,
    AEVT_UNICODE_STRING | CapturedValueNameFlags, CapturedValueName.Length,                      "ValueName", CapturedValueName.Buffer,
    AEVT_ENUM,                        &AvmpHookEnum_REG_TYPE,                    "Type",                     Type,
    AEVT_BINARY,                      DataSize,                             "Data",                     Data,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

#pragma endregion Registry

#pragma region Memory

//////////////////////////////////////////////////////////////////////////
// NtAllocateVirtualMemory
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtAllocateVirtualMemory,
  _In_ HANDLE ProcessHandle,
  _Inout_ _At_ (*BaseAddress, _Readable_bytes_ (*RegionSize) _Writable_bytes_ (*RegionSize) _Post_readable_byte_size_ (*RegionSize)) PVOID *BaseAddress,
  _In_ ULONG_PTR ZeroBits,
  _Inout_ PSIZE_T RegionSize,
  _In_ ULONG AllocationType,
  _In_ ULONG Protect
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtAllocateVirtualMemory)(AvmpHookFunction_NtAllocateVirtualMemory.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    ZeroBits,
    RegionSize,
    AllocationType,
    Protect);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtAllocateVirtualMemory,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(PVOID), "BaseAddress", BaseAddress,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(SIZE_T), "RegionSize", RegionSize,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_ALLOCATION_TYPE, "AllocationType", AllocationType,
    AEVT_ENUM, &AvmpHookEnum_PAGE_PROTECT, "Protect", Protect,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtFreeVirtualMemory
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtFreeVirtualMemory,
  _In_ HANDLE ProcessHandle,
  _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
  _Inout_ PSIZE_T RegionSize,
  _In_ ULONG FreeType
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtFreeVirtualMemory)(AvmpHookFunction_NtFreeVirtualMemory.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    RegionSize,
    FreeType);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtFreeVirtualMemory,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(PVOID), "BaseAddress", BaseAddress,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(SIZE_T), "RegionSize", RegionSize,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_ALLOCATION_TYPE, "FreeType", FreeType,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtReadVirtualMemory
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtReadVirtualMemory,
  _In_ HANDLE ProcessHandle,
  _In_opt_ PVOID BaseAddress,
  _Out_writes_bytes_(BufferSize) PVOID Buffer,
  _In_ SIZE_T BufferSize,
  _Out_opt_ PSIZE_T NumberOfBytesRead
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtReadVirtualMemory)(AvmpHookFunction_NtReadVirtualMemory.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    Buffer,
    BufferSize,
    NumberOfBytesRead);

  AvmpReturnIfNotWatched(ReturnValue);

  SIZE_T CapturedNumberOfBytesRead;
  AvmpTryToFetchInt(&CapturedNumberOfBytesRead, NumberOfBytesRead);

  SIZE_T BufferToLogSize = 0;
  if (NT_SUCCESS(ReturnValue))
  {
    BufferToLogSize = CapturedNumberOfBytesRead
      ? CapturedNumberOfBytesRead
      : BufferSize;
  }

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtReadVirtualMemory,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BaseAddress", BaseAddress,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BufferPointer", Buffer,
    AEVT_BINARY, BufferToLogSize, "Buffer", Buffer,
    AEVT_INTEGER, sizeof(SIZE_T), "BufferSize", BufferSize,
    AEVT_INTEGER, sizeof(SIZE_T), "NumberOfBytesRead", CapturedNumberOfBytesRead,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtWriteVirtualMemory
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtWriteVirtualMemory,
  _In_ HANDLE ProcessHandle,
  _In_opt_ PVOID BaseAddress,
  _In_reads_bytes_(BufferSize) PVOID Buffer,
  _In_ SIZE_T BufferSize,
  _Out_opt_ PSIZE_T NumberOfBytesWritten
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtWriteVirtualMemory)(AvmpHookFunction_NtWriteVirtualMemory.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    Buffer,
    BufferSize,
    NumberOfBytesWritten);

  AvmpReturnIfNotWatched(ReturnValue);

  SIZE_T CapturedNumberOfBytesWritten;
  AvmpTryToFetchInt(&CapturedNumberOfBytesWritten, NumberOfBytesWritten);

  SIZE_T BufferToLogSize = 0;
  if (NT_SUCCESS(ReturnValue))
  {
    BufferToLogSize = CapturedNumberOfBytesWritten
      ? CapturedNumberOfBytesWritten
      : BufferSize;
  }

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  if (ProcessHandleToPid != 0 && ProcessHandleToPid != PsGetCurrentProcessId())
  {
    AvmDbgPrint(
      "[INJECTION] Writing memory from PID: %u to PID: %u\n",
      PsGetCurrentProcessId(),
      ProcessHandleToPid);

    AvmHookAddWatchedProcessId(ProcessHandleToPid, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtWriteVirtualMemory,
    ReturnValue,

    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BaseAddress", BaseAddress,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BufferPointer", Buffer,
    AEVT_BINARY, BufferToLogSize, "Buffer", Buffer,
    AEVT_INTEGER, sizeof(SIZE_T), "BufferSize", BufferSize,
    AEVT_INTEGER, sizeof(SIZE_T), "NumberOfBytesWritten", CapturedNumberOfBytesWritten,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtProtectVirtualMemory
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtProtectVirtualMemory,
  _In_ HANDLE ProcessHandle,
  _Inout_ PVOID *BaseAddress,
  _Inout_ PSIZE_T RegionSize,
  _In_ ULONG NewProtect,
  _Out_ PULONG OldProtect
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtProtectVirtualMemory)(AvmpHookFunction_NtProtectVirtualMemory.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress,
    RegionSize,
    NewProtect,
    OldProtect);

  AvmpReturnIfNotWatched(ReturnValue);

  PVOID CapturedBaseAddress;
  AvmpTryToFetchInt(&CapturedBaseAddress, BaseAddress);

  SIZE_T CapturedRegionSize;
  AvmpTryToFetchInt(&CapturedRegionSize, RegionSize);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtProtectVirtualMemory,
    ReturnValue,

    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "BaseAddress", BaseAddress,
    AEVT_BINARY | AEVT_HINT_INDIRECT_PROCESS, ProcessHandle, CapturedRegionSize, "Buffer", CapturedBaseAddress,
    AEVT_INTEGER, sizeof(SIZE_T), "RegionSize", CapturedRegionSize,
    AEVT_ENUM, &AvmpHookEnum_PAGE_PROTECT, "NewProtect", NewProtect,
    AEVT_ENUM | AEVT_HINT_PROBE, &AvmpHookEnum_PAGE_PROTECT, "OldProtect", OldProtect,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtMapViewOfSection
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtMapViewOfSection,
  _In_ HANDLE SectionHandle,
  _In_ HANDLE ProcessHandle,
  _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
  _In_ ULONG_PTR ZeroBits,
  _In_ SIZE_T CommitSize,
  _Inout_opt_ PLARGE_INTEGER SectionOffset,
  _Inout_ PSIZE_T ViewSize,
  _In_ SECTION_INHERIT InheritDisposition,
  _In_ ULONG AllocationType,
  _In_ ULONG Win32Protect
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtMapViewOfSection)(AvmpHookFunction_NtMapViewOfSection.Function.SSDTEntry->OriginalRoutineAddress))(
    SectionHandle,
    ProcessHandle,
    BaseAddress,
    ZeroBits,
    CommitSize,
    SectionOffset,
    ViewSize,
    InheritDisposition,
    AllocationType,
    Win32Protect);

  AvmpReturnIfNotWatched(ReturnValue);

  PVOID CapturedBaseAddress;
  AvmpTryToFetchInt(&CapturedBaseAddress, BaseAddress);

  SIZE_T CapturedViewSize;
  AvmpTryToFetchInt(&CapturedViewSize, ViewSize);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  if (ProcessHandleToPid != 0 && ProcessHandleToPid != PsGetCurrentProcessId())
  {
    AvmDbgPrint(
      "[INJECTION] Mapping view from PID: %u to PID: %u\n",
      PsGetCurrentProcessId(),
      ProcessHandleToPid);

    AvmHookAddWatchedProcessId(ProcessHandleToPid, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtMapViewOfSection,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),           "SectionHandle",      SectionHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),           "ProcessHandle",      ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE),           "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID),            "BaseAddress",        CapturedBaseAddress,
    AEVT_BINARY | AEVT_HINT_INDIRECT_PROCESS, ProcessHandle, CapturedViewSize, "Buffer", CapturedBaseAddress,
    AEVT_INTEGER,                     sizeof(SIZE_T),           "ViewSize",           CapturedViewSize,
    AEVT_ENUM,                        &AvmpHookEnum_SECTION_INHERIT, "InheritDisposition", InheritDisposition,
    AEVT_ENUM | AEVT_HINT_FLAGS,      &AvmpHookEnum_ALLOCATION_TYPE, "AllocationType",     AllocationType,
    AEVT_ENUM,                        &AvmpHookEnum_PAGE_PROTECT,    "Win32Protect",       Win32Protect,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtUnmapViewOfSection
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Memory",
NTSTATUS,
NtUnmapViewOfSection,
  _In_ HANDLE ProcessHandle,
  _In_ PVOID BaseAddress
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtUnmapViewOfSection)(AvmpHookFunction_NtUnmapViewOfSection.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    BaseAddress);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  if (ProcessHandleToPid != 0 && ProcessHandleToPid != PsGetCurrentProcessId())
  {
    AvmDbgPrint(
      "[INJECTION] Unmapping view from PID: %u to PID: %u\n",
      PsGetCurrentProcessId(),
      ProcessHandleToPid);

    AvmHookAddWatchedProcessId(ProcessHandleToPid, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtUnmapViewOfSection,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE),           "ProcessHandle",      ProcessHandle,
    AEVT_INTEGER,                     sizeof(HANDLE),           "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID),            "BaseAddress",        BaseAddress,

    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

#pragma endregion Memory

#pragma region Process

//////////////////////////////////////////////////////////////////////////
// NtCreateProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtCreateProcess,
  _Out_ PHANDLE ProcessHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ HANDLE ParentProcess,
  _In_ BOOLEAN InheritObjectTable,
  _In_opt_ HANDLE SectionHandle,
  _In_opt_ HANDLE DebugPort,
  _In_opt_ HANDLE ExceptionPort
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateProcess)(AvmpHookFunction_NtCreateProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    DesiredAccess,
    ObjectAttributes,
    ParentProcess,
    InheritObjectTable,
    SectionHandle,
    DebugPort,
    ExceptionPort);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  HANDLE CapturedProcessHandle;
  AvmpTryToFetchInt(&CapturedProcessHandle, ProcessHandle);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(CapturedProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", CapturedProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_PROCESS_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ParentProcess", ParentProcess,
    AEVT_BOOL, sizeof(BOOLEAN), "InheritObjectTable", InheritObjectTable,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "SectionHandle", SectionHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "DebugPort", DebugPort,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ExceptionPort", ExceptionPort,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtCreateProcessEx
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtCreateProcessEx,
  _Out_ PHANDLE ProcessHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ HANDLE ParentProcess,
  _In_ ULONG Flags,
  _In_opt_ HANDLE SectionHandle,
  _In_opt_ HANDLE DebugPort,
  _In_opt_ HANDLE ExceptionPort,
  _In_ ULONG JobMemberLevel
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateProcessEx)(AvmpHookFunction_NtCreateProcessEx.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    DesiredAccess,
    ObjectAttributes,
    ParentProcess,
    Flags,
    SectionHandle,
    DebugPort,
    ExceptionPort,
    JobMemberLevel);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  HANDLE CapturedProcessHandle;
  AvmpTryToFetchInt(&CapturedProcessHandle, ProcessHandle);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(CapturedProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateProcessEx,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", CapturedProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_PROCESS_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ParentProcess", ParentProcess,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_PROCESS_CREATE, "Flags", Flags,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "SectionHandle", SectionHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "DebugPort", DebugPort,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ExceptionPort", ExceptionPort,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtCreateUserProcess
//////////////////////////////////////////////////////////////////////////

typedef struct _SECTION_IMAGE_INFORMATION
{
  PVOID TransferAddress;
  ULONG ZeroBits;
  SIZE_T MaximumStackSize;
  SIZE_T CommittedStackSize;
  ULONG SubSystemType;
  union
  {
    struct
    {
      USHORT SubSystemMinorVersion;
      USHORT SubSystemMajorVersion;
    };
    ULONG SubSystemVersion;
  };
  union
  {
    struct
    {
      USHORT MajorOperatingSystemVersion;
      USHORT MinorOperatingSystemVersion;
    };
    ULONG OperatingSystemVersion;
  };
  USHORT ImageCharacteristics;
  USHORT DllCharacteristics;
  USHORT Machine;
  BOOLEAN ImageContainsCode;
  union
  {
    UCHAR ImageFlags;
    struct
    {
      UCHAR ComPlusNativeReady : 1;
      UCHAR ComPlusILOnly : 1;
      UCHAR ImageDynamicallyRelocated : 1;
      UCHAR ImageMappedFlat : 1;
      UCHAR BaseBelow4gb : 1;
      UCHAR ComPlusPrefer32bit : 1;
      UCHAR Reserved : 2;
    };
  };
  ULONG LoaderFlags;
  ULONG ImageFileSize;
  ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
  UNICODE_STRING DosPath;
  HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
  ULONG MaximumLength;
  ULONG Length;

  ULONG Flags;
  ULONG DebugFlags;

  HANDLE ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StandardInput;
  HANDLE StandardOutput;
  HANDLE StandardError;

  CURDIR CurrentDirectory;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PVOID Environment;

  ULONG StartingX;
  ULONG StartingY;
  ULONG CountX;
  ULONG CountY;
  ULONG CountCharsX;
  ULONG CountCharsY;
  ULONG FillAttribute;

  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopInfo;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeData;
  RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

  ULONG EnvironmentSize;
  ULONG EnvironmentVersion;
  PVOID PackageDependencyData;
  ULONG ProcessGroupId;
  ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION
{
  ULONG Length;
  HANDLE Process;
  HANDLE Thread;
  CLIENT_ID ClientId;
  SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef enum _PS_CREATE_STATE
{
  PsCreateInitialState,
  PsCreateFailOnFileOpen,
  PsCreateFailOnSectionCreate,
  PsCreateFailExeFormat,
  PsCreateFailMachineMismatch,
  PsCreateFailExeName, // Debugger specified
  PsCreateSuccess,
  PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
  SIZE_T Size;
  PS_CREATE_STATE State;
  union
  {
    // PsCreateInitialState
    struct
    {
      union
      {
        ULONG InitFlags;
        struct
        {
          UCHAR WriteOutputOnExit : 1;
          UCHAR DetectManifest : 1;
          UCHAR IFEOSkipDebugger : 1;
          UCHAR IFEODoNotPropagateKeyState : 1;
          UCHAR SpareBits1 : 4;
          UCHAR SpareBits2 : 8;
          USHORT ProhibitedImageCharacteristics : 16;
        };
      };
      ACCESS_MASK AdditionalFileAccess;
    } InitState;

    // PsCreateFailOnSectionCreate
    struct
    {
      HANDLE FileHandle;
    } FailSection;

    // PsCreateFailExeFormat
    struct
    {
      USHORT DllCharacteristics;
    } ExeFormat;

    // PsCreateFailExeName
    struct
    {
      HANDLE IFEOKey;
    } ExeName;

    // PsCreateSuccess
    struct
    {
      union
      {
        ULONG OutputFlags;
        struct
        {
          UCHAR ProtectedProcess : 1;
          UCHAR AddressSpaceOverride : 1;
          UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
          UCHAR ManifestDetected : 1;
          UCHAR ProtectedProcessLight : 1;
          UCHAR SpareBits1 : 3;
          UCHAR SpareBits2 : 8;
          USHORT SpareBits3 : 16;
        };
      };
      HANDLE FileHandle;
      HANDLE SectionHandle;
      ULONGLONG UserProcessParametersNative;
      ULONG UserProcessParametersWow64;
      ULONG CurrentParameterFlags;
      ULONGLONG PebAddressNative;
      ULONG PebAddressWow64;
      ULONGLONG ManifestAddress;
      ULONG ManifestSize;
    } SuccessState;
  };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
  ULONG_PTR Attribute;
  SIZE_T Size;
  union
  {
    ULONG_PTR Value;
    PVOID ValuePtr;
  };
  PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
  SIZE_T TotalLength;
  PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtCreateUserProcess,
  _Out_ PHANDLE ProcessHandle,
  _Out_ PHANDLE ThreadHandle,
  _In_ ACCESS_MASK ProcessDesiredAccess,
  _In_ ACCESS_MASK ThreadDesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
  _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
  _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
  _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
  _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
  _Inout_ PPS_CREATE_INFO CreateInfo,
  _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateUserProcess)(AvmpHookFunction_NtCreateUserProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    ThreadHandle,
    ProcessDesiredAccess,
    ThreadDesiredAccess,
    ProcessObjectAttributes,
    ThreadObjectAttributes,
    ProcessFlags,
    ThreadFlags,
    ProcessParameters,
    CreateInfo,
    AttributeList);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedProcessObjectName;
  ULONG CapturedProcessObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedProcessObjectName, ProcessObjectAttributes, &CapturedProcessObjectNameFlags);

  UNICODE_STRING CapturedThreadObjectName;
  ULONG CapturedThreadObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedThreadObjectName, ThreadObjectAttributes, &CapturedThreadObjectNameFlags);

  HANDLE CaptureadProcessHandle;
  AvmpTryToFetchInt(&CaptureadProcessHandle, ProcessHandle);

  HANDLE CaptureadThreadHandle;
  AvmpTryToFetchInt(&CaptureadThreadHandle, ThreadHandle);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(CaptureadProcessHandle, &ProcessHandleToPid);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(CaptureadThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateUserProcess,
    ReturnValue,
    AEVT_UNICODE_STRING | CapturedProcessObjectNameFlags, CapturedProcessObjectName.Length, "ProcessObjectName", CapturedProcessObjectName.Buffer,
    AEVT_UNICODE_STRING | CapturedThreadObjectNameFlags, CapturedThreadObjectName.Length, "ThreadObjectName", CapturedThreadObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", CaptureadProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", CaptureadThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_PROCESS_CREATE, "ProcessFlags", ProcessFlags,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_THREAD_CREATE, "ThreadFlags", ThreadFlags,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtOpenProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtOpenProcess,
  _Out_ PHANDLE ProcessHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_opt_ PCLIENT_ID ClientId
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtOpenProcess)(AvmpHookFunction_NtOpenProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    DesiredAccess,
    ObjectAttributes,
    ClientId);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  HANDLE CapturedProcessHandle;
  AvmpTryToFetchInt(&CapturedProcessHandle, ProcessHandle);

  PHANDLE CapturedUniqueProcessPointer = ClientId ? &ClientId->UniqueProcess : NULL;
  PHANDLE CapturedUniqueThreadPointer  = ClientId ? &ClientId->UniqueThread  : NULL;

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(CapturedProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtOpenProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", CapturedProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_PROCESS_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(HANDLE), "ClientIdUniqueProcess", CapturedUniqueProcessPointer,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(HANDLE), "ClientIdUniqueThread", CapturedUniqueThreadPointer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSuspendProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtSuspendProcess,
  _In_ HANDLE ProcessHandle
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSuspendProcess)(AvmpHookFunction_NtSuspendProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSuspendProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtResumeProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtResumeProcess,
  _In_ HANDLE ProcessHandle
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtResumeProcess)(AvmpHookFunction_NtResumeProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtResumeProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtTerminateProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtTerminateProcess,
  _In_opt_ HANDLE ProcessHandle,
  _In_ NTSTATUS ExitStatus
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtTerminateProcess)(AvmpHookFunction_NtTerminateProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    ExitStatus);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtTerminateProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_ENUM, &AvmpHookEnum_NTSTATUS, "ExitStatus", ExitStatus,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueryInformationProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtQueryInformationProcess,
  _In_ HANDLE ProcessHandle,
  _In_ PROCESSINFOCLASS ProcessInformationClass,
  _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
  _In_ ULONG ProcessInformationLength,
  _Out_opt_ PULONG ReturnLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueryInformationProcess)(AvmpHookFunction_NtQueryInformationProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    ProcessInformationClass,
    ProcessInformation,
    ProcessInformationLength,
    ReturnLength);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  ULONG CapturedReturnLength;
  AvmpTryToFetchInt(&CapturedReturnLength, ReturnLength);

  if (
    !NT_SUCCESS(ReturnValue) &&

    //
    // These two errors mean that partial data has been written
    // and ResultLength is valid.
    //
    ReturnValue != STATUS_BUFFER_OVERFLOW &&
    ReturnValue != STATUS_BUFFER_TOO_SMALL
    )
  {
    CapturedReturnLength = 0;
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueryInformationProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_ENUM, &AvmpHookEnum_PROCESSINFOCLASS, "ProcessInformationClass", ProcessInformationClass,
    AEVT_BINARY, CapturedReturnLength, "ProcessInformation", ProcessInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSetInformationProcess
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtSetInformationProcess,
  _In_ HANDLE ProcessHandle,
  _In_ PROCESSINFOCLASS ProcessInformationClass,
  _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
  _In_ ULONG ProcessInformationLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSetInformationProcess)(AvmpHookFunction_NtSetInformationProcess.Function.SSDTEntry->OriginalRoutineAddress))(
    ProcessHandle,
    ProcessInformationClass,
    ProcessInformation,
    ProcessInformationLength);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSetInformationProcess,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_ENUM, &AvmpHookEnum_PROCESSINFOCLASS, "ProcessInformationClass", ProcessInformationClass,
    AEVT_BINARY, ProcessInformationLength, "ProcessInformation", ProcessInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtCreateThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtCreateThread,
  _Out_ PHANDLE ThreadHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ HANDLE ProcessHandle,
  _Out_ PCLIENT_ID ClientId,
  _In_ PCONTEXT ThreadContext,
  _In_ /*PINITIAL_TEB*/ PVOID InitialTeb,
  _In_ BOOLEAN CreateSuspended
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateThread)(AvmpHookFunction_NtCreateThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    DesiredAccess,
    ObjectAttributes,
    ProcessHandle,
    ClientId,
    ThreadContext,
    InitialTeb,
    CreateSuspended);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  HANDLE CapturedThreadHandle;
  AvmpTryToFetchInt(&CapturedThreadHandle, ThreadHandle);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(CapturedThreadHandle, &ThreadHandleToTid);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  if (ProcessHandleToPid != 0 && ProcessHandleToPid != PsGetCurrentProcessId())
  {
    AvmDbgPrint(
      "[INJECTION] Thread injection from PID: %u to PID: %u, suspended: %s\n",
      PsGetCurrentProcessId(),
      ProcessHandleToPid,
      CreateSuspended ? "TRUE" : "FALSE");

    AvmHookAddWatchedProcessId(ProcessHandleToPid, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", CapturedThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_THREAD_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
#if defined(_X86_)
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(PVOID), "ThreadContext->Eip", &ThreadContext->Eip,
#elif defined (_AMD64_)
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(PVOID), "ThreadContext->Rip", &ThreadContext->Rip,
#endif
    AEVT_BOOL, sizeof(BOOLEAN), "CreateSuspended", CreateSuspended,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtCreateThreadEx
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtCreateThreadEx,
  _Out_ PHANDLE ThreadHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ HANDLE ProcessHandle,
  _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
  _In_opt_ PVOID Argument,
  _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
  _In_ SIZE_T ZeroBits,
  _In_ SIZE_T StackSize,
  _In_ SIZE_T MaximumStackSize,
  _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateThreadEx)(AvmpHookFunction_NtCreateThreadEx.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    DesiredAccess,
    ObjectAttributes,
    ProcessHandle,
    StartRoutine,
    Argument,
    CreateFlags,
    ZeroBits,
    StackSize,
    MaximumStackSize,
    AttributeList);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  HANDLE CapturedThreadHandle;
  AvmpTryToFetchInt(&CapturedThreadHandle, ThreadHandle);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(CapturedThreadHandle, &ThreadHandleToTid);

  HANDLE ProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(ProcessHandle, &ProcessHandleToPid);

  if (ProcessHandleToPid != 0 && ProcessHandleToPid != PsGetCurrentProcessId())
  {
    AvmDbgPrint(
      "[INJECTION] Thread injection from PID: %u to PID: %u, suspended: %s\n",
      PsGetCurrentProcessId(),
      ProcessHandleToPid,
      (CreateFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) ? "TRUE" : "FALSE");

    AvmHookAddWatchedProcessId(ProcessHandleToPid, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateThreadEx,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", CapturedThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_THREAD_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ProcessHandle", ProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ProcessHandleToPid", ProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "StartRoutine", StartRoutine,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "Argument", Argument,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_THREAD_CREATE, "CreateFlags", CreateFlags,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtOpenThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtOpenThread,
  _Out_ PHANDLE ThreadHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_opt_ PCLIENT_ID ClientId
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtOpenThread)(AvmpHookFunction_NtOpenThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    DesiredAccess,
    ObjectAttributes,
    ClientId);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  HANDLE CapturedThreadHandle;
  AvmpTryToFetchInt(&CapturedThreadHandle, ThreadHandle);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(CapturedThreadHandle, &ThreadHandleToTid);

  PHANDLE CapturedUniqueProcessPointer = ClientId ? &ClientId->UniqueProcess : NULL;
  PHANDLE CapturedUniqueThreadPointer  = ClientId ? &ClientId->UniqueThread  : NULL;

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtOpenThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", CapturedThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_THREAD_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(HANDLE), "ClientIdUniqueProcess", CapturedUniqueProcessPointer,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(HANDLE), "ClientIdUniqueThread", CapturedUniqueThreadPointer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSuspendThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtSuspendThread,
  _In_ HANDLE ThreadHandle,
  _Out_opt_ PULONG PreviousSuspendCount
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSuspendThread)(AvmpHookFunction_NtSuspendThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    PreviousSuspendCount);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSuspendThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(ULONG), "PreviousSuspendCount", PreviousSuspendCount,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtResumeThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtResumeThread,
  _In_ HANDLE ThreadHandle,
  _Out_opt_ PULONG PreviousSuspendCount
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtResumeThread)(AvmpHookFunction_NtResumeThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    PreviousSuspendCount);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtResumeThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(ULONG), "PreviousSuspendCount", PreviousSuspendCount,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtTerminateThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtTerminateThread,
  _In_opt_ HANDLE ThreadHandle,
  _In_ NTSTATUS ExitStatus
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtTerminateThread)(AvmpHookFunction_NtTerminateThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    ExitStatus);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtTerminateThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM, &AvmpHookEnum_NTSTATUS, "ExitStatus", ExitStatus,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueryInformationThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtQueryInformationThread,
  _In_ HANDLE ThreadHandle,
  _In_ THREADINFOCLASS ThreadInformationClass,
  _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
  _In_ ULONG ThreadInformationLength,
  _Out_opt_ PULONG ReturnLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueryInformationThread)(AvmpHookFunction_NtQueryInformationThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    ThreadInformationClass,
    ThreadInformation,
    ThreadInformationLength,
    ReturnLength);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  ULONG CapturedReturnLength;
  AvmpTryToFetchInt(&CapturedReturnLength, ReturnLength);

  if (
    !NT_SUCCESS(ReturnValue) &&

    //
    // These two errors mean that partial data has been written
    // and ResultLength is valid.
    //
    ReturnValue != STATUS_BUFFER_OVERFLOW &&
    ReturnValue != STATUS_BUFFER_TOO_SMALL
    )
  {
    CapturedReturnLength = 0;
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueryInformationThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM, &AvmpHookEnum_THREADINFOCLASS, "ThreadInformationClass", ThreadInformationClass,
    AEVT_BINARY, CapturedReturnLength, "ThreadInformation", ThreadInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSetInformationThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtSetInformationThread,
  _In_ HANDLE ThreadHandle,
  _In_ THREADINFOCLASS ThreadInformationClass,
  _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
  _In_ ULONG ThreadInformationLength
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSetInformationThread)(AvmpHookFunction_NtSetInformationThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    ThreadInformationClass,
    ThreadInformation,
    ThreadInformationLength);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSetInformationThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_ENUM, &AvmpHookEnum_THREADINFOCLASS, "ThreadInformationClass", ThreadInformationClass,
    AEVT_BINARY, ThreadInformationLength, "ThreadInformation", ThreadInformation,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}
//////////////////////////////////////////////////////////////////////////
// NtGetContextThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtGetContextThread,
  _In_ HANDLE ThreadHandle,
  _Inout_ PCONTEXT ThreadContext
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtGetContextThread)(AvmpHookFunction_NtGetContextThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    ThreadContext);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtGetContextThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtSetContextThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtSetContextThread,
  _In_ HANDLE ThreadHandle,
  _In_  PCONTEXT ThreadContext
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtSetContextThread)(AvmpHookFunction_NtSetContextThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    ThreadContext);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtSetContextThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
#if defined(_X86_)
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(PVOID), "ThreadContext->Eip", &ThreadContext->Eip,
#elif defined (_AMD64_)
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(PVOID), "ThreadContext->Rip", &ThreadContext->Rip,
#endif
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtImpersonateThread
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtImpersonateThread,
  _In_ HANDLE ServerThreadHandle,
  _In_ HANDLE ClientThreadHandle,
  _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtImpersonateThread)(AvmpHookFunction_NtImpersonateThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ServerThreadHandle,
    ClientThreadHandle,
    SecurityQos);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ServerThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ServerThreadHandle, &ServerThreadHandleToTid);

  HANDLE ClientThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ClientThreadHandle, &ClientThreadHandleToTid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtImpersonateThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ServerThreadHandle", ServerThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ServerThreadHandleToTid", ServerThreadHandleToTid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ClientThreadHandle", ClientThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ClientThreadHandleToTid", ClientThreadHandleToTid,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueueApcThread
//////////////////////////////////////////////////////////////////////////

typedef VOID (*PPS_APC_ROUTINE)(
  _In_opt_ PVOID ApcArgument1,
  _In_opt_ PVOID ApcArgument2,
  _In_opt_ PVOID ApcArgument3
  );

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtQueueApcThread,
  _In_ HANDLE ThreadHandle,
  _In_ PPS_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcArgument1,
  _In_opt_ PVOID ApcArgument2,
  _In_opt_ PVOID ApcArgument3
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueueApcThread)(AvmpHookFunction_NtQueueApcThread.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    ApcRoutine,
    ApcArgument1,
    ApcArgument2,
    ApcArgument3);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  HANDLE ProcessIdFromThreadHandle = 0;
  AvmHookGetProcessIdFromThreadHandle(ThreadHandle, &ProcessIdFromThreadHandle);

  if (ProcessIdFromThreadHandle != PsGetCurrentProcessId() && ProcessIdFromThreadHandle != 0)
  {
    AvmDbgPrint(
      "[INJECTION] Queuing APC from PID: %u to PID: %u\n",
      PsGetCurrentProcessId(),
      ProcessIdFromThreadHandle);

    AvmHookAddWatchedProcessId(ProcessIdFromThreadHandle, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueueApcThread,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcRoutine", ApcRoutine,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcArgument1", ApcArgument1,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcArgument2", ApcArgument2,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcArgument3", ApcArgument3,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtQueueApcThreadEx
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Process",
NTSTATUS,
NtQueueApcThreadEx,
  _In_ HANDLE ThreadHandle,
  _In_opt_ HANDLE UserApcReserveHandle,
  _In_ PPS_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcArgument1,
  _In_opt_ PVOID ApcArgument2,
  _In_opt_ PVOID ApcArgument3
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtQueueApcThreadEx)(AvmpHookFunction_NtQueueApcThreadEx.Function.SSDTEntry->OriginalRoutineAddress))(
    ThreadHandle,
    UserApcReserveHandle,
    ApcRoutine,
    ApcArgument1,
    ApcArgument2,
    ApcArgument3);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE ThreadHandleToTid = 0;
  AvmHookGetThreadIdFromThreadHandle(ThreadHandle, &ThreadHandleToTid);

  HANDLE ProcessIdFromThreadHandle = 0;
  AvmHookGetProcessIdFromThreadHandle(ThreadHandle, &ProcessIdFromThreadHandle);

  if (ProcessIdFromThreadHandle != PsGetCurrentProcessId() && ProcessIdFromThreadHandle != 0)
  {
    AvmDbgPrint(
      "[INJECTION] Queuing APC from PID: %u to PID: %u\n",
      PsGetCurrentProcessId(),
      ProcessIdFromThreadHandle);

    AvmHookAddWatchedProcessId(ProcessIdFromThreadHandle, TRUE);
  }

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtQueueApcThreadEx,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "ThreadHandle", ThreadHandle,
    AEVT_INTEGER, sizeof(HANDLE), "ThreadHandleToTid", ThreadHandleToTid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "UserApcReserveHandle", UserApcReserveHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcRoutine", ApcRoutine,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcArgument1", ApcArgument1,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcArgument2", ApcArgument2,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(PVOID), "ApcArgument3", ApcArgument3,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

#pragma endregion Process

#pragma region Synchronization

//////////////////////////////////////////////////////////////////////////
// NtCreateMutant
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtCreateMutant,
  _Out_ PHANDLE MutantHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ BOOLEAN InitialOwner
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateMutant)(AvmpHookFunction_NtCreateMutant.Function.SSDTEntry->OriginalRoutineAddress))(
    MutantHandle,
    DesiredAccess,
    ObjectAttributes,
    InitialOwner);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateMutant,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(HANDLE), "MutantHandle", MutantHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_MUTANT_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_BOOL, sizeof(BOOLEAN), "InitialOwner", InitialOwner,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtOpenMutant
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtOpenMutant,
  _Out_ PHANDLE MutantHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtOpenMutant)(AvmpHookFunction_NtOpenMutant.Function.SSDTEntry->OriginalRoutineAddress))(
    MutantHandle,
    DesiredAccess,
    ObjectAttributes);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtOpenMutant,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(HANDLE), "MutantHandle", MutantHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_MUTANT_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtCreateEvent
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtCreateEvent,
  _Out_ PHANDLE EventHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ EVENT_TYPE EventType,
  _In_ BOOLEAN InitialState
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateEvent)(AvmpHookFunction_NtCreateEvent.Function.SSDTEntry->OriginalRoutineAddress))(
    EventHandle,
    DesiredAccess,
    ObjectAttributes,
    EventType,
    InitialState);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateEvent,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(HANDLE), "EventHandle", EventHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_EVENT_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_ENUM, &AvmpHookEnum_EVENT_TYPE, "EventType", EventType,
    AEVT_BOOL, sizeof(BOOLEAN), "InitialState", InitialState,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtOpenEvent
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtOpenEvent,
  _Out_ PHANDLE EventHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtOpenEvent)(AvmpHookFunction_NtOpenEvent.Function.SSDTEntry->OriginalRoutineAddress))(
    EventHandle,
    DesiredAccess,
    ObjectAttributes);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtOpenEvent,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(HANDLE), "EventHandle", EventHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_EVENT_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtCreateSemaphore
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtCreateSemaphore,
  _Out_ PHANDLE SemaphoreHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ LONG InitialCount,
  _In_ LONG MaximumCount
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtCreateSemaphore)(AvmpHookFunction_NtCreateSemaphore.Function.SSDTEntry->OriginalRoutineAddress))(
    SemaphoreHandle,
    DesiredAccess,
    ObjectAttributes,
    InitialCount,
    MaximumCount);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtCreateSemaphore,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(HANDLE), "SemaphoreHandle", SemaphoreHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_SEMAPHORE_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_INTEGER, sizeof(LONG), "InitialCount", InitialCount,
    AEVT_INTEGER, sizeof(LONG), "MaximumCount", MaximumCount,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtOpenSemaphore
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtOpenSemaphore,
  _Out_ PHANDLE SemaphoreHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtOpenSemaphore)(AvmpHookFunction_NtOpenSemaphore.Function.SSDTEntry->OriginalRoutineAddress))(
    SemaphoreHandle,
    DesiredAccess,
    ObjectAttributes);

  AvmpReturnIfNotWatched(ReturnValue);

  UNICODE_STRING CapturedObjectName;
  ULONG CapturedObjectNameFlags;
  AvmpTryToFetchObjectName(&CapturedObjectName, ObjectAttributes, &CapturedObjectNameFlags);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtOpenSemaphore,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE, sizeof(HANDLE), "SemaphoreHandle", SemaphoreHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_SEMAPHORE_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_UNICODE_STRING | CapturedObjectNameFlags, CapturedObjectName.Length, "ObjectName", CapturedObjectName.Buffer,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtWaitForSingleObject
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtWaitForSingleObject,
  _In_ HANDLE Handle,
  _In_ BOOLEAN Alertable,
  _In_opt_ PLARGE_INTEGER Timeout
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtWaitForSingleObject)(AvmpHookFunction_NtWaitForSingleObject.Function.SSDTEntry->OriginalRoutineAddress))(
    Handle,
    Alertable,
    Timeout);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtWaitForSingleObject,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "Handle", Handle,
    AEVT_BOOL, sizeof(BOOLEAN), "Alertable", Alertable,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(LONGLONG), "Timeout", &Timeout->QuadPart,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtWaitForMultipleObjects
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtWaitForMultipleObjects,
  _In_ ULONG Count,
  _In_reads_(Count) HANDLE Handles[],
  _In_ WAIT_TYPE WaitType,
  _In_ BOOLEAN Alertable,
  _In_opt_ PLARGE_INTEGER Timeout
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtWaitForMultipleObjects)(AvmpHookFunction_NtWaitForMultipleObjects.Function.SSDTEntry->OriginalRoutineAddress))(
    Count,
    Handles,
    WaitType,
    Alertable,
    Timeout);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtWaitForMultipleObjects,
    ReturnValue,
    AEVT_INTEGER, sizeof(ULONG), "Count", Count,
    AEVT_BINARY, sizeof(HANDLE) * Count, "Handles", Handles,
    AEVT_ENUM, &AvmpHookEnum_WAIT_TYPE, "WaitType", WaitType,
    AEVT_BOOL, sizeof(BOOLEAN), "Alertable", Alertable,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(LONGLONG), "Timeout", &Timeout->QuadPart,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtDelayExecution
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Synchronization",
NTSTATUS,
NtDelayExecution,
  _In_ BOOLEAN Alertable,
  _In_ PLARGE_INTEGER DelayInterval
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtDelayExecution)(AvmpHookFunction_NtDelayExecution.Function.SSDTEntry->OriginalRoutineAddress))(
    Alertable,
    DelayInterval);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtDelayExecution,
    ReturnValue,
    AEVT_BOOL, sizeof(BOOLEAN), "Alertable", Alertable,
    AEVT_INTEGER | AEVT_HINT_PROBE, sizeof(LONGLONG), "DelayInterval", &DelayInterval->QuadPart,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

#pragma endregion Synchronization

#pragma region Objects

//////////////////////////////////////////////////////////////////////////
// NtDuplicateObject
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Objects",
NTSTATUS,
NtDuplicateObject,
  _In_ HANDLE SourceProcessHandle,
  _In_ HANDLE SourceHandle,
  _In_opt_ HANDLE TargetProcessHandle,
  _Out_opt_ PHANDLE TargetHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ ULONG HandleAttributes,
  _In_ ULONG Options
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtDuplicateObject)(AvmpHookFunction_NtDuplicateObject.Function.SSDTEntry->OriginalRoutineAddress))(
    SourceProcessHandle,
    SourceHandle,
    TargetProcessHandle,
    TargetHandle,
    DesiredAccess,
    HandleAttributes,
    Options);

  AvmpReturnIfNotWatched(ReturnValue);

  HANDLE SourceProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(SourceProcessHandle, &SourceProcessHandleToPid);

  HANDLE TargetProcessHandleToPid = 0;
  AvmHookGetProcessIdFromProcessHandle(TargetProcessHandle, &TargetProcessHandleToPid);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtDuplicateObject,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "SourceProcessHandle", SourceProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "SourceProcessHandleToPid", SourceProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "SourceHandle", SourceHandle,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "TargetProcessHandle", TargetProcessHandle,
    AEVT_INTEGER, sizeof(HANDLE), "TargetProcessHandleToPid", TargetProcessHandleToPid,
    AEVT_INTEGER | AEVT_HINT_POINTER | AEVT_HINT_PROBE , sizeof(HANDLE), "TargetHandle", TargetHandle,
    AEVT_ENUM | AEVT_HINT_FLAGS, &AvmpHookEnum_GENERIC_ACCESS_MASK, "DesiredAccess", DesiredAccess,
    AEVT_ENUM, &AvmpHookEnum_OBJ_ATTRIBUTES, "HandleAttributes", HandleAttributes,
    AEVT_ENUM, &AvmpHookEnum_DUPLICATE_OPTIONS, "Options", Options,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

//////////////////////////////////////////////////////////////////////////
// NtClose
//////////////////////////////////////////////////////////////////////////

AVM_FUNCTION_DEFINE("Objects",
NTSTATUS,
NtClose,
  _In_ HANDLE Handle
  )
{
  InterlockedIncrement(&AvmpHookActualFunctionCallCount);

  NTSTATUS ReturnValue = ((pfnNtClose)(AvmpHookFunction_NtClose.Function.SSDTEntry->OriginalRoutineAddress))(
    Handle);

  AvmpReturnIfNotWatched(ReturnValue);

  AvmQueueFunctionCallEvent(
    &AvmpHookFunction_NtClose,
    ReturnValue,
    AEVT_INTEGER | AEVT_HINT_POINTER, sizeof(HANDLE), "Handle", Handle,
    AEVT_VOID);

  InterlockedDecrement(&AvmpHookActualFunctionCallCount);
  return ReturnValue;
}

#pragma endregion Objects
