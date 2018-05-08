//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

//
// TODO: Add AEVT_HINT_FLAGS here.
//
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))

#define AVM_ENUM_DEFINE(EnumName, ...)                                          \
  AVM_HOOK_DEFINITION_ENUM_NAME_VALUE AvmpHookEnumNameValue_##EnumName[] = {    \
      __VA_ARGS__                                                               \
    { { 0, 0, NULL }, 0 }                                                       \
  };                                                                            \
                                                                                \
  __declspec(allocate(AVM_HOOK_DEFINITION_SECTION_NAME))                        \
  AVM_HOOK_DEFINITION AvmpHookEnum_##EnumName = {                               \
    .Id = __COUNTER__,                                                          \
    .Type = AHDT_ENUM,                                                          \
    .Name = RTL_CONSTANT_STRING(#EnumName),                                     \
    .Enum = {                                                                   \
      .EnumType = AEVT_INTEGER,                                                 \
      .EnumTypeSize = 4, /* Consider all enums to be LONGs */                   \
      .ItemCount = _countof(AvmpHookEnumNameValue_##EnumName),                  \
      .Items = AvmpHookEnumNameValue_##EnumName                                 \
    }                                                                           \
  }

#define AVM_ENUM_VALUE(Value)                                                   \
  { RTL_CONSTANT_STRING(#Value), (ULONG)Value }

#include "hookdef/hook_ntstatus.inl"

//////////////////////////////////////////////////////////////////////////
// Enum descriptions.
//////////////////////////////////////////////////////////////////////////

AVM_ENUM_DEFINE(
  OBJ_ATTRIBUTES,
    AVM_ENUM_VALUE(OBJ_INHERIT),
    AVM_ENUM_VALUE(OBJ_PERMANENT),
    AVM_ENUM_VALUE(OBJ_EXCLUSIVE),
    AVM_ENUM_VALUE(OBJ_CASE_INSENSITIVE),
    AVM_ENUM_VALUE(OBJ_OPENIF),
    AVM_ENUM_VALUE(OBJ_OPENLINK),
    AVM_ENUM_VALUE(OBJ_KERNEL_HANDLE),
    AVM_ENUM_VALUE(OBJ_FORCE_ACCESS_CHECK),
    AVM_ENUM_VALUE(OBJ_IGNORE_IMPERSONATED_DEVICEMAP),
    AVM_ENUM_VALUE(OBJ_DONT_REPARSE),
);

AVM_ENUM_DEFINE(
  GENERIC_ACCESS_MASK,
    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(GENERIC_ALL),
    AVM_ENUM_VALUE(GENERIC_EXECUTE),
    AVM_ENUM_VALUE(GENERIC_WRITE),
    AVM_ENUM_VALUE(GENERIC_READ),
);

AVM_ENUM_DEFINE(
  FILE_ACCESS_MASK,
    AVM_ENUM_VALUE(FILE_READ_DATA), /* FILE_LIST_DIRECTORY */
    AVM_ENUM_VALUE(FILE_WRITE_DATA), /* FILE_ADD_FILE */
    AVM_ENUM_VALUE(FILE_ADD_FILE),
    AVM_ENUM_VALUE(FILE_APPEND_DATA), /* FILE_ADD_SUBDIRECTORY, FILE_CREATE_PIPE_INSTANCE */
    AVM_ENUM_VALUE(FILE_READ_EA),
    AVM_ENUM_VALUE(FILE_WRITE_EA),
    AVM_ENUM_VALUE(FILE_EXECUTE), /* FILE_TRAVERSE */
    AVM_ENUM_VALUE(FILE_DELETE_CHILD),
    AVM_ENUM_VALUE(FILE_READ_ATTRIBUTES),
    AVM_ENUM_VALUE(FILE_WRITE_ATTRIBUTES),

    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(FILE_GENERIC_READ),
    AVM_ENUM_VALUE(FILE_GENERIC_WRITE),
    AVM_ENUM_VALUE(FILE_GENERIC_EXECUTE),
    AVM_ENUM_VALUE(FILE_ALL_ACCESS),

    AVM_ENUM_VALUE(GENERIC_ALL),
    AVM_ENUM_VALUE(GENERIC_EXECUTE),
    AVM_ENUM_VALUE(GENERIC_WRITE),
    AVM_ENUM_VALUE(GENERIC_READ),
);

#define PROCESS_TERMINATE 0x0001
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_SET_SESSIONID 0x0004
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_SET_QUOTA 0x0100
#define PROCESS_SET_INFORMATION 0x0200
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_SET_PORT 0x0800
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

AVM_ENUM_DEFINE(
  PROCESS_ACCESS_MASK,
    AVM_ENUM_VALUE(PROCESS_TERMINATE),
    AVM_ENUM_VALUE(PROCESS_CREATE_THREAD),
    AVM_ENUM_VALUE(PROCESS_SET_SESSIONID),
    AVM_ENUM_VALUE(PROCESS_VM_OPERATION),
    AVM_ENUM_VALUE(PROCESS_VM_READ),
    AVM_ENUM_VALUE(PROCESS_VM_WRITE),
    AVM_ENUM_VALUE(PROCESS_CREATE_PROCESS),
    AVM_ENUM_VALUE(PROCESS_SET_QUOTA),
    AVM_ENUM_VALUE(PROCESS_SET_INFORMATION),
    AVM_ENUM_VALUE(PROCESS_QUERY_INFORMATION),
    AVM_ENUM_VALUE(PROCESS_SET_PORT),
    AVM_ENUM_VALUE(PROCESS_SUSPEND_RESUME),
    AVM_ENUM_VALUE(PROCESS_QUERY_LIMITED_INFORMATION),

    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(PROCESS_ALL_ACCESS),

    AVM_ENUM_VALUE(GENERIC_ALL),
    AVM_ENUM_VALUE(GENERIC_EXECUTE),
    AVM_ENUM_VALUE(GENERIC_WRITE),
    AVM_ENUM_VALUE(GENERIC_READ),
);

//#define THREAD_TERMINATE                 0x0001
//#define THREAD_SUSPEND_RESUME            0x0002
//#define THREAD_ALERT                     0x0004
//#define THREAD_GET_CONTEXT               0x0008
//#define THREAD_SET_CONTEXT               0x0010
//#define THREAD_SET_INFORMATION           0x0020
#define THREAD_QUERY_INFORMATION         0x0040
#define THREAD_SET_THREAD_TOKEN          0x0080
#define THREAD_IMPERSONATE               0x0100
#define THREAD_DIRECT_IMPERSONATION      0x0200
//#define THREAD_SET_LIMITED_INFORMATION   0x0400
//#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
//#define THREAD_RESUME                    0x1000

AVM_ENUM_DEFINE(
  THREAD_ACCESS_MASK,
    AVM_ENUM_VALUE(THREAD_TERMINATE),
    AVM_ENUM_VALUE(THREAD_SUSPEND_RESUME),
    AVM_ENUM_VALUE(THREAD_ALERT),
    AVM_ENUM_VALUE(THREAD_GET_CONTEXT),
    AVM_ENUM_VALUE(THREAD_SET_CONTEXT),
    AVM_ENUM_VALUE(THREAD_SET_INFORMATION),
    AVM_ENUM_VALUE(THREAD_QUERY_INFORMATION),
    AVM_ENUM_VALUE(THREAD_SET_THREAD_TOKEN),
    AVM_ENUM_VALUE(THREAD_IMPERSONATE),
    AVM_ENUM_VALUE(THREAD_DIRECT_IMPERSONATION),
    AVM_ENUM_VALUE(THREAD_SET_LIMITED_INFORMATION),
    AVM_ENUM_VALUE(THREAD_QUERY_LIMITED_INFORMATION),
    AVM_ENUM_VALUE(THREAD_RESUME),

    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(THREAD_ALL_ACCESS),

    AVM_ENUM_VALUE(GENERIC_ALL),
    AVM_ENUM_VALUE(GENERIC_EXECUTE),
    AVM_ENUM_VALUE(GENERIC_WRITE),
    AVM_ENUM_VALUE(GENERIC_READ),
);

#define MUTANT_QUERY_STATE    0x0001
#define MUTANT_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE)

AVM_ENUM_DEFINE(
  MUTANT_ACCESS_MASK,
    AVM_ENUM_VALUE(MUTANT_QUERY_STATE),

    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(MUTANT_ALL_ACCESS), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE
);

AVM_ENUM_DEFINE(
  EVENT_ACCESS_MASK,
    AVM_ENUM_VALUE(EVENT_QUERY_STATE),
    AVM_ENUM_VALUE(EVENT_MODIFY_STATE),

    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(EVENT_ALL_ACCESS), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | EVENT_QUERY_STATE | EVENT_MODIFY_STATE
);

AVM_ENUM_DEFINE(
  SEMAPHORE_ACCESS_MASK,
    AVM_ENUM_VALUE(SEMAPHORE_QUERY_STATE),
    AVM_ENUM_VALUE(SEMAPHORE_MODIFY_STATE),

    AVM_ENUM_VALUE(DELETE),
    AVM_ENUM_VALUE(READ_CONTROL),
    AVM_ENUM_VALUE(WRITE_DAC),
    AVM_ENUM_VALUE(WRITE_OWNER),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_REQUIRED), // DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

    AVM_ENUM_VALUE(SYNCHRONIZE),
    AVM_ENUM_VALUE(STANDARD_RIGHTS_ALL), // STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    AVM_ENUM_VALUE(SEMAPHORE_ALL_ACCESS), // STANDARD_RIGHTS_REQUIRED | SEMAPHORE_QUERY_STATE | SEMAPHORE_MODIFY_STATE
);

AVM_ENUM_DEFINE(
  CREATE_DISPOSITION,
    AVM_ENUM_VALUE(FILE_SUPERSEDE),
    AVM_ENUM_VALUE(FILE_OPEN),
    AVM_ENUM_VALUE(FILE_CREATE),
    AVM_ENUM_VALUE(FILE_OPEN_IF),
    AVM_ENUM_VALUE(FILE_OVERWRITE),
    AVM_ENUM_VALUE(FILE_OVERWRITE_IF),
    AVM_ENUM_VALUE(FILE_MAXIMUM_DISPOSITION),
);

AVM_ENUM_DEFINE(
  CREATE_OPTIONS,
    AVM_ENUM_VALUE(FILE_DIRECTORY_FILE),
    AVM_ENUM_VALUE(FILE_WRITE_THROUGH),
    AVM_ENUM_VALUE(FILE_SEQUENTIAL_ONLY),
    AVM_ENUM_VALUE(FILE_NO_INTERMEDIATE_BUFFERING),
    AVM_ENUM_VALUE(FILE_SYNCHRONOUS_IO_ALERT),
    AVM_ENUM_VALUE(FILE_SYNCHRONOUS_IO_NONALERT),
    AVM_ENUM_VALUE(FILE_NON_DIRECTORY_FILE),
    AVM_ENUM_VALUE(FILE_CREATE_TREE_CONNECTION),
    AVM_ENUM_VALUE(FILE_COMPLETE_IF_OPLOCKED),
    AVM_ENUM_VALUE(FILE_NO_EA_KNOWLEDGE),
    AVM_ENUM_VALUE(FILE_OPEN_REMOTE_INSTANCE),
    AVM_ENUM_VALUE(FILE_RANDOM_ACCESS),
    AVM_ENUM_VALUE(FILE_DELETE_ON_CLOSE),
    AVM_ENUM_VALUE(FILE_OPEN_BY_FILE_ID),
    AVM_ENUM_VALUE(FILE_OPEN_FOR_BACKUP_INTENT),
    AVM_ENUM_VALUE(FILE_NO_COMPRESSION),
    AVM_ENUM_VALUE(FILE_OPEN_REQUIRING_OPLOCK),
    AVM_ENUM_VALUE(FILE_DISALLOW_EXCLUSIVE),
);

AVM_ENUM_DEFINE(
  FILE_ATTRIBUTES,
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_READONLY),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_HIDDEN),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_SYSTEM),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_DIRECTORY),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_ARCHIVE),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_DEVICE),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_NORMAL),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_TEMPORARY),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_SPARSE_FILE),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_REPARSE_POINT),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_COMPRESSED),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_OFFLINE),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_ENCRYPTED),
    AVM_ENUM_VALUE(FILE_ATTRIBUTE_VIRTUAL),
);

AVM_ENUM_DEFINE(
  SHARE_ACCESS,
    AVM_ENUM_VALUE(FILE_SHARE_READ),
    AVM_ENUM_VALUE(FILE_SHARE_WRITE),
    AVM_ENUM_VALUE(FILE_SHARE_DELETE),
);

AVM_ENUM_DEFINE(
  SECTION_INHERIT,
    AVM_ENUM_VALUE(ViewShare),
    AVM_ENUM_VALUE(ViewUnmap),
);

AVM_ENUM_DEFINE(
  KEY_VALUE_INFORMATION_CLASS,
    AVM_ENUM_VALUE(KeyValueBasicInformation),
    AVM_ENUM_VALUE(KeyValueFullInformation),
    AVM_ENUM_VALUE(KeyValuePartialInformation),
    AVM_ENUM_VALUE(KeyValueFullInformationAlign64),
    AVM_ENUM_VALUE(KeyValuePartialInformationAlign64),
    AVM_ENUM_VALUE(KeyValueLayerInformation),
);

AVM_ENUM_DEFINE(
  REG_TYPE,
    AVM_ENUM_VALUE(REG_NONE),
    AVM_ENUM_VALUE(REG_SZ),
    AVM_ENUM_VALUE(REG_EXPAND_SZ),
    AVM_ENUM_VALUE(REG_BINARY),
    AVM_ENUM_VALUE(REG_DWORD),
    AVM_ENUM_VALUE(REG_DWORD_LITTLE_ENDIAN),
    AVM_ENUM_VALUE(REG_DWORD_BIG_ENDIAN),
    AVM_ENUM_VALUE(REG_LINK),
    AVM_ENUM_VALUE(REG_MULTI_SZ),
    AVM_ENUM_VALUE(REG_RESOURCE_LIST),
    AVM_ENUM_VALUE(REG_FULL_RESOURCE_DESCRIPTOR),
    AVM_ENUM_VALUE(REG_RESOURCE_REQUIREMENTS_LIST),
    AVM_ENUM_VALUE(REG_QWORD),
);

AVM_ENUM_DEFINE(
  ALLOCATION_TYPE,
    AVM_ENUM_VALUE(MEM_COMMIT),
    AVM_ENUM_VALUE(MEM_RESERVE),
    AVM_ENUM_VALUE(MEM_DECOMMIT),
    AVM_ENUM_VALUE(MEM_RELEASE),
    AVM_ENUM_VALUE(MEM_FREE),
    AVM_ENUM_VALUE(MEM_PRIVATE),
    AVM_ENUM_VALUE(MEM_MAPPED),
    AVM_ENUM_VALUE(MEM_RESET),
    AVM_ENUM_VALUE(MEM_TOP_DOWN),
    AVM_ENUM_VALUE(MEM_RESET_UNDO),
    AVM_ENUM_VALUE(MEM_LARGE_PAGES),
);

AVM_ENUM_DEFINE(
  PAGE_PROTECT,
    AVM_ENUM_VALUE(PAGE_NOACCESS),
    AVM_ENUM_VALUE(PAGE_READONLY),
    AVM_ENUM_VALUE(PAGE_READWRITE),
    AVM_ENUM_VALUE(PAGE_WRITECOPY),
    AVM_ENUM_VALUE(PAGE_EXECUTE),
    AVM_ENUM_VALUE(PAGE_EXECUTE_READ),
    AVM_ENUM_VALUE(PAGE_EXECUTE_READWRITE),
    AVM_ENUM_VALUE(PAGE_EXECUTE_WRITECOPY),
    AVM_ENUM_VALUE(PAGE_GUARD),
    AVM_ENUM_VALUE(PAGE_NOCACHE),
    AVM_ENUM_VALUE(PAGE_WRITECOMBINE),
);

AVM_ENUM_DEFINE(
  FILE_INFORMATION_CLASS,
    AVM_ENUM_VALUE(FileDirectoryInformation),
    AVM_ENUM_VALUE(FileFullDirectoryInformation),
    AVM_ENUM_VALUE(FileBothDirectoryInformation),
    AVM_ENUM_VALUE(FileBasicInformation),
    AVM_ENUM_VALUE(FileStandardInformation),
    AVM_ENUM_VALUE(FileInternalInformation),
    AVM_ENUM_VALUE(FileEaInformation),
    AVM_ENUM_VALUE(FileAccessInformation),
    AVM_ENUM_VALUE(FileNameInformation),
    AVM_ENUM_VALUE(FileRenameInformation),
    AVM_ENUM_VALUE(FileLinkInformation),
    AVM_ENUM_VALUE(FileNamesInformation),
    AVM_ENUM_VALUE(FileDispositionInformation),
    AVM_ENUM_VALUE(FilePositionInformation),
    AVM_ENUM_VALUE(FileFullEaInformation),
    AVM_ENUM_VALUE(FileModeInformation),
    AVM_ENUM_VALUE(FileAlignmentInformation),
    AVM_ENUM_VALUE(FileAllInformation),
    AVM_ENUM_VALUE(FileAllocationInformation),
    AVM_ENUM_VALUE(FileEndOfFileInformation),
    AVM_ENUM_VALUE(FileAlternateNameInformation),
    AVM_ENUM_VALUE(FileStreamInformation),
    AVM_ENUM_VALUE(FilePipeInformation),
    AVM_ENUM_VALUE(FilePipeLocalInformation),
    AVM_ENUM_VALUE(FilePipeRemoteInformation),
    AVM_ENUM_VALUE(FileMailslotQueryInformation),
    AVM_ENUM_VALUE(FileMailslotSetInformation),
    AVM_ENUM_VALUE(FileCompressionInformation),
    AVM_ENUM_VALUE(FileObjectIdInformation),
    AVM_ENUM_VALUE(FileCompletionInformation),
    AVM_ENUM_VALUE(FileMoveClusterInformation),
    AVM_ENUM_VALUE(FileQuotaInformation),
    AVM_ENUM_VALUE(FileReparsePointInformation),
    AVM_ENUM_VALUE(FileNetworkOpenInformation),
    AVM_ENUM_VALUE(FileAttributeTagInformation),
    AVM_ENUM_VALUE(FileTrackingInformation),
    AVM_ENUM_VALUE(FileIdBothDirectoryInformation),
    AVM_ENUM_VALUE(FileIdFullDirectoryInformation),
    AVM_ENUM_VALUE(FileValidDataLengthInformation),
    AVM_ENUM_VALUE(FileShortNameInformation),
    AVM_ENUM_VALUE(FileIoCompletionNotificationInformation),
    AVM_ENUM_VALUE(FileIoStatusBlockRangeInformation),
    AVM_ENUM_VALUE(FileIoPriorityHintInformation),
    AVM_ENUM_VALUE(FileSfioReserveInformation),
    AVM_ENUM_VALUE(FileSfioVolumeInformation),
    AVM_ENUM_VALUE(FileHardLinkInformation),
    AVM_ENUM_VALUE(FileProcessIdsUsingFileInformation),
    AVM_ENUM_VALUE(FileNormalizedNameInformation),
    AVM_ENUM_VALUE(FileNetworkPhysicalNameInformation),
    AVM_ENUM_VALUE(FileIdGlobalTxDirectoryInformation),
    AVM_ENUM_VALUE(FileIsRemoteDeviceInformation),
    AVM_ENUM_VALUE(FileUnusedInformation),
    AVM_ENUM_VALUE(FileNumaNodeInformation),
    AVM_ENUM_VALUE(FileStandardLinkInformation),
    AVM_ENUM_VALUE(FileRemoteProtocolInformation),
    AVM_ENUM_VALUE(FileRenameInformationBypassAccessCheck),
    AVM_ENUM_VALUE(FileLinkInformationBypassAccessCheck),
    AVM_ENUM_VALUE(FileVolumeNameInformation),
    AVM_ENUM_VALUE(FileIdInformation),
    AVM_ENUM_VALUE(FileIdExtdDirectoryInformation),
    AVM_ENUM_VALUE(FileReplaceCompletionInformation),
    AVM_ENUM_VALUE(FileHardLinkFullIdInformation),
    AVM_ENUM_VALUE(FileIdExtdBothDirectoryInformation),
    AVM_ENUM_VALUE(FileDispositionInformationEx),
    AVM_ENUM_VALUE(FileRenameInformationEx),
    AVM_ENUM_VALUE(FileRenameInformationExBypassAccessCheck),
//     AVM_ENUM_VALUE(FileDesiredStorageClassInformation),
//     AVM_ENUM_VALUE(FileStatInformation),
);

AVM_ENUM_DEFINE(
  FS_INFORMATION_CLASS,
    AVM_ENUM_VALUE(FileFsVolumeInformation),
    AVM_ENUM_VALUE(FileFsLabelInformation),
    AVM_ENUM_VALUE(FileFsSizeInformation),
    AVM_ENUM_VALUE(FileFsDeviceInformation),
    AVM_ENUM_VALUE(FileFsAttributeInformation),
    AVM_ENUM_VALUE(FileFsControlInformation),
    AVM_ENUM_VALUE(FileFsFullSizeInformation),
    AVM_ENUM_VALUE(FileFsObjectIdInformation),
    AVM_ENUM_VALUE(FileFsDriverPathInformation),
    AVM_ENUM_VALUE(FileFsVolumeFlagsInformation),
    AVM_ENUM_VALUE(FileFsSectorSizeInformation),
    AVM_ENUM_VALUE(FileFsDataCopyInformation),
    AVM_ENUM_VALUE(FileFsMetadataSizeInformation),
);

enum
{
  ProcessResourceManagement = 35,
  ProcessConsoleHostProcess = 49,
  ProcessDefaultCpuSetsInformation = 66,
  ProcessAllowedCpuSetsInformation = 67,
  ProcessJobMemoryInformation = 69,
  ProcessIumChallengeResponse = 72,
  ProcessChildProcessInformation = 73,
  ProcessHighGraphicsPriorityInformation = 74,
  ProcessEnergyValues,
  ProcessActivityThrottleState = 77,
  ProcessActivityThrottlePolicy = 78,
  ProcessDisableSystemAllowedCpuSets = 80,
  ProcessWakeInformation = 81,
};

AVM_ENUM_DEFINE(
  PROCESSINFOCLASS,
    AVM_ENUM_VALUE(ProcessBasicInformation),
    AVM_ENUM_VALUE(ProcessQuotaLimits),
    AVM_ENUM_VALUE(ProcessIoCounters),
    AVM_ENUM_VALUE(ProcessVmCounters),
    AVM_ENUM_VALUE(ProcessTimes),
    AVM_ENUM_VALUE(ProcessBasePriority),
    AVM_ENUM_VALUE(ProcessRaisePriority),
    AVM_ENUM_VALUE(ProcessDebugPort),
    AVM_ENUM_VALUE(ProcessExceptionPort),
    AVM_ENUM_VALUE(ProcessAccessToken),
    AVM_ENUM_VALUE(ProcessLdtInformation),
    AVM_ENUM_VALUE(ProcessLdtSize),
    AVM_ENUM_VALUE(ProcessDefaultHardErrorMode),
    AVM_ENUM_VALUE(ProcessIoPortHandlers),
    AVM_ENUM_VALUE(ProcessPooledUsageAndLimits),
    AVM_ENUM_VALUE(ProcessWorkingSetWatch),
    AVM_ENUM_VALUE(ProcessUserModeIOPL),
    AVM_ENUM_VALUE(ProcessEnableAlignmentFaultFixup),
    AVM_ENUM_VALUE(ProcessPriorityClass),
    AVM_ENUM_VALUE(ProcessWx86Information),
    AVM_ENUM_VALUE(ProcessHandleCount),
    AVM_ENUM_VALUE(ProcessAffinityMask),
    AVM_ENUM_VALUE(ProcessPriorityBoost),
    AVM_ENUM_VALUE(ProcessDeviceMap),
    AVM_ENUM_VALUE(ProcessSessionInformation),
    AVM_ENUM_VALUE(ProcessForegroundInformation),
    AVM_ENUM_VALUE(ProcessWow64Information),
    AVM_ENUM_VALUE(ProcessImageFileName),
    AVM_ENUM_VALUE(ProcessLUIDDeviceMapsEnabled),
    AVM_ENUM_VALUE(ProcessBreakOnTermination),
    AVM_ENUM_VALUE(ProcessDebugObjectHandle),
    AVM_ENUM_VALUE(ProcessDebugFlags),
    AVM_ENUM_VALUE(ProcessHandleTracing),
    AVM_ENUM_VALUE(ProcessIoPriority),
    AVM_ENUM_VALUE(ProcessExecuteFlags),
    AVM_ENUM_VALUE(ProcessResourceManagement),
    AVM_ENUM_VALUE(ProcessCookie),
    AVM_ENUM_VALUE(ProcessImageInformation),
    AVM_ENUM_VALUE(ProcessCycleTime),
    AVM_ENUM_VALUE(ProcessPagePriority),
    AVM_ENUM_VALUE(ProcessInstrumentationCallback),
    AVM_ENUM_VALUE(ProcessThreadStackAllocation),
    AVM_ENUM_VALUE(ProcessWorkingSetWatchEx),
    AVM_ENUM_VALUE(ProcessImageFileNameWin32),
    AVM_ENUM_VALUE(ProcessImageFileMapping),
    AVM_ENUM_VALUE(ProcessAffinityUpdateMode),
    AVM_ENUM_VALUE(ProcessMemoryAllocationMode),
    AVM_ENUM_VALUE(ProcessGroupInformation),
    AVM_ENUM_VALUE(ProcessTokenVirtualizationEnabled),
    AVM_ENUM_VALUE(ProcessConsoleHostProcess),
    AVM_ENUM_VALUE(ProcessWindowInformation),
    AVM_ENUM_VALUE(ProcessHandleInformation),
    AVM_ENUM_VALUE(ProcessMitigationPolicy),
    AVM_ENUM_VALUE(ProcessDynamicFunctionTableInformation),
    AVM_ENUM_VALUE(ProcessHandleCheckingMode),
    AVM_ENUM_VALUE(ProcessKeepAliveCount),
    AVM_ENUM_VALUE(ProcessRevokeFileHandles),
    AVM_ENUM_VALUE(ProcessWorkingSetControl),
    AVM_ENUM_VALUE(ProcessHandleTable),
    AVM_ENUM_VALUE(ProcessCheckStackExtentsMode),
    AVM_ENUM_VALUE(ProcessCommandLineInformation),
    AVM_ENUM_VALUE(ProcessProtectionInformation),
    AVM_ENUM_VALUE(ProcessMemoryExhaustion),
    AVM_ENUM_VALUE(ProcessFaultInformation),
    AVM_ENUM_VALUE(ProcessTelemetryIdInformation),
    AVM_ENUM_VALUE(ProcessCommitReleaseInformation),
    AVM_ENUM_VALUE(ProcessDefaultCpuSetsInformation),
    AVM_ENUM_VALUE(ProcessAllowedCpuSetsInformation),
    AVM_ENUM_VALUE(ProcessSubsystemProcess),
    AVM_ENUM_VALUE(ProcessJobMemoryInformation),
    AVM_ENUM_VALUE(ProcessInPrivate),
    AVM_ENUM_VALUE(ProcessRaiseUMExceptionOnInvalidHandleClose),
    AVM_ENUM_VALUE(ProcessIumChallengeResponse),
    AVM_ENUM_VALUE(ProcessChildProcessInformation),
    AVM_ENUM_VALUE(ProcessHighGraphicsPriorityInformation),
//     AVM_ENUM_VALUE(ProcessSubsystemInformation),
    AVM_ENUM_VALUE(ProcessEnergyValues),
    AVM_ENUM_VALUE(ProcessActivityThrottleState),
    AVM_ENUM_VALUE(ProcessActivityThrottlePolicy),
//     AVM_ENUM_VALUE(ProcessWin32kSyscallFilterInformation),
    AVM_ENUM_VALUE(ProcessDisableSystemAllowedCpuSets),
    AVM_ENUM_VALUE(ProcessWakeInformation),
//     AVM_ENUM_VALUE(ProcessEnergyTrackingState),
);

enum
{
  ThreadEventPair = 8,
  ThreadHeterogeneousCpuPolicy = 36,
  ThreadContainerId = 37,
  ThreadNameInformation = 38,
  ThreadSelectedCpuSets = 39,
  ThreadSystemThreadInformation = 40,
  ThreadExplicitCaseSensitivity = 43,
  ThreadWorkOnBehalfTicket = 44,
  ThreadDbgkWerReportActive = 46,
  ThreadAttachContainer = 47,
};

AVM_ENUM_DEFINE(
  THREADINFOCLASS,
    AVM_ENUM_VALUE(ThreadBasicInformation),
    AVM_ENUM_VALUE(ThreadTimes),
    AVM_ENUM_VALUE(ThreadPriority),
    AVM_ENUM_VALUE(ThreadBasePriority),
    AVM_ENUM_VALUE(ThreadAffinityMask),
    AVM_ENUM_VALUE(ThreadImpersonationToken),
    AVM_ENUM_VALUE(ThreadDescriptorTableEntry),
    AVM_ENUM_VALUE(ThreadEnableAlignmentFaultFixup),
    AVM_ENUM_VALUE(ThreadEventPair),
    AVM_ENUM_VALUE(ThreadQuerySetWin32StartAddress),
    AVM_ENUM_VALUE(ThreadZeroTlsCell),
    AVM_ENUM_VALUE(ThreadPerformanceCount),
    AVM_ENUM_VALUE(ThreadAmILastThread),
    AVM_ENUM_VALUE(ThreadIdealProcessor),
    AVM_ENUM_VALUE(ThreadPriorityBoost),
    AVM_ENUM_VALUE(ThreadSetTlsArrayAddress),
    AVM_ENUM_VALUE(ThreadIsIoPending),
    AVM_ENUM_VALUE(ThreadHideFromDebugger),
    AVM_ENUM_VALUE(ThreadBreakOnTermination),
    AVM_ENUM_VALUE(ThreadSwitchLegacyState),
    AVM_ENUM_VALUE(ThreadIsTerminated),
    AVM_ENUM_VALUE(ThreadLastSystemCall),
    AVM_ENUM_VALUE(ThreadIoPriority),
    AVM_ENUM_VALUE(ThreadCycleTime),
    AVM_ENUM_VALUE(ThreadPagePriority),
    AVM_ENUM_VALUE(ThreadActualBasePriority),
    AVM_ENUM_VALUE(ThreadTebInformation),
    AVM_ENUM_VALUE(ThreadCSwitchMon),
    AVM_ENUM_VALUE(ThreadCSwitchPmu),
    AVM_ENUM_VALUE(ThreadWow64Context),
    AVM_ENUM_VALUE(ThreadGroupInformation),
    AVM_ENUM_VALUE(ThreadUmsInformation),
    AVM_ENUM_VALUE(ThreadCounterProfiling),
    AVM_ENUM_VALUE(ThreadIdealProcessorEx),
    AVM_ENUM_VALUE(ThreadCpuAccountingInformation),
    AVM_ENUM_VALUE(ThreadSuspendCount),
    AVM_ENUM_VALUE(ThreadHeterogeneousCpuPolicy),
    AVM_ENUM_VALUE(ThreadContainerId),
    AVM_ENUM_VALUE(ThreadNameInformation),
    AVM_ENUM_VALUE(ThreadSelectedCpuSets),
    AVM_ENUM_VALUE(ThreadSystemThreadInformation),
    AVM_ENUM_VALUE(ThreadActualGroupAffinity),
    AVM_ENUM_VALUE(ThreadDynamicCodePolicyInfo),
    AVM_ENUM_VALUE(ThreadExplicitCaseSensitivity),
    AVM_ENUM_VALUE(ThreadWorkOnBehalfTicket),
//     AVM_ENUM_VALUE(ThreadSubsystemInformation),
    AVM_ENUM_VALUE(ThreadDbgkWerReportActive),
    AVM_ENUM_VALUE(ThreadAttachContainer),
);

AVM_ENUM_DEFINE(
  DUPLICATE_OPTIONS,
    AVM_ENUM_VALUE(DUPLICATE_CLOSE_SOURCE),
    AVM_ENUM_VALUE(DUPLICATE_SAME_ACCESS),
    AVM_ENUM_VALUE(DUPLICATE_SAME_ATTRIBUTES),
);

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

AVM_ENUM_DEFINE(
  THREAD_CREATE,
    AVM_ENUM_VALUE(THREAD_CREATE_FLAGS_CREATE_SUSPENDED),
    AVM_ENUM_VALUE(THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH),
    AVM_ENUM_VALUE(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER),
    AVM_ENUM_VALUE(THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR),
    AVM_ENUM_VALUE(THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET),
    AVM_ENUM_VALUE(THREAD_CREATE_FLAGS_INITIAL_THREAD),
);

#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010

AVM_ENUM_DEFINE(
  PROCESS_CREATE,
    AVM_ENUM_VALUE(PROCESS_CREATE_FLAGS_BREAKAWAY),
    AVM_ENUM_VALUE(PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT),
    AVM_ENUM_VALUE(PROCESS_CREATE_FLAGS_INHERIT_HANDLES),
    AVM_ENUM_VALUE(PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE),
    AVM_ENUM_VALUE(PROCESS_CREATE_FLAGS_LARGE_PAGES),
);

AVM_ENUM_DEFINE(
  EVENT_TYPE,
    AVM_ENUM_VALUE(NotificationEvent),
    AVM_ENUM_VALUE(SynchronizationEvent),
);

AVM_ENUM_DEFINE(
  WAIT_TYPE,
    AVM_ENUM_VALUE(WaitAll),
    AVM_ENUM_VALUE(WaitAny),
    AVM_ENUM_VALUE(WaitNotification),
    AVM_ENUM_VALUE(WaitDequeue),
);
