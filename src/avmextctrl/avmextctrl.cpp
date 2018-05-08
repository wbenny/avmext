// #include "avmextctrl.h"
// 
// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <inttypes.h>
// 
// #include <string>
// #include <map>
// #include <string>
// #include <tuple>
// #include <vector>
// #include <cassert>
// #include <unordered_map>
// 
// HANDLE AvmDeviceHandle = INVALID_HANDLE_VALUE;
// 
// BOOL
// AvmInitialize(
//   VOID
//   )
// {
//   AvmDeviceHandle = CreateFile(
//     TEXT("\\\\.\\AvmExt"),
//     GENERIC_WRITE | GENERIC_READ,
//     0,
//     NULL,
//     OPEN_EXISTING,
//     FILE_ATTRIBUTE_NORMAL,
//     NULL);
// 
//   return AvmDeviceHandle != INVALID_HANDLE_VALUE;
// }
// 
// VOID
// AvmDestroy(
//   VOID
//   )
// {
//   if (AvmDeviceHandle != INVALID_HANDLE_VALUE)
//   {
//     CloseHandle(AvmDeviceHandle);
//   }
// }
// 
// BOOL
// AvmHookEnable(
//   VOID
//   )
// {
//   DWORD BytesReturned;
// 
//   DeviceIoControl(
//     AvmDeviceHandle,
//     IOCTL_AVM_HOOK_ENABLE,
//     NULL,
//     0,
//     NULL,
//     0,
//     &BytesReturned,
//     NULL);
// 
//   return TRUE;
// }
// 
// BOOL
// AvmHookDisable(
//   VOID
//   )
// {
//   DWORD BytesReturned;
// 
//   DeviceIoControl(
//     AvmDeviceHandle,
//     IOCTL_AVM_HOOK_DISABLE,
//     NULL,
//     0,
//     NULL,
//     0,
//     &BytesReturned,
//     NULL);
// 
//   return TRUE;
// }
// 
// VOID
// AvmPrintHelp(
//   VOID
//   )
// {
//   printf("\n");
// }
// 
// 
// template <
//   typename T
// >
// PVOID
// AvmEventRead(
//   PVOID& EventData,
//   T& Data
//   )
// {
//   PAVM_EVENT_VARIANT EventVariant = (PAVM_EVENT_VARIANT)EventData;
// 
//   assert(EventVariant->Size == sizeof(T));
// 
//   memcpy(&Data, EventVariant->Buffer, EventVariant->Size);
//   EventData = (PCHAR)EventData + sizeof(AVM_EVENT_VARIANT) + EventVariant->Size;
// 
//   return EventData;
// }
// 
// template <
//   typename T
// >
// PVOID
// AvmEventRead(
//   PVOID& EventData,
//   T* Data
//   )
// {
//   PAVM_EVENT_VARIANT EventVariant = (PAVM_EVENT_VARIANT)EventData;
// 
//   memcpy(Data, EventVariant->Buffer, EventVariant->Size);
//   EventData = (PCHAR)EventData + sizeof(AVM_EVENT_VARIANT) + EventVariant->Size;
// 
//   return EventData;
// }
// 
// PVOID
// AvmEventRead(
//   PVOID& EventData,
//   std::string& Data
//   )
// {
//   PAVM_EVENT_VARIANT EventVariant = (PAVM_EVENT_VARIANT)EventData;
// 
//   Data.resize(EventVariant->Size);
// 
//   memcpy(&Data[0], EventVariant->Buffer, EventVariant->Size);
//   EventData = (PCHAR)EventData + sizeof(AVM_EVENT_VARIANT) + EventVariant->Size;
// 
//   return EventData;
// }
// 
// std::map<int, std::string> FunctionNameMap;
// std::map<std::tuple<int, int>, std::string> FunctionParameterMap;
// std::map<std::string, std::map<int, std::string>> EnumMap;
// std::map<std::tuple<int, int>, std::string> FunctionEnumMap;
// 
// VOID
// AvmPrintEventFunctionCall(
//   PAVM_EVENT_FUNCTION_CALL EventData
//   )
// {
//   PVOID EventPosition = (PVOID)((PBYTE)EventData + sizeof(AVM_EVENT_FUNCTION_CALL));
// 
//   //
//   // We should receive function description only once.
//   //
//   assert(EventData->FunctionDescription ? (
//     FunctionNameMap.find(EventData->FunctionId) == FunctionNameMap.end() &&
//     FunctionParameterMap.find(std::make_tuple((int)EventData->FunctionId, (int)0)) == FunctionParameterMap.end()) : 1);
// 
//   if (EventData->FunctionDescription)
//   {
//     CHAR FunctionNameValue[64] = { 0 };
// 
//     PAVM_EVENT_VARIANT FunctionName = (PAVM_EVENT_VARIANT)EventPosition;
//     memcpy(FunctionNameValue, FunctionName->Buffer, FunctionName->Size);
//     FunctionNameMap[EventData->FunctionId] = FunctionNameValue;
// 
//     EventPosition = (PVOID)((PBYTE)EventPosition + sizeof(AVM_EVENT_VARIANT) + FunctionName->Size);
// 
//     for (DWORD Index = 0; Index < EventData->FunctionParameterCount; Index++)
//     {
//       CHAR ParameterNameValue[64] = { 0 };
//       std::string LastEnumName;
// 
//       PAVM_EVENT_VARIANT ParameterName = (PAVM_EVENT_VARIANT)EventPosition;
//       PAVM_EVENT_VARIANT ParameterName2 = (PAVM_EVENT_VARIANT)EventPosition;
//       if ((ParameterName->Type & AEVT_TYPE_MASK) == AEVT_ENUM)
//       {
//         EventPosition = (PVOID)((PBYTE)EventPosition + sizeof(AVM_EVENT_VARIANT) /* + ParameterName->Size */);
// 
//         std::string EnumName;
//         AvmEventRead(EventPosition, EnumName);
// 
//         uint32_t EnumId;
//         AvmEventRead(EventPosition, EnumId);
// 
//         uint32_t EnumType;
//         AvmEventRead(EventPosition, EnumType);
// 
//         uint32_t EnumTypeSize;
//         AvmEventRead(EventPosition, EnumTypeSize);
// 
//         uint32_t EnumElementCount;
//         AvmEventRead(EventPosition, EnumElementCount);
// 
//         std::map<int, std::string> EnumValues;
// 
//         for (DWORD EnumIndex = 0; EnumIndex < EnumElementCount; EnumIndex++)
//         {
//           std::string EnumItemName;
//           AvmEventRead(EventPosition, EnumItemName);
// 
//           uint32_t EnumItemValue;
//           AvmEventRead(EventPosition, EnumItemValue);
// 
//           EnumValues[EnumItemValue] = EnumItemName;
//         }
// 
//         LastEnumName = EnumName;
//         EnumMap[LastEnumName] = EnumValues;
// 
//         ParameterName = (PAVM_EVENT_VARIANT)EventPosition;
//       }
// 
//       memcpy(ParameterNameValue, ParameterName->Buffer, ParameterName->Size);
//       FunctionParameterMap[std::make_tuple((int)EventData->FunctionId, (int)Index)] = ParameterNameValue;
// 
//       if ((ParameterName2->Type & AEVT_TYPE_MASK) == AEVT_ENUM)
//       {
//         FunctionEnumMap[std::make_tuple((int)EventData->FunctionId, (int)Index)] = LastEnumName;
//       }
// 
//       EventPosition = (PVOID)((PBYTE)EventPosition + sizeof(AVM_EVENT_VARIANT) + ParameterName->Size);
//     }
//   }
// 
//   printf("%s\n", FunctionNameMap[EventData->FunctionId].c_str());
//   printf("\tPID:         %p\n", EventData->ProcessId);
//   printf("\tTID:         %p\n", EventData->ThreadId);
//   printf("\tReturnValue: %s\n", EnumMap["NTSTATUS"][EventData->ReturnValue].c_str());
// 
//   PAVM_EVENT_VARIANT Parameter = (PAVM_EVENT_VARIANT)EventPosition;
// 
//   for (DWORD Index = 0; Index < EventData->FunctionParameterCount; Index++)
//   {
//     CHAR Buffer[1024] = { 0 };
//     WCHAR WBuffer[1024] = { 0 };
// 
//     auto enumIt = FunctionEnumMap.find(std::make_tuple((int)EventData->FunctionId, (int)Index));
//     if (enumIt == FunctionEnumMap.end())
//     {
//       printf("\tParameter[%s]: ", FunctionParameterMap[std::make_tuple((int)EventData->FunctionId, (int)Index)].c_str());
// 
//       switch (Parameter->Type & AEVT_TYPE_MASK)
//       {
//         case AEVT_BOOL:
//         case AEVT_INTEGER:
//         case AEVT_UNSIGNED_INTEGER:
//           switch (Parameter->Type & AEVT_HINT_MASK)
//           {
//             case AEVT_HINT_POINTER:
//               printf("%p", *(PVOID*)Parameter->Buffer);
//               break;
// 
//             case AEVT_HINT_HEX:
//               printf("%0.*x", Parameter->Size*2, *(PDWORD)Parameter->Buffer);
//               break;
// 
//             default:
//               printf("%i", *(PDWORD)Parameter->Buffer);
//               break;
//           }
//           break;
// 
//         case AEVT_FLOAT:
//           printf("%08x", *(PDWORD)Parameter->Buffer);
//           break;
// 
//         case AEVT_BINARY:
//           for (ULONG i = 0; i < min(Parameter->Size, 32); i++)
//           {
//             if (!(i % 16))
//             {
//               printf("\n");
//               printf("\t");
//             }
//             printf("%02x ", Parameter->Buffer[i]);
//           }
//           printf("\n");
//           break;
// 
//         case AEVT_STRING:
//           memcpy(Buffer, Parameter->Buffer, min(Parameter->Size, sizeof(Buffer)-1));
//           printf("%s", Buffer);
//           break;
// 
//         case AEVT_UNICODE_STRING:
//           memcpy(WBuffer, Parameter->Buffer, min(Parameter->Size, sizeof(WBuffer)-1));
//           printf("%S", WBuffer);
//           break;
// 
//         case AEVT_ENUM:
//           assert(0);
//           break;
// 
//         default:
//           break;
//       }
//     }
//     else
//     {
//       auto& enumName = enumIt->second;
//       auto& enumVals = EnumMap[enumName];
//       if ((Parameter->Type & AEVT_HINT_MASK) == AEVT_HINT_FLAGS)
//       {
//         std::string resultStr;
//         int val = *(int*)Parameter->Buffer;
//         for (auto& e : enumVals)
//         {
//           if (val & e.first)
//           {
//             if (resultStr.empty())
//             {
//               resultStr += e.second;
//             }
//             else
//             {
//               resultStr += " | " + e.second;
//             }
// 
//             val &= ~e.first;
//           }
//         }
// 
//         if (val)
//         {
//           if (resultStr.empty())
//           {
//             resultStr += std::to_string(val);
//           }
//           else
//           {
//             char res[64];
//             sprintf_s(res, "0x%08X", val);
// 
//             resultStr += " | ";
//             resultStr += res;
//           }
//         }
// 
//         printf("\tParameter[%s]: %s::%s", FunctionParameterMap[std::make_tuple((int)EventData->FunctionId, (int)Index)].c_str(),
//           enumName.c_str(), resultStr.c_str());
//       }
//       else
//       {
//         printf("\tParameter[%s]: %s::%s", FunctionParameterMap[std::make_tuple((int)EventData->FunctionId, (int)Index)].c_str(),
//           enumName.c_str(), enumVals[*(int*)Parameter->Buffer].c_str());
//       }
//     }
// 
//     printf("\n");
// 
//     Parameter = (PAVM_EVENT_VARIANT)((PBYTE)Parameter + sizeof(AVM_EVENT_VARIANT) + Parameter->Size);
//   }
// }
// 
// VOID
// AvmPrintEventProcess(
//   PAVM_EVENT_PROCESS EventData
//   )
// {
//   printf("Process %s\n", EventData->Created ? "creation" : "exit");
//   printf("\tPID:         %p\n", EventData->ProcessId);
//   printf("\tPPID:        %p\n", EventData->ParentProcessId);
// 
//   if (EventData->Created)
//   {
//     WCHAR Buffer[1024] = { 0 };
//     PAVM_EVENT_VARIANT ImageFileNameBuffer = (PAVM_EVENT_VARIANT)((PUCHAR)EventData + sizeof(AVM_EVENT_PROCESS));
// 
//     memcpy(Buffer, ImageFileNameBuffer->Buffer, ImageFileNameBuffer->Size);
// 
//     printf("\tFileName:    '%S'\n", Buffer);
//   }
// }
// 
// VOID
// AvmPrintEventThread(
//   PAVM_EVENT_THREAD EventData
//   )
// {
//   printf("Thread %s\n", EventData->Created ? "creation" : "exit");
//   printf("\tPID:         %p\n", EventData->ProcessId);
//   printf("\tTID:         %p\n", EventData->ThreadId);
// }
// 
// 
// VOID
// AvmPrintEventLoadImage(
//   PAVM_EVENT_LOAD_IMAGE EventData
//   )
// {
//   WCHAR Buffer[1024] = { 0 };
//   PAVM_EVENT_VARIANT ImageFileNameBuffer = &EventData->ImageFileName;
//   memcpy(Buffer, ImageFileNameBuffer->Buffer, ImageFileNameBuffer->Size);
// 
//   printf("Image '%S'\n", Buffer);
//   printf("\tPID:         %p\n", EventData->ProcessId);
//   printf("\tImageBase:   %p\n", EventData->ImageBase);
//   printf("\tImageSize:   %" PRIu64 "\n", EventData->ImageSize);
// }
// 
// 
// VOID
// AvmPrintEvent(
//   PAVM_EVENT Event
//   )
// {
//   //printf("SequenceId: %u\n", Event->SequenceId);
// 
//   PVOID EventData = (PBYTE)Event + sizeof(AVM_EVENT);
// 
//   switch (Event->Type)
//   {
//     case AET_FUNCTION_CALL:
//       AvmPrintEventFunctionCall((PAVM_EVENT_FUNCTION_CALL)EventData);
//       break;
// 
//     case AET_PROCESS:
//       AvmPrintEventProcess((PAVM_EVENT_PROCESS)EventData);
//       break;
// 
//     case AET_THREAD:
//       AvmPrintEventThread((PAVM_EVENT_THREAD)EventData);
//       break;
// 
//     case AET_LOAD_IMAGE:
//       AvmPrintEventLoadImage((PAVM_EVENT_LOAD_IMAGE)EventData);
//       break;
// 
//     default:
//       break;
//   }
// 
// //   printf("\n");
// }
// 
// int
// main2(
//   int Argc,
//   char** Argv
//   )
// {
//   if (Argc == 1)
//   {
//     AvmPrintHelp();
//     exit(0);
//   }
// 
//   if (!AvmInitialize())
//   {
//     printf("Cannot initialize AVM!\n");
//     exit(-1);
//   }
// 
//   FILE* fout = fopen("out.dat", "wb+");
// 
//   int CurrentArgc = 0;
//   BOOL DoEnable         = FALSE;
//   BOOL DoDisable        = FALSE;
//   PBYTE Buffer = (PBYTE)malloc(1024 * 1024 * 100);
//   while (1)
//   {
//     DWORD BytesRead = 0;
//     (void)ReadFile(AvmDeviceHandle, Buffer, 1024 * 1024 * 100, &BytesRead, NULL);
//     if (BytesRead == 0) {
//       printf("!!!! BytesRead == 0\n");
//       Sleep(1000);
//     }
//     fwrite(Buffer, 1, BytesRead, fout);
//     DWORD Position = 0;
//     while (Position < BytesRead)
//     {
//       PAVM_EVENT Event = (PAVM_EVENT)&Buffer[Position];
//       AvmPrintEvent(Event);
//       Position += Event->Size;
//     }
//   }
//   free(Buffer);
//   fclose(fout);
// 
//   while (++CurrentArgc < Argc)
//   {
//     if (strcmp(Argv[CurrentArgc], "--enable") == 0)
//     {
//       DoEnable = TRUE;
//     }
//     else if (strcmp(Argv[CurrentArgc], "--disable") == 0)
//     {
//       DoDisable = TRUE;
//     }
//     else
//     {
//       printf("Invalid argument '%s'!\n", Argv[CurrentArgc]);
//       exit(-1);
//     }
//   }
// 
//   if (DoEnable)
//   {
//     printf("[+] Enabling...\n");
//     AvmHookEnable();
//   }
// 
//   if (DoDisable)
//   {
//     printf("[+] Disabling...\n");
//     AvmHookDisable();
//   }
// 
//   AvmDestroy();
// 
//   return 0;
// }
