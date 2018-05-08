#define _CRT_SECURE_NO_WARNINGS

#include "avmextctrl.h"

#include <string>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <cassert>
#include <unordered_map>
#include <windows.h>
#include <cinttypes>

#define dbg_printf printf

class event_parser
{
  public:
    void parse(AVM_EVENT* event)
    {
      switch (event->Type)
      {
        case AET_FUNCTION_CALL:
          parse_function_call((AVM_EVENT_FUNCTION_CALL*)event->EventData);
          break;

        case AET_PROCESS:
          parse_process((AVM_EVENT_PROCESS*)event->EventData);
          break;

        case AET_THREAD:
          parse_thread((AVM_EVENT_THREAD*)event->EventData);
          break;

        case AET_LOAD_IMAGE:
          parse_load_image((AVM_EVENT_LOAD_IMAGE*)event->EventData);
          break;
      }
    }

    template <
      typename T
    >
    static
    PVOID
    parse_variant(
        PVOID& EventData,
        T& Data
      )
    {
      PAVM_EVENT_VARIANT EventVariant = (PAVM_EVENT_VARIANT)EventData;

      assert(EventVariant->Size == sizeof(T));

      memcpy(&Data, EventVariant->Buffer, EventVariant->Size);
      EventData = (PCHAR)EventData + sizeof(AVM_EVENT_VARIANT) + EventVariant->Size;

      return EventData;
    }

    template <
      typename T
    >
    static
    PVOID
    parse_variant(
        PVOID& EventData,
        T* Data
      )
    {
      PAVM_EVENT_VARIANT EventVariant = (PAVM_EVENT_VARIANT)EventData;

      memcpy(Data, EventVariant->Buffer, EventVariant->Size);
      EventData = (PCHAR)EventData + sizeof(AVM_EVENT_VARIANT) + EventVariant->Size;

      return EventData;
    }

    static
    PVOID
    parse_variant(
        PVOID& EventData,
        std::string& Data
      )
    {
      PAVM_EVENT_VARIANT EventVariant = (PAVM_EVENT_VARIANT)EventData;

      Data.resize(EventVariant->Size);

      memcpy(&Data[0], EventVariant->Buffer, EventVariant->Size);
      EventData = (PCHAR)EventData + sizeof(AVM_EVENT_VARIANT) + EventVariant->Size;

      return EventData;
    }

  private:
    using function_id_parameter_id_pair = std::tuple<
      uint32_t, // ID of the function.
      uint32_t  // Index of the parameter.
    >;

    using enum_value_to_name_map_t = std::map<
      uint32_t,      // Value of the enum element.
      std::string    // Name of the enum element.
    >;

    using enum_id_to_values_map_t = std::unordered_map<
      uint32_t,    // ID of the enum.
      enum_value_to_name_map_t // Values in the enum.
    >;

    using enum_id_to_name_map_t = std::unordered_map<
      uint32_t,    // ID of the enum.
      std::string  // Name of the enum.
    >;

    using function_to_name_map_t = std::unordered_map<
      uint32_t,       // ID of the function.
      std::string     // Name of the function.
    >;

    using function_to_parameter_map_t = std::map<
      function_id_parameter_id_pair,   // Pair of function ID and parameter index.
      std::string     // Name of the parameter.
    >;

    function_to_name_map_t _function_to_name_map;
    function_to_parameter_map_t _function_to_parameter_map;
    enum_id_to_values_map_t _enum_to_values_map;
    enum_id_to_name_map_t _enum_id_to_name_map;

    enum_value_to_name_map_t _ntstatus;

    std::string ntstatus_pretty(uint32_t status) const
    {
      auto it = _ntstatus.find(status);

      if (it != _ntstatus.end())
      {
        return it->second;
      }

      char hexstatus[32];
      sprintf_s(hexstatus, "0x%08X", status);
      return hexstatus;
    }

    PVOID parse_function_description(AVM_EVENT_FUNCTION_CALL* event_data)
    {
      PVOID EventPosition = (PVOID)((PBYTE)event_data + sizeof(AVM_EVENT_FUNCTION_CALL));

      CHAR FunctionNameValue[64] = { 0 };

      PAVM_EVENT_VARIANT FunctionName = (PAVM_EVENT_VARIANT)EventPosition;
      memcpy(FunctionNameValue, FunctionName->Buffer, FunctionName->Size);
      _function_to_name_map[event_data->FunctionId] = FunctionNameValue;

      EventPosition = (PVOID)((PBYTE)EventPosition + sizeof(AVM_EVENT_VARIANT) + FunctionName->Size);

      for (DWORD Index = 0; Index < event_data->FunctionParameterCount; Index++)
      {
        CHAR ParameterNameValue[64] = { 0 };

        PAVM_EVENT_VARIANT ParameterName = (PAVM_EVENT_VARIANT)EventPosition;
        PAVM_EVENT_VARIANT ParameterName2 = (PAVM_EVENT_VARIANT)EventPosition;
        if ((ParameterName->Type & AEVT_TYPE_MASK) == AEVT_ENUM)
        {
          EventPosition = (PVOID)((PBYTE)EventPosition + sizeof(AVM_EVENT_VARIANT));

          std::string EnumName;
          parse_variant(EventPosition, EnumName);

          uint32_t EnumId;
          parse_variant(EventPosition, EnumId);

          uint32_t EnumType;
          parse_variant(EventPosition, EnumType);

          uint32_t EnumTypeSize;
          parse_variant(EventPosition, EnumTypeSize);

          uint32_t EnumElementCount;
          parse_variant(EventPosition, EnumElementCount);

          enum_value_to_name_map_t EnumValues;

          for (DWORD EnumIndex = 0; EnumIndex < EnumElementCount; EnumIndex++)
          {
            std::string EnumItemName;
            parse_variant(EventPosition, EnumItemName);

            uint32_t EnumItemValue;
            parse_variant(EventPosition, EnumItemValue);

            EnumValues[EnumItemValue] = EnumItemName;
          }

          _enum_to_values_map[EnumId] = EnumValues;
          _enum_id_to_name_map[EnumId] = EnumName;

          if (EnumName == "NTSTATUS")
          {
            _ntstatus = EnumValues;
          }

          ParameterName = (PAVM_EVENT_VARIANT)EventPosition;
        }

        memcpy(ParameterNameValue, ParameterName->Buffer, ParameterName->Size);
        _function_to_parameter_map[std::make_tuple(event_data->FunctionId, Index)] = ParameterNameValue;

        EventPosition = (PVOID)((PBYTE)EventPosition + sizeof(AVM_EVENT_VARIANT) + ParameterName->Size);
      }

      return EventPosition;
    }

    void print_binary_blob(void* buffer, uint32_t size, uint32_t indent, uint32_t max_elements_in_line)
    {
      uint8_t* byte_buffer = reinterpret_cast<uint8_t*>(buffer);
      uint32_t size_rounded_up = ((size + max_elements_in_line - 1) / max_elements_in_line) * max_elements_in_line;

      for (uint32_t position = 0; position < size_rounded_up; position += 1)
      {
        bool is_begin_of_row = !(position % max_elements_in_line);
        bool is_end_of_row = !((position + 1) % max_elements_in_line);

        if (is_begin_of_row)
        {
          dbg_printf("%*s", indent, " ");
        }

        if (position < size)
        {
          dbg_printf("%02x ", byte_buffer[position]);
        }
        else
        {
          dbg_printf("?? ");
        }

        if (is_end_of_row)
        {
          dbg_printf(" |  ");
          for (uint32_t line_begin_position = position - max_elements_in_line + 1; line_begin_position < position; line_begin_position++)
          {
            if (line_begin_position < size && isprint(byte_buffer[line_begin_position]))
            {
              dbg_printf("%c", byte_buffer[line_begin_position]);
            }
            else
            {
              dbg_printf(".");
            }
          }

          dbg_printf("\n");
        }
      }
    }

    void parse_function_call_parameter_basic(AVM_EVENT_FUNCTION_CALL* event_data, PAVM_EVENT_VARIANT Parameter, int parameter_id)
    {
      dbg_printf("\tParameter[%s]: ", _function_to_parameter_map[std::make_tuple(event_data->FunctionId, parameter_id)].c_str());

      if (Parameter->Type & AEVT_HINT_ERROR)
      {
        printf("[ERROR]");
        return;
      }

      switch (Parameter->Type & AEVT_TYPE_MASK)
      {
        case AEVT_BOOL:
          assert(Parameter->Size == 1);
          switch (*(uint8_t*)Parameter->Buffer)
          {
          case 0:
            dbg_printf("FALSE");
            break;

          case 1:
            dbg_printf("TRUE");
            break;

          default:
            dbg_printf("%i", *(int8_t*)Parameter->Buffer);
            break;
          }
          break;

        case AEVT_INTEGER:
        case AEVT_UNSIGNED_INTEGER:
          switch (Parameter->Type & AEVT_HINT_MASK)
          {
            case AEVT_HINT_POINTER:
              assert(Parameter->Size == sizeof(void*));
              dbg_printf("%p", *(void**)Parameter->Buffer);
              break;

            case AEVT_HINT_HEX:
              switch (Parameter->Size)
              {
                case 1: dbg_printf("0x%02"  PRIx8,  *(uint8_t *)Parameter->Buffer); break;
                case 2: dbg_printf("0x%04"  PRIx16, *(uint16_t*)Parameter->Buffer); break;
                case 4: dbg_printf("0x%08"  PRIx32, *(uint32_t*)Parameter->Buffer); break;
                case 8: dbg_printf("0x%016" PRIx64, *(uint64_t*)Parameter->Buffer); break;
                default: assert(0); break;
              }
              break;

            default:
              if (Parameter->Type == AEVT_INTEGER)
              {
                switch (Parameter->Size)
                {
                  case 1: dbg_printf("%" PRIi8,  *(int8_t *)Parameter->Buffer); break;
                  case 2: dbg_printf("%" PRIi16, *(int16_t*)Parameter->Buffer); break;
                  case 4: dbg_printf("%" PRIi32, *(int32_t*)Parameter->Buffer); break;
                  case 8: dbg_printf("%" PRIi64, *(int64_t*)Parameter->Buffer); break;
                  default: assert(0); break;
                }
              }
              else // AEVT_UNSIGNED_INTEGER
              {
                switch (Parameter->Size)
                {
                  case 1: dbg_printf("%" PRIu8,  *(uint8_t *)Parameter->Buffer); break;
                  case 2: dbg_printf("%" PRIu16, *(uint16_t*)Parameter->Buffer); break;
                  case 4: dbg_printf("%" PRIu32, *(uint32_t*)Parameter->Buffer); break;
                  case 8: dbg_printf("%" PRIu64, *(uint64_t*)Parameter->Buffer); break;
                  default: assert(0); break;
                }
              }
              break;
          }
          break;

        case AEVT_FLOAT:
          switch (Parameter->Size)
          {
            case 4: dbg_printf("%f", *(float*)Parameter->Buffer); break;
            case 8: dbg_printf("%f", *(double*)Parameter->Buffer); break;
            default: assert(0); break;
          }
          break;

        case AEVT_BINARY:
          dbg_printf("\n");
          print_binary_blob(Parameter->Buffer, min(Parameter->Size, 128), 4, 16);
          break;

        case AEVT_STRING:
          dbg_printf("%.*s", min(Parameter->Size, 1024), (char*)Parameter->Buffer);
          break;

        case AEVT_UNICODE_STRING:
          dbg_printf("%.*S", min(Parameter->Size / 2, 1024), (wchar_t*)Parameter->Buffer);
          break;

        case AEVT_ENUM:
          assert(0);
          break;

        default:
          break;
      }
    }

    void parse_function_call_parameter_flags(AVM_EVENT_FUNCTION_CALL* event_data, PAVM_EVENT_VARIANT Parameter, int parameter_id)
    {
      auto& enum_values = _enum_to_values_map[AEVT_GET_ENUM(Parameter->Type)];
      auto& enum_name = _enum_id_to_name_map[AEVT_GET_ENUM(Parameter->Type)];
      auto& parameter_name = _function_to_parameter_map[std::make_tuple(event_data->FunctionId, parameter_id)];

      uint32_t enum_value = *(uint32_t*)Parameter->Buffer;
      std::string enum_value_pretty;

      for (auto it = enum_values.rbegin(); it != enum_values.rend(); ++it)
      {
        auto& value = *it;

        if (enum_value & value.first)
        {
          if (enum_value_pretty.empty())
          {
            enum_value_pretty += value.second;
          }
          else
          {
            enum_value_pretty += " | " + value.second;
          }

          enum_value &= ~value.first;
        }
      }

      //
      // Remainder.
      //
      if (enum_value)
      {
        if (enum_value_pretty.empty())
        {
          enum_value_pretty += std::to_string(enum_value);
        }
        else
        {
          char res[64];
          sprintf_s(res, "0x%08X", enum_value);

          enum_value_pretty += " | ";
          enum_value_pretty += res;
        }
      }

      dbg_printf("\tParameter[%s]: (%s) %s",
        parameter_name.c_str(),
        enum_name.c_str(),
        enum_value_pretty.c_str());
    }

    void parse_function_call_parameter_enum(AVM_EVENT_FUNCTION_CALL* event_data, PAVM_EVENT_VARIANT Parameter, int parameter_id)
    {
      auto& enum_values = _enum_to_values_map[AEVT_GET_ENUM(Parameter->Type)];
      auto& enum_name = _enum_id_to_name_map[AEVT_GET_ENUM(Parameter->Type)];
      auto& parameter_name = _function_to_parameter_map[std::make_tuple(event_data->FunctionId, parameter_id)];

      uint32_t enum_value = *(uint32_t*)Parameter->Buffer;
      std::string enum_value_pretty = enum_values.find(enum_value) == enum_values.end()
        ? std::to_string(enum_value)
        : enum_values[enum_value];

      dbg_printf("\tParameter[%s]: (%s) %s",
        parameter_name.c_str(),
        enum_name.c_str(),
        enum_value_pretty.c_str());
    }

    void parse_function_call_parameters(AVM_EVENT_FUNCTION_CALL* event_data, void* EventPosition)
    {
      PAVM_EVENT_VARIANT Parameter = (PAVM_EVENT_VARIANT)EventPosition;

      for (DWORD Index = 0; Index < event_data->FunctionParameterCount; Index++)
      {
        if (AEVT_GET_ENUM(Parameter->Type) == 0)
        {
          parse_function_call_parameter_basic(event_data, Parameter, Index);
        }
        else if ((Parameter->Type & AEVT_HINT_MASK) == AEVT_HINT_FLAGS)
        {
          parse_function_call_parameter_flags(event_data, Parameter, Index);
        }
        else
        {
          parse_function_call_parameter_enum(event_data, Parameter, Index);
        }

        dbg_printf("\n");

        Parameter = (PAVM_EVENT_VARIANT)((PBYTE)Parameter + sizeof(AVM_EVENT_VARIANT) + Parameter->Size);
      }
    }

    void parse_function_call(AVM_EVENT_FUNCTION_CALL* event_data)
    {
      PVOID EventPosition = (PVOID)((PBYTE)event_data + sizeof(AVM_EVENT_FUNCTION_CALL));

      if (event_data->FunctionDescription)
      {
        EventPosition = parse_function_description(event_data);
      }

      dbg_printf("%s\n", _function_to_name_map[event_data->FunctionId].c_str());
      dbg_printf("\tPID:         %08u\n", (uint32_t)(uintptr_t)event_data->ProcessId);
      dbg_printf("\tTID:         %08u\n", (uint32_t)(uintptr_t)event_data->ThreadId);
      dbg_printf("\tReturnValue: %s\n", ntstatus_pretty(event_data->ReturnValue).c_str());
      parse_function_call_parameters(event_data, EventPosition);
    }

    void parse_process(AVM_EVENT_PROCESS* event_data)
    {
      dbg_printf("Process %s\n", event_data->Created ? "creation" : "exit");
      dbg_printf("\tPID:         %08u\n", (uint32_t)(uintptr_t)event_data->ProcessId);
      dbg_printf("\tPPID:        %08u\n", (uint32_t)(uintptr_t)event_data->ParentProcessId);

      if (event_data->Created)
      {
        WCHAR Buffer[1024] = { 0 };
        PAVM_EVENT_VARIANT ImageFileNameBuffer = (PAVM_EVENT_VARIANT)((PUCHAR)event_data + sizeof(AVM_EVENT_PROCESS));

        memcpy(Buffer, ImageFileNameBuffer->Buffer, ImageFileNameBuffer->Size);

        dbg_printf("\tFileName:    '%S'\n", Buffer);
      }
    }

    void parse_thread(AVM_EVENT_THREAD* event_data)
    {
      dbg_printf("Thread %s\n", event_data->Created ? "creation" : "exit");
      dbg_printf("\tPID:         %08u\n", (uint32_t)(uintptr_t)event_data->ProcessId);
      dbg_printf("\tTID:         %08u\n", (uint32_t)(uintptr_t)event_data->ThreadId);
    }

    void parse_load_image(AVM_EVENT_LOAD_IMAGE* event_data)
    {
      WCHAR Buffer[1024] = { 0 };
      PAVM_EVENT_VARIANT ImageFileNameBuffer = &event_data->ImageFileName;
      memcpy(Buffer, ImageFileNameBuffer->Buffer, ImageFileNameBuffer->Size);

      dbg_printf("Image '%S'\n", Buffer);
      dbg_printf("\tPID:         %p\n", event_data->ProcessId);
      dbg_printf("\tImageBase:   %p\n", event_data->ImageBase);
      dbg_printf("\tImageSize:   %" PRIu64 "\n", event_data->ImageSize);
    }

};

class device
{
  public:
    using handle_t = HANDLE;

    device()
    {
      _device_handle = CreateFile(
        TEXT("\\\\.\\AvmExt"),
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

      if (_device_handle != INVALID_HANDLE_VALUE)
      {
        _buffer = new uint8_t[100 * 1024 * 1024];
      }
    }

    ~device()
    {
      if (_device_handle != INVALID_HANDLE_VALUE)
      {
        CloseHandle(_device_handle);
      }

      if (_buffer)
      {
        delete[] _buffer;
      }
    }

    void enable_hook()
    {
      ioctl(IOCTL_AVM_HOOK_ENABLE);
    }

    void disable_hook()
    {
      ioctl(IOCTL_AVM_HOOK_DISABLE);
    }

    void add_watched_process_id(handle_t process_id)
    {
      ioctl(IOCTL_AVM_HOOK_ADD_WATCHED_PROCESS_ID, &process_id, sizeof(process_id));
    }

    void add_set_hook(uint32_t function_id)
    {
      ioctl(IOCTL_AVM_HOOK_SET, &function_id, sizeof(function_id));
    }

    std::vector<std::tuple<std::string, std::string, uint32_t>> hookdef;

    void add_get_hook_list()
    {
      uint32_t length = 0;
      ioctl(IOCTL_AVM_HOOK_GET_FUNCTION_DEFINITION_LIST_SIZE, NULL, 0, &length, sizeof(length));

      void* buff = malloc(length);
      ioctl(IOCTL_AVM_HOOK_GET_FUNCTION_DEFINITION_LIST, NULL, 0, buff, length);

      uint32_t function_count;
      event_parser::parse_variant(buff, function_count);

      while (function_count-- > 0)
      {
        std::string category_name;
        event_parser::parse_variant(buff, category_name);

        std::string function_name;
        event_parser::parse_variant(buff, function_name);

        uint32_t function_id;
        event_parser::parse_variant(buff, function_id);

        printf("[*] Got '%s' with id: %u (category: '%s')\n", function_name.c_str(), function_id, category_name.c_str());

        if (category_name != "Special")
          hookdef.push_back(std::make_tuple(category_name, function_name, function_id));
      }
    }

    void read()
    {
      event_parser parser;
      FILE* fout = fopen("out.dat", "wb+");
      uint64_t total_bytes = 0;

      for (;;)
      {
        DWORD bytes_read;
        ReadFile(_device_handle, _buffer, 1024 * 1024 * 100, &bytes_read, NULL);
          fwrite(_buffer, 1, bytes_read, fout);
        total_bytes += bytes_read;
        DWORD position = 0;
        int event_count = 0;
        while (position < bytes_read)
        {
          PAVM_EVENT event = (PAVM_EVENT)&_buffer[position];
          parser.parse(event);
          position += event->Size;

          event_count += 1;
        }

        //printf(">>> Read %i events, total: %.3f MB\n", event_count, (double)total_bytes / 1024 / 1024);
      }

      fclose(fout);
    }

  private:
    void ioctl(uint32_t ioctl_code, void* input_buffer = nullptr, uint32_t input_buffer_size = 0, void* output_buffer = nullptr, uint32_t output_buffer_size = 0)
    {
      DWORD BytesReturned;

      DeviceIoControl(
        _device_handle,
        ioctl_code,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        &BytesReturned,
        NULL);
    }

    uint8_t* _buffer = NULL;
    HANDLE _device_handle = INVALID_HANDLE_VALUE;
};

int
main(
  int Argc,
  char** Argv
  )
{
  if (Argc < 2)
  {
    printf("Specify PID!\n");
    return -1;
  }

  device::handle_t pid = (device::handle_t)std::stoull(Argv[1]);

  device d;
  d.enable_hook();

  d.add_get_hook_list();

  //Sleep(2000);

  for (auto& hd : d.hookdef)
  {
    d.add_set_hook(std::get<2>(hd));
  }

  d.add_watched_process_id(pid);
  d.read();

  return 0;
}
