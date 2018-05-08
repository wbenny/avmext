using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Avm.Driver
{
    public class AvmEventFunctionCall : AvmEvent
    {
        public int FunctionId;
        public uint ReturnValue;

        public uint ProcessId;
        public uint ThreadId;

        public List<EventVariant> ParameterValues;

        public FunctionDescription Description;

        public class Parameter
        {
            public string ParameterName;
            public EnumDescription EnumDescription;
            public EventVariant Value;

            public string ToString(EventVariant parameter)
            {
                if (parameter.Hints.HasFlag(VariantHint.Enum))
                {
                    if (parameter.Hints.HasFlag(VariantHint.Flags))
                    {
                        return ToStringParameterFlags(parameter);
                    }
                    else
                    {
                        return ToStringParameterEnum(parameter);
                    }
                }
                else
                {
                    return ToStringParameterBasic(parameter);
                }

            }

            private string ToStringParameterEnum(EventVariant parameter)
            {
                var enumValue = (uint)(int)parameter.Object;
                string enumValuePretty = "";

                if (!EnumDescription.ItemMap.TryGetValue(enumValue, out enumValuePretty))
                {
                    enumValuePretty = string.Format("0x{0:X8}", enumValue);
                }

                return enumValuePretty;
            }

            private string ToStringParameterFlags(EventVariant parameter)
            {
                var enumValue = (uint)(int)parameter.Object;
                string enumValuePretty = "";

                foreach (var pair in EnumDescription.ItemMap.Reverse())
                {
                    if ((enumValue & pair.Key) != 0)
                    {
                        if (!string.IsNullOrEmpty(enumValuePretty))
                        {
                            enumValuePretty += " | ";
                        }

                        enumValuePretty += pair.Value;
                        enumValue &= ~pair.Key;
                    }
                }

                if (enumValue > 0)
                {
                    if (!string.IsNullOrEmpty(enumValuePretty))
                    {
                        enumValuePretty += " | ";
                    }

                    enumValuePretty += string.Format("0x{0:X8}", enumValue);
                }

                return enumValuePretty;
            }

            private string ToStringParameterBasic(EventVariant parameter)
            {
                return parameter.ToString();
            }
        }

        public class EnumDescription
        {
            public string Name;
            public int Id;
            public int Type;
            public int TypeSize;
            public Dictionary<uint, string> ItemMap;

            public static EnumDescription Parse(BinaryReader reader)
            {
                var result = new EnumDescription();
                result.Name = EventVariant.Parse(reader).String;
                result.Id = EventVariant.Parse(reader).Int32;
                result.Type = EventVariant.Parse(reader).Int32;
                result.TypeSize = EventVariant.Parse(reader).Int32;
                result.ItemMap = new Dictionary<uint, string>();

                var elementCount = EventVariant.Parse(reader).Int32;

                for (int i = 0; i < elementCount; i++)
                {
                    var name = EventVariant.Parse(reader).String;
                    var value = (uint)EventVariant.Parse(reader).Int32;

                    result.ItemMap[value] = name;
                }

                return result;
            }
        }

        public class FunctionDescription
        {
            public string FunctionName;
            public List<Parameter> FunctionParameters;

            public static FunctionDescription Parse(BinaryReader reader, int functionParameterCount)
            {
                var result = new FunctionDescription();
                result.FunctionName = EventVariant.Parse(reader).String;
                result.FunctionParameters = new List<Parameter>();

                for (int i = 0; i < (int)functionParameterCount; i++)
                {
                    var enumDescription = EventVariant.IsEnum(reader)
                        ? EnumDescription.Parse(reader)
                        : null;

                    result.FunctionParameters.Add(new Parameter
                    {
                        ParameterName = EventVariant.Parse(reader).String,
                        EnumDescription = enumDescription
                    });
                }

                return result;
            }
        }

        internal static AvmEventFunctionCall Parse(BinaryReader reader)
        {
            var result = new AvmEventFunctionCall();

            result.FunctionId = reader.ReadInt32();
            var functionParameterCount = reader.ReadInt32();
            var functionDescription = reader.ReadInt32();
            result.ReturnValue = reader.ReadUInt32();

            result.ProcessId = reader.ReadUInt32();
            result.ThreadId = reader.ReadUInt32();

            if (functionDescription > 0)
            {
                result.Description = FunctionDescription.Parse(reader, functionParameterCount);
            }

            result.ParameterValues = new List<EventVariant>();
            for (int i = 0; i < functionParameterCount; i++)
            {
                result.ParameterValues.Add(EventVariant.Parse(reader));
            }

            return result;
        }
    }
}
