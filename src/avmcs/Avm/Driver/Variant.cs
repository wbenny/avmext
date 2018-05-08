using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Avm.Driver
{
    public enum VariantType
    {
        Void = 0,
        Bool = 1,
        Integer = 2,
        UnsignedInteger = 3,
        Float = 4,
        Binary = 5,
        String = 6,
        UnicodeString = 7,
        Enum = 8,
    }

    [Flags]
    public enum VariantHint
    {
        Pointer = 1 << 4,
        Hex = 1 << 5,
        Flags = 1 << 6,
        Enum = 1 << 7,
        Probe = 1 << 8,
        Indirect = 1 << 9,
        IndirectProcess = 1 << 10,
        Error = 1 << 11,
    }

    public class EventVariant
    {
        public int RequestedSize;
        public int Size;
        public VariantType Type;
        public VariantHint Hints;
        public int EnumId;

        public object Object;

        public string String { get { return (string)Object; } }
        public int Int32 { get { return (int)Object; } }

        public T As<T>() { return (T)Object; }

        public override string ToString()
        {
            if (Hints.HasFlag(VariantHint.Error))
            {
                return "[ERROR]";
            }

            switch (Type)
            {
                case VariantType.Bool:
                    return As<bool>()
                        ? "TRUE"
                        : "FALSE";

                case VariantType.Integer:
                case VariantType.UnsignedInteger:
                    if (Hints.HasFlag(VariantHint.Pointer))
                    {
                        return Size == 4 ? string.Format("0x{0:X8}", Object)
                             : Size == 8 ? string.Format("0x{0:X16}", Object)
                             : "[ERROR]";
                    }
                    else if (Hints.HasFlag(VariantHint.Hex))
                    {
                        return Size == 1 ? string.Format("0x{0:X2}", Object)
                             : Size == 2 ? string.Format("0x{0:X4}", Object)
                             : Size == 4 ? string.Format("0x{0:X8}", Object)
                             : Size == 8 ? string.Format("0x{0:X16}", Object)
                             : "[ERROR]";
                    }
                    else
                    {
                        return string.Format("{0}", Object);
                    }
                   

                case VariantType.Float:
                    return string.Format("{0}", Object);

                case VariantType.Binary:
                    return PrintBinaryBlob((byte[])Object, Math.Min(Size, 128), 4, 16);

                case VariantType.String:
                case VariantType.UnicodeString:
                    return String;

                default:
                    return "[ERROR]";
            }
        }

        internal static EventVariant Parse(BinaryReader reader)
        {
            var result = new EventVariant();

            result.RequestedSize = reader.ReadInt32();
            result.Size = reader.ReadInt32();

            var type = reader.ReadUInt32();
            result.Type = (VariantType)(type & 0xF);
            result.Hints = (VariantHint)(type & 0xFF0);
            result.EnumId = (int)(type >> 12);

            switch (result.Type)
            {
                case VariantType.Bool:
                    result.Object = reader.ReadBoolean();
                    break;

                case VariantType.Integer:
                    switch (result.Size)
                    {
                        case 1: result.Object = reader.ReadSByte(); break;
                        case 2: result.Object = reader.ReadInt16(); break;
                        case 4: result.Object = reader.ReadInt32(); break;
                        case 8: result.Object = reader.ReadInt64(); break;
                        default: throw new InvalidDataException();
                    }
                    break;

                case VariantType.UnsignedInteger:
                    switch (result.Size)
                    {
                        case 1: result.Object = reader.ReadByte(); break;
                        case 2: result.Object = reader.ReadUInt16(); break;
                        case 4: result.Object = reader.ReadUInt32(); break;
                        case 8: result.Object = reader.ReadUInt64(); break;
                        default: throw new InvalidDataException();
                    }
                    break;

                case VariantType.Binary:
                    result.Object = reader.ReadBytes(result.Size);
                    break;

                case VariantType.String:
                    result.Object = Encoding.UTF8.GetString(reader.ReadBytes(result.Size));
                    break;

                case VariantType.UnicodeString:
                    result.Object = Encoding.Unicode.GetString(reader.ReadBytes(result.Size));
                    break;
            }

            return result;
        }

        internal static bool IsEnum(BinaryReader reader)
        {
            var requestedSize = reader.ReadInt32();
            var size = reader.ReadInt32();
            var type = reader.ReadUInt32();

            var result = ((VariantType)(type & 0xF) == VariantType.Enum);

            reader.BaseStream.Seek(-12, SeekOrigin.Current);

            if (result)
            {
                EventVariant.Parse(reader);
            }

            return result;
        }

        private string PrintBinaryBlob(byte[] buffer, int size, int indent, int maxElementsInLine)
        {
            StringBuilder result = new StringBuilder("\n");
            int sizeRoundedUp = ((size + maxElementsInLine - 1) / maxElementsInLine) * maxElementsInLine;

            for (int position = 0; position < sizeRoundedUp; position += 1)
            {
                bool isBeginOfRow = (position % maxElementsInLine) == 0;
                bool isEndOfRow = ((position + 1) % maxElementsInLine) == 0;

                if (isBeginOfRow)
                {
                    result.Append("".PadLeft(indent));
                }

                if (position < size)
                {
                    result.Append(buffer[position].ToString("x2"));
                    result.Append(" ");
                }
                else
                {
                    result.Append("?? ");
                }

                if (isEndOfRow)
                {
                    result.Append(" |  ");

                    for (int lineBeginPosition = position - maxElementsInLine + 1; lineBeginPosition < position; lineBeginPosition++)
                    {
                        //
                        // Is printable?
                        //
                        if (lineBeginPosition < size && buffer[lineBeginPosition] >= 0x20 && buffer[lineBeginPosition] <= 0x7E)
                        {
                            result.Append(Convert.ToChar(buffer[lineBeginPosition]));
                        }
                        else
                        {
                            result.Append(".");
                        }
                    }

                    //
                    // Do not write end of line on the last row.
                    //
                    if (position != sizeRoundedUp - 1)
                    {
                        result.AppendLine();
                    }
                }
            }

            return result.ToString();
        }
    }
}
