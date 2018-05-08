using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Avm.Driver
{
    public class AvmEventLoadImage : AvmEvent
    {
        public uint ProcessId;
        public ulong ImageBase;
        public ulong ImageSize;
        public string ImageFileName;

        internal static AvmEventLoadImage Parse(BinaryReader reader)
        {
            var result = new AvmEventLoadImage();
            result.ProcessId = reader.ReadUInt32();
            result.ImageBase = reader.ReadUInt64();
            result.ImageSize = reader.ReadUInt64();
            result.ImageFileName = EventVariant.Parse(reader).String;

            return result;
        }
    }
}
