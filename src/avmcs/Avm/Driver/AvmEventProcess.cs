using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Avm.Driver
{
    public class AvmEventProcess : AvmEvent
    {
        public bool Created;
        public uint ProcessId;
        public uint ParentProcessId;

        //
        // Only set if Created == TRUE.
        //
        public string ImageFileName;

        internal static AvmEventProcess Parse(BinaryReader reader)
        {
            var result = new AvmEventProcess();
            result.Created = reader.ReadByte() != 0;
            result.ProcessId = reader.ReadUInt32();
            result.ParentProcessId = reader.ReadUInt32();

            if (result.Created)
            {
                result.ImageFileName = EventVariant.Parse(reader).String;
            }

            return result;
        }
    }
}
