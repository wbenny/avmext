using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Avm.Driver
{
    public class AvmEventThread : AvmEvent
    {
        public bool Created;
        public uint ProcessId;
        public uint ThreadId;

        internal static AvmEventThread Parse(BinaryReader reader)
        {
            var result = new AvmEventThread();
            result.Created = reader.ReadByte() != 0;
            result.ProcessId = reader.ReadUInt32();
            result.ThreadId = reader.ReadUInt32();

            return result;
        }
    }
}
