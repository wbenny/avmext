using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Unmanaged;

namespace Avm.Driver
{
    public enum EventType
    {
        FunctionCall,
        Process,
        Thread,
        LoadImage
    }

    public class AvmEvent
    {
        public uint Size;
        public uint SequenceId;
        public EventType Type;
    }
}
