using Avm.Driver;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;

using Unmanaged;

namespace Avm
{
    public class AvmEventStream : Stream
    {
        public AvmEventStream()
        {
            _deviceHandle = Kernel32.CreateFile(
                //@"\\.\AvmExt",
                @"out.dat",
                FileAccess.Read,
                FileShare.None,
                IntPtr.Zero,
                FileMode.Open,
                FileAttributes.Normal,
                IntPtr.Zero);
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            uint bytesRead;
            var tmp = new byte[count];

            Kernel32.ReadFile(
                _deviceHandle.DangerousGetHandle(),
                tmp,
                (uint)count,
                out bytesRead,
                IntPtr.Zero);

            Array.Copy(tmp, 0, buffer, offset, bytesRead);

            return (int)bytesRead;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override bool CanRead
        {
            get 
            {
                return true;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return false;
            }
        }

        public override long Length
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotImplementedException();
            }

            set
            {
                throw new NotImplementedException();
            }
        }

        private SafeFileHandle _deviceHandle;
    }
}
