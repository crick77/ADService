using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace adEditor
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CounterVar
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public byte[] varName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public byte[] varGuid;

        [MarshalAs(UnmanagedType.U1)]
        public byte refCount;

        [MarshalAs(UnmanagedType.U2)]
        public short value;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DateVar
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public byte[] varName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public byte[] varGuid;

        [MarshalAs(UnmanagedType.U1)]
        public byte refCount;

        [MarshalAs(UnmanagedType.U8)]
        public long value;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Event
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] eventName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public byte[] varGuid;

        [MarshalAs(UnmanagedType.U2)]
        public short decreaseQty;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ActiveDataFile
    {
        // must be set to "*AD*"
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] magic;

        [MarshalAs(UnmanagedType.U1)]
        public byte version;

        [MarshalAs(UnmanagedType.U8)]
        public long createTime;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] owner;

        // This is the SHA1 of only metadata fields with this and "dataHash" fields set to 0
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] metaDataHash;

        // This is the SHA1 of WHOLE data block - means ALL data fields togheter (ActiveDataFields structure + data)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] dataHash;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public CounterVar[] counter;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public DateVar[] datetime;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public Event[] events;

        // Must be set to "DF"
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] magic2;

        [MarshalAs(UnmanagedType.U4)]
        public uint openCount;

        [MarshalAs(UnmanagedType.U2)]
        public short dataCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ActiveDataFields
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] fieldName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] extension;

        [MarshalAs(UnmanagedType.U4)]
        public uint flag;

        [MarshalAs(UnmanagedType.U4)]
        public uint fieldSize;

        // follow "filedSize" bytes of data
    }
}
