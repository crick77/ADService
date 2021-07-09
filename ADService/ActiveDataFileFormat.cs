using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace adEditor
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ActiveDataHeader
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

        [MarshalAs(UnmanagedType.U4)]
        public int nextHeaderLen;

        [MarshalAs(UnmanagedType.U2)]
        public short dataCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 259)]
        public byte[] publicKey;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] symmetricKey;

        // This is the SHA1 of only metadata fields with this and "dataHash" fields set to 0
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] headerHash;

        // Must be set to "DFB"
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] magic2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ActiveDataNextHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] headerName;

        [MarshalAs(UnmanagedType.U4)]
        public int nextHeaderLen;

        // follow content
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ActiveDataGuardHeader10
    {
        // Must be "GRD1"
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] magic;

        [MarshalAs(UnmanagedType.U4)]
        public int openCount;

        [MarshalAs(UnmanagedType.U4)]
        public int counter;

        [MarshalAs(UnmanagedType.U8)]
        public long expireDate;

        // bit field (bit 0 - "can share")
        [MarshalAs(UnmanagedType.U2)]
        public short flags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ActiveDataDataBlock
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public byte[] extension;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] type;

        [MarshalAs(UnmanagedType.U2)]
        public short flag;

        // This is the SHA1 of WHOLE data block - means ALL data fields togheter (ActiveDataFields structure + unencrypted data)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] dataHash;

        [MarshalAs(UnmanagedType.U4)]
        public uint dataLen;

        // follow "cryptLen" bytes of data
    }
}
