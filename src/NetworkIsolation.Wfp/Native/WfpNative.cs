using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: InternalsVisibleTo("NetworkIsolation.Tests")]

namespace NetworkIsolation.Wfp.Native;

/// <summary>x64 Windows Filtering Platform (fwpuclnt.dll) ABI declarations.</summary>
internal static class WfpNative
{
    // FWP_DATA_TYPE
    internal const uint FWP_EMPTY = 0;
    internal const uint FWP_UINT8 = 1;
    internal const uint FWP_UINT16 = 2;
    internal const uint FWP_UINT32 = 3;
    internal const uint FWP_UINT64 = 4;
    internal const uint FWP_INT8 = 5;
    internal const uint FWP_INT16 = 6;
    internal const uint FWP_INT32 = 7;
    internal const uint FWP_INT64 = 8;
    internal const uint FWP_FLOAT = 9;
    internal const uint FWP_DOUBLE = 10;
    internal const uint FWP_BYTE_ARRAY16_TYPE = 11;
    internal const uint FWP_BYTE_BLOB_TYPE = 12;
    internal const uint FWP_SID = 13;
    internal const uint FWP_V4_ADDR_MASK = 0x100;
    internal const uint FWP_V6_ADDR_MASK = 0x101;

    // FWP_MATCH_TYPE
    internal const uint FWP_MATCH_EQUAL = 0;

    // FWP_ACTION_TYPE
    internal const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    internal const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;   // 0x1001
    internal const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;  // 0x1002

    // Session, Provider, Sublayer, Filter flags
    internal const uint FWPM_SESSION_FLAG_NONE = 0x00000000;
    internal const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    internal const uint FWPM_PROVIDER_FLAG_NONE = 0x00000000;
    internal const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;

    internal const uint FWPM_SUBLAYER_FLAG_NONE = 0x00000000;
    internal const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;

    internal const uint FWPM_FILTER_FLAG_NONE = 0x00000000;
    internal const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;

    // Enumeration constants
    internal const uint FWP_FILTER_ENUM_FULLY_CONTAINED = 0;
    internal const uint FWP_FILTER_ENUM_OVERLAPPING = 1;
    internal const uint FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH = 0x00000001;
    internal const uint FWP_FILTER_ENUM_FLAG_SORTED = 0x00000002;
    internal const uint FWP_FILTER_ENUM_ACTION_MASK_ALL = 0xFFFFFFFF;

    // RPC authentication services for FwpmEngineOpen0
    internal const uint RPC_C_AUTHN_WINNT = 10;
    internal const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;

    // Common Win32 / FWP error codes
    internal const uint ERROR_SUCCESS = 0;
    internal const uint ERROR_FILE_NOT_FOUND = 2;
    internal const uint ERROR_PATH_NOT_FOUND = 3;
    internal const uint ERROR_ACCESS_DENIED = 5;
    internal const uint FWP_E_LAYER_NOT_FOUND = 0x80320001;
    internal const uint FWP_E_CONDITION_NOT_FOUND = 0x80320002;
    internal const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    internal const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    internal const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    internal const uint FWP_E_NOT_FOUND = 0x80320008;
    internal const uint FWP_E_IN_USE = 0x80320009;
    internal const uint FWP_E_ALREADY_EXISTS = 0x8032000A;
    internal const uint FWP_E_DYNAMIC_SESSION_IN_PROGRESS = 0x8032000B;

    internal static readonly Guid ProviderKey = NetworkIsolation.Core.NetworkIsolationConstants.ProviderGuid;
    internal static readonly Guid SublayerKey = NetworkIsolation.Core.NetworkIsolationConstants.SubLayerGuid;

    // Supported ALE authorization layers (IPv4/IPv6)
    internal static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    internal static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    internal static readonly Guid LayerAleAuthRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    internal static readonly Guid LayerAleAuthRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");

    // Packet-level transport layers (no ALE_APP_ID / ALE_PACKAGE_ID support in user-mode filters)
    internal static readonly Guid LayerOutboundTransportV4 = new("09e61aea-d214-46e2-9b21-b26b0b2f28c8");
    internal static readonly Guid LayerOutboundTransportV6 = new("e1735bde-013f-4655-b351-a49e15762df0");

    internal static readonly Guid[] AleLayers =
    [
        LayerAleAuthConnectV4,
        LayerAleAuthConnectV6,
        LayerAleAuthRecvAcceptV4,
        LayerAleAuthRecvAcceptV6
    ];

    internal static readonly Guid[] Layers =
    [
        LayerAleAuthConnectV4,
        LayerAleAuthConnectV6,
        LayerAleAuthRecvAcceptV4,
        LayerAleAuthRecvAcceptV6,
        LayerOutboundTransportV4,
        LayerOutboundTransportV6
    ];

    // Condition field GUIDs
    internal static readonly Guid ConditionApp = new("d78e1e87-8644-4ea5-9437-d809ecefc971");       // FWPM_CONDITION_ALE_APP_ID
    internal static readonly Guid ConditionPackage = new("71bc78fa-f17c-4997-a602-6abb261f351c");   // FWPM_CONDITION_ALE_PACKAGE_ID
    internal static readonly Guid ConditionInterface = new("4cd62a49-59c3-4969-b7f3-bda5d32890a4"); // FWPM_CONDITION_IP_LOCAL_INTERFACE
    internal static readonly Guid ConditionRemote = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");    // FWPM_CONDITION_IP_REMOTE_ADDRESS

    /// <summary>FWPM_DISPLAY_DATA0 (16 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct DISPLAY
    {
        public nint name;
        public nint description;
    }

    /// <summary>FWP_BYTE_BLOB (16 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct BLOB
    {
        public uint size;
        public nint data;
    }

    /// <summary>FWPM_SESSION0 (72 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SESSION
    {
        public Guid sessionKey;
        public DISPLAY displayData;
        public uint flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public nint sid;
        public nint username;
        public int kernelMode;
    }

    /// <summary>FWPM_PROVIDER0 (64 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROVIDER
    {
        public Guid providerKey;
        public DISPLAY displayData;
        public uint flags;
        public BLOB providerData;
        public nint serviceName;
    }

    /// <summary>FWPM_SUBLAYER0 (72 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SUBLAYER
    {
        public Guid subLayerKey;
        public DISPLAY displayData;
        public uint flags;
        public nint providerKey;
        public BLOB providerData;
        public ushort weight;
    }

    /// <summary>FWP_VALUE0 (16 bytes on x64). Note: FWP_UINT64 stores a pointer in <see cref="ptr"/>.</summary>
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct VALUE
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public byte uint8;
        [FieldOffset(8)] public ushort uint16;
        [FieldOffset(8)] public uint uint32;
        [FieldOffset(8)] public ulong u64;
        [FieldOffset(8)] public nint ptr;
    }

    /// <summary>FWP_CONDITION_VALUE0 (16 bytes on x64). Note: FWP_UINT64 stores a pointer in <see cref="ptr"/>.</summary>
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct CVALUE
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public byte uint8;
        [FieldOffset(8)] public ushort uint16;
        [FieldOffset(8)] public uint uint32;
        [FieldOffset(8)] public ulong u64;
        [FieldOffset(8)] public nint ptr;
    }

    /// <summary>FWPM_FILTER_CONDITION0 (40 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CONDITION
    {
        public Guid field;
        public uint match;
        public CVALUE value;
    }

    /// <summary>FWPM_ACTION0 (20 bytes on x64; 4-byte aligned).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ACTION
    {
        public uint type;
        public Guid callout;
    }

    /// <summary>Union of rawContext / providerContextKey in FWPM_FILTER0 (16 bytes, 8-byte aligned).</summary>
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct CONTEXT_UNION
    {
        [FieldOffset(0)] public ulong rawContext;
        [FieldOffset(0)] public Guid providerContextKey;
    }

    /// <summary>FWPM_FILTER0 (200 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FILTER
    {
        public Guid key;
        public DISPLAY display;
        public uint flags;
        public nint providerKey;
        public BLOB providerData;
        public Guid layerKey;
        public Guid sublayerKey;
        public VALUE weight;
        public uint numConditions;
        public nint conditions;
        public ACTION action;
        public CONTEXT_UNION context;
        public nint reserved;
        public ulong filterId;
        public VALUE effectiveWeight;
    }

    /// <summary>FWP_V4_ADDR_AND_MASK (8 bytes; host byte order).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    /// <summary>FWP_V6_ADDR_AND_MASK (17 bytes; network byte order address + prefix length).</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct FWP_V6_ADDR_AND_MASK
    {
        public byte a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, prefix;

        public static FWP_V6_ADDR_AND_MASK FromBytes(ReadOnlySpan<byte> addrBytes, byte prefixLength)
        {
            if (addrBytes.Length != 16)
                throw new ArgumentException("IPv6 address must be 16 bytes.", nameof(addrBytes));

            return new FWP_V6_ADDR_AND_MASK
            {
                a0 = addrBytes[0],
                a1 = addrBytes[1],
                a2 = addrBytes[2],
                a3 = addrBytes[3],
                a4 = addrBytes[4],
                a5 = addrBytes[5],
                a6 = addrBytes[6],
                a7 = addrBytes[7],
                a8 = addrBytes[8],
                a9 = addrBytes[9],
                a10 = addrBytes[10],
                a11 = addrBytes[11],
                a12 = addrBytes[12],
                a13 = addrBytes[13],
                a14 = addrBytes[14],
                a15 = addrBytes[15],
                prefix = prefixLength
            };
        }
    }

    /// <summary>FWPM_FILTER_ENUM_TEMPLATE0 (72 bytes on x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ENUM_TEMPLATE
    {
        public nint providerKey;
        public Guid layerKey;
        public uint enumType;
        public uint flags;
        public nint providerContextTemplate;
        public uint numFilterConditions;
        public nint filterCondition;
        public uint actionMask;
        public nint calloutKey;
    }

    [DllImport("fwpuclnt.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService,
        nint authIdentity,
        ref SESSION session,
        out nint engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmEngineClose0(nint engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmTransactionBegin0(nint engineHandle, uint flags);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmTransactionCommit0(nint engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmTransactionAbort0(nint engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmProviderAdd0(nint engineHandle, ref PROVIDER provider, nint sd);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmProviderGetByKey0(nint engineHandle, ref Guid key, out nint provider);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmSubLayerAdd0(nint engineHandle, ref SUBLAYER subLayer, nint sd);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmSubLayerGetByKey0(nint engineHandle, ref Guid key, out nint subLayer);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterAdd0(nint engineHandle, ref FILTER filter, nint sd, out ulong id);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterDeleteById0(nint engineHandle, ulong id);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterCreateEnumHandle0(nint engineHandle, ref ENUM_TEMPLATE enumTemplate, out nint enumHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterDestroyEnumHandle0(nint engineHandle, nint enumHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out nint appId);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern void FwpmFreeMemory0(ref nint p);
}
