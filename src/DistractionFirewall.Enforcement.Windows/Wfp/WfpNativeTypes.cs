using System.Runtime.InteropServices;

namespace DistractionFirewall.Enforcement.Windows.Wfp;

internal enum FwpDataType : uint
{
    Empty = 0,
    UInt8 = 1,
    UInt16 = 2,
    UInt32 = 3,
    UInt64 = 4,
    V4AddressMask = 0x100,
    V6AddressMask = 0x101,
}

internal enum FwpMatchType : uint
{
    Equal = 0,
}

internal enum FwpActionType : uint
{
    Block = 0x00001001,
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FwpDisplayData0
{
    [FieldOffset(0)]
    public nint Name;

    [FieldOffset(8)]
    public nint Description;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FwpByteBlob
{
    [FieldOffset(0)]
    public uint Size;

    [FieldOffset(8)]
    public nint Data;
}

[StructLayout(LayoutKind.Explicit, Size = 8)]
internal struct FwpValueUnion
{
    [FieldOffset(0)]
    public byte UInt8;

    [FieldOffset(0)]
    public ushort UInt16;

    [FieldOffset(0)]
    public uint UInt32;

    [FieldOffset(0)]
    public nint Pointer;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FwpValue0
{
    [FieldOffset(0)]
    public FwpDataType Type;

    [FieldOffset(8)]
    public FwpValueUnion Value;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FwpConditionValue0
{
    [FieldOffset(0)]
    public FwpDataType Type;

    [FieldOffset(8)]
    public FwpValueUnion Value;
}

[StructLayout(LayoutKind.Explicit, Size = 8)]
internal struct FwpV4AddressAndMask
{
    [FieldOffset(0)]
    public uint Address;

    [FieldOffset(4)]
    public uint Mask;
}

[StructLayout(LayoutKind.Explicit, Size = 17)]
internal unsafe struct FwpV6AddressAndMask
{
    [FieldOffset(0)]
    public fixed byte Address[16];

    [FieldOffset(16)]
    public byte PrefixLength;
}

[StructLayout(LayoutKind.Explicit, Size = 40)]
internal struct FwpmFilterCondition0
{
    [FieldOffset(0)]
    public Guid FieldKey;

    [FieldOffset(16)]
    public FwpMatchType MatchType;

    [FieldOffset(24)]
    public FwpConditionValue0 ConditionValue;
}

[StructLayout(LayoutKind.Explicit, Size = 20)]
internal struct FwpAction0
{
    [FieldOffset(0)]
    public FwpActionType Type;

    [FieldOffset(4)]
    public Guid FilterType;
}

[StructLayout(LayoutKind.Explicit, Size = 64)]
internal struct FwpmProvider0
{
    [FieldOffset(0)]
    public Guid ProviderKey;

    [FieldOffset(16)]
    public FwpDisplayData0 DisplayData;

    [FieldOffset(32)]
    public uint Flags;

    [FieldOffset(40)]
    public FwpByteBlob ProviderData;

    [FieldOffset(56)]
    public nint ServiceName;
}

[StructLayout(LayoutKind.Explicit, Size = 72)]
internal struct FwpmSubLayer0
{
    [FieldOffset(0)]
    public Guid SubLayerKey;

    [FieldOffset(16)]
    public FwpDisplayData0 DisplayData;

    [FieldOffset(32)]
    public uint Flags;

    [FieldOffset(40)]
    public nint ProviderKey;

    [FieldOffset(48)]
    public FwpByteBlob ProviderData;

    [FieldOffset(64)]
    public ushort Weight;
}

[StructLayout(LayoutKind.Explicit, Size = 192)]
internal struct FwpmFilter0
{
    [FieldOffset(0)]
    public Guid FilterKey;

    [FieldOffset(16)]
    public FwpDisplayData0 DisplayData;

    [FieldOffset(32)]
    public uint Flags;

    [FieldOffset(40)]
    public nint ProviderKey;

    [FieldOffset(48)]
    public FwpByteBlob ProviderData;

    [FieldOffset(64)]
    public Guid LayerKey;

    [FieldOffset(80)]
    public Guid SubLayerKey;

    [FieldOffset(96)]
    public FwpValue0 Weight;

    [FieldOffset(112)]
    public uint NumberOfFilterConditions;

    [FieldOffset(120)]
    public nint FilterCondition;

    [FieldOffset(128)]
    public FwpAction0 Action;

    [FieldOffset(152)]
    public ulong RawContext;

    [FieldOffset(152)]
    public nint ProviderContextKey;

    [FieldOffset(160)]
    public nint Reserved;

    [FieldOffset(168)]
    public ulong FilterId;

    [FieldOffset(176)]
    public FwpValue0 EffectiveWeight;
}
