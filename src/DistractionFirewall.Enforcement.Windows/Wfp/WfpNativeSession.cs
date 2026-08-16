using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace DistractionFirewall.Enforcement.Windows.Wfp;

internal enum WfpObjectMatch
{
    Missing,
    Matching,
    Foreign,
}

internal interface IWfpNativeSessionFactory
{
    IWfpNativeSession Open();
}

internal interface IWfpNativeSession : IDisposable
{
    void BeginTransaction();

    void CommitTransaction();

    void AbortTransaction();

    WfpObjectMatch InspectProvider();

    void AddProvider();

    void DeleteProvider();

    WfpObjectMatch InspectSubLayer();

    void AddSubLayer();

    void DeleteSubLayer();

    int CountFiltersReferencingProductObjects();

    WfpObjectMatch InspectFilter(WfpFilterSpec spec);

    void AddFilter(WfpFilterSpec spec);

    void DeleteFilter(Guid filterKey);
}

internal sealed class WfpNativeSessionFactory : IWfpNativeSessionFactory
{
    private readonly byte[] _ownerData;

    public WfpNativeSessionFactory(string productInstanceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(productInstanceId);
        _ownerData = Encoding.UTF8.GetBytes("DistractionFirewall/WFP/v1/" + productInstanceId);
    }

    public IWfpNativeSession Open()
    {
        if (nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException("The WFP interop layer is intentionally x64-only.");
        }

        var error = WfpNativeMethods.EngineOpen(
            serverName: null,
            WfpNativeMethods.RpcAuthenticationWinNt,
            authenticationIdentity: nint.Zero,
            session: nint.Zero,
            out var rawHandle);
        WfpException.ThrowIfFailed(error, "FwpmEngineOpen0");
        return new WfpNativeSession(new SafeWfpEngineHandle(rawHandle), _ownerData);
    }
}

internal sealed class WfpNativeSession : IWfpNativeSession
{
    private readonly SafeWfpEngineHandle _engineHandle;
    private readonly byte[] _ownerData;
    private bool _disposed;

    public WfpNativeSession(SafeWfpEngineHandle engineHandle, byte[] ownerData)
    {
        _engineHandle = engineHandle ?? throw new ArgumentNullException(nameof(engineHandle));
        _ownerData = ownerData?.ToArray() ?? throw new ArgumentNullException(nameof(ownerData));
    }

    public void BeginTransaction()
    {
        ThrowIfDisposed();
        WfpException.ThrowIfFailed(
            WfpNativeMethods.TransactionBegin(_engineHandle, flags: 0),
            "FwpmTransactionBegin0");
    }

    public void CommitTransaction()
    {
        ThrowIfDisposed();
        WfpException.ThrowIfFailed(WfpNativeMethods.TransactionCommit(_engineHandle), "FwpmTransactionCommit0");
    }

    public void AbortTransaction()
    {
        ThrowIfDisposed();
        WfpException.ThrowIfFailed(WfpNativeMethods.TransactionAbort(_engineHandle), "FwpmTransactionAbort0");
    }

    public WfpObjectMatch InspectProvider()
    {
        ThrowIfDisposed();
        var key = WfpProductConstants.ProviderKey;
        var error = WfpNativeMethods.ProviderGetByKey(_engineHandle, in key, out var pointer);
        if (error == WfpNativeMethods.ErrorProviderNotFound)
        {
            return WfpObjectMatch.Missing;
        }

        WfpException.ThrowIfFailed(error, "FwpmProviderGetByKey0");
        using var allocation = new SafeWfpAllocatedMemoryHandle(pointer);
        var provider = Marshal.PtrToStructure<FwpmProvider0>(allocation.DangerousGetHandle());
        return provider.ProviderKey == key
            && provider.Flags == WfpNativeMethods.ProviderFlagPersistent
            && provider.ServiceName == nint.Zero
            && BlobEquals(provider.ProviderData, _ownerData)
                ? WfpObjectMatch.Matching
                : WfpObjectMatch.Foreign;
    }

    public void AddProvider()
    {
        ThrowIfDisposed();
        using var allocations = new NativeAllocationScope();
        var provider = new FwpmProvider0
        {
            ProviderKey = WfpProductConstants.ProviderKey,
            DisplayData = new FwpDisplayData0
            {
                Name = allocations.AllocateString("Distraction Firewall"),
                Description = allocations.AllocateString("Persistent exact-address blocking provider."),
            },
            Flags = WfpNativeMethods.ProviderFlagPersistent,
            ProviderData = CreateBlob(allocations, _ownerData),
            ServiceName = nint.Zero,
        };
        WfpException.ThrowIfFailed(
            WfpNativeMethods.ProviderAdd(_engineHandle, in provider, securityDescriptor: nint.Zero),
            "FwpmProviderAdd0");
    }

    public void DeleteProvider()
    {
        ThrowIfDisposed();
        var key = WfpProductConstants.ProviderKey;
        WfpException.ThrowIfFailed(
            WfpNativeMethods.ProviderDeleteByKey(_engineHandle, in key),
            "FwpmProviderDeleteByKey0");
    }

    public WfpObjectMatch InspectSubLayer()
    {
        ThrowIfDisposed();
        var key = WfpProductConstants.SubLayerKey;
        var error = WfpNativeMethods.SubLayerGetByKey(_engineHandle, in key, out var pointer);
        if (error == WfpNativeMethods.ErrorSubLayerNotFound)
        {
            return WfpObjectMatch.Missing;
        }

        WfpException.ThrowIfFailed(error, "FwpmSubLayerGetByKey0");
        using var allocation = new SafeWfpAllocatedMemoryHandle(pointer);
        var subLayer = Marshal.PtrToStructure<FwpmSubLayer0>(allocation.DangerousGetHandle());
        return subLayer.SubLayerKey == key
            && subLayer.Flags == WfpNativeMethods.SubLayerFlagPersistent
            && subLayer.ProviderKey != nint.Zero
            && Marshal.PtrToStructure<Guid>(subLayer.ProviderKey) == WfpProductConstants.ProviderKey
            && subLayer.Weight == WfpProductConstants.SubLayerWeight
            && BlobEquals(subLayer.ProviderData, _ownerData)
                ? WfpObjectMatch.Matching
                : WfpObjectMatch.Foreign;
    }

    public void AddSubLayer()
    {
        ThrowIfDisposed();
        using var allocations = new NativeAllocationScope();
        var subLayer = new FwpmSubLayer0
        {
            SubLayerKey = WfpProductConstants.SubLayerKey,
            DisplayData = new FwpDisplayData0
            {
                Name = allocations.AllocateString("Distraction Firewall exact-address blocks"),
                Description = allocations.AllocateString("Product-owned ALE_AUTH_CONNECT block filters."),
            },
            Flags = WfpNativeMethods.SubLayerFlagPersistent,
            ProviderKey = allocations.AllocateStruct(WfpProductConstants.ProviderKey),
            ProviderData = CreateBlob(allocations, _ownerData),
            Weight = WfpProductConstants.SubLayerWeight,
        };
        WfpException.ThrowIfFailed(
            WfpNativeMethods.SubLayerAdd(_engineHandle, in subLayer, securityDescriptor: nint.Zero),
            "FwpmSubLayerAdd0");
    }

    public void DeleteSubLayer()
    {
        ThrowIfDisposed();
        var key = WfpProductConstants.SubLayerKey;
        WfpException.ThrowIfFailed(
            WfpNativeMethods.SubLayerDeleteByKey(_engineHandle, in key),
            "FwpmSubLayerDeleteByKey0");
    }

    public int CountFiltersReferencingProductObjects()
    {
        ThrowIfDisposed();
        WfpException.ThrowIfFailed(
            WfpNativeMethods.FilterCreateEnumHandle(
                _engineHandle,
                enumTemplate: nint.Zero,
                out var enumHandle),
            "FwpmFilterCreateEnumHandle0");
        try
        {
            const uint pageSize = 128;
            var count = 0;
            while (true)
            {
                WfpException.ThrowIfFailed(
                    WfpNativeMethods.FilterEnum(
                        _engineHandle,
                        enumHandle,
                        pageSize,
                        out var entries,
                        out var returned),
                    "FwpmFilterEnum0");
                try
                {
                    for (var index = 0u; index < returned; index++)
                    {
                        var filterPointer = Marshal.ReadIntPtr(entries, checked((int)(index * (uint)nint.Size)));
                        if (filterPointer == nint.Zero)
                        {
                            throw new InvalidDataException("WFP filter enumeration returned a null entry.");
                        }

                        var filter = Marshal.PtrToStructure<FwpmFilter0>(filterPointer);
                        var referencesProvider = filter.ProviderKey != nint.Zero
                            && Marshal.PtrToStructure<Guid>(filter.ProviderKey)
                                == WfpProductConstants.ProviderKey;
                        if (referencesProvider || filter.SubLayerKey == WfpProductConstants.SubLayerKey)
                        {
                            count = checked(count + 1);
                        }
                    }
                }
                finally
                {
                    if (entries != nint.Zero)
                    {
                        WfpNativeMethods.FreeMemory(ref entries);
                    }
                }

                if (returned < pageSize)
                {
                    return count;
                }
            }
        }
        finally
        {
            WfpException.ThrowIfFailed(
                WfpNativeMethods.FilterDestroyEnumHandle(_engineHandle, enumHandle),
                "FwpmFilterDestroyEnumHandle0");
        }
    }

    public WfpObjectMatch InspectFilter(WfpFilterSpec spec)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(spec);
        var key = spec.FilterKey;
        var error = WfpNativeMethods.FilterGetByKey(_engineHandle, in key, out var pointer);
        if (error == WfpNativeMethods.ErrorFilterNotFound)
        {
            return WfpObjectMatch.Missing;
        }

        WfpException.ThrowIfFailed(error, "FwpmFilterGetByKey0");
        using var allocation = new SafeWfpAllocatedMemoryHandle(pointer);
        var filter = Marshal.PtrToStructure<FwpmFilter0>(allocation.DangerousGetHandle());
        if (filter.FilterKey != spec.FilterKey
            || filter.Flags != WfpNativeMethods.FilterFlagPersistent
            || filter.ProviderKey == nint.Zero
            || Marshal.PtrToStructure<Guid>(filter.ProviderKey) != WfpProductConstants.ProviderKey
            || !BlobEquals(filter.ProviderData, _ownerData)
            || filter.LayerKey != spec.LayerKey
            || filter.SubLayerKey != WfpProductConstants.SubLayerKey
            || filter.Weight.Type != FwpDataType.Empty
            || filter.NumberOfFilterConditions != 1
            || filter.FilterCondition == nint.Zero
            || filter.Action.Type != FwpActionType.Block)
        {
            return WfpObjectMatch.Foreign;
        }

        var condition = Marshal.PtrToStructure<FwpmFilterCondition0>(filter.FilterCondition);
        return condition.FieldKey == WfpProductConstants.ConditionIpRemoteAddress
            && condition.MatchType == FwpMatchType.Equal
            && ConditionAddressEquals(condition.ConditionValue, spec.ParseAddress())
                ? WfpObjectMatch.Matching
                : WfpObjectMatch.Foreign;
    }

    public void AddFilter(WfpFilterSpec spec)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(spec);
        var address = spec.ParseAddress();
        using var allocations = new NativeAllocationScope();

        var conditionValue = CreateAddressConditionValue(allocations, address);
        var condition = new FwpmFilterCondition0
        {
            FieldKey = WfpProductConstants.ConditionIpRemoteAddress,
            MatchType = FwpMatchType.Equal,
            ConditionValue = conditionValue,
        };
        var filter = new FwpmFilter0
        {
            FilterKey = spec.FilterKey,
            DisplayData = new FwpDisplayData0
            {
                Name = allocations.AllocateString("Distraction Firewall target address"),
                Description = allocations.AllocateString(address.ToString()),
            },
            Flags = WfpNativeMethods.FilterFlagPersistent,
            ProviderKey = allocations.AllocateStruct(WfpProductConstants.ProviderKey),
            ProviderData = CreateBlob(allocations, _ownerData),
            LayerKey = spec.LayerKey,
            SubLayerKey = WfpProductConstants.SubLayerKey,
            Weight = new FwpValue0 { Type = FwpDataType.Empty },
            NumberOfFilterConditions = 1,
            FilterCondition = allocations.AllocateStruct(condition),
            Action = new FwpAction0 { Type = FwpActionType.Block },
        };
        WfpException.ThrowIfFailed(
            WfpNativeMethods.FilterAdd(
                _engineHandle,
                in filter,
                securityDescriptor: nint.Zero,
                out _),
            "FwpmFilterAdd0");
    }

    public void DeleteFilter(Guid filterKey)
    {
        ThrowIfDisposed();
        WfpException.ThrowIfFailed(
            WfpNativeMethods.FilterDeleteByKey(_engineHandle, in filterKey),
            "FwpmFilterDeleteByKey0");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _engineHandle.Dispose();
        _disposed = true;
    }

    private static FwpByteBlob CreateBlob(NativeAllocationScope allocations, byte[] data)
    {
        return new FwpByteBlob
        {
            Size = checked((uint)data.Length),
            Data = allocations.AllocateBytes(data),
        };
    }

    private static bool BlobEquals(FwpByteBlob blob, byte[] expected)
    {
        if (blob.Size != expected.Length || (blob.Size > 0 && blob.Data == nint.Zero))
        {
            return false;
        }

        var actual = new byte[blob.Size];
        if (actual.Length > 0)
        {
            Marshal.Copy(blob.Data, actual, 0, actual.Length);
        }

        return actual.AsSpan().SequenceEqual(expected);
    }

    private static FwpConditionValue0 CreateAddressConditionValue(
        NativeAllocationScope allocations,
        IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var mask = new FwpV4AddressAndMask
            {
                Address = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes()),
                Mask = uint.MaxValue,
            };
            return new FwpConditionValue0
            {
                Type = FwpDataType.V4AddressMask,
                Value = new FwpValueUnion { Pointer = allocations.AllocateStruct(mask) },
            };
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var mask = CreateV6Mask(address);
            return new FwpConditionValue0
            {
                Type = FwpDataType.V6AddressMask,
                Value = new FwpValueUnion { Pointer = allocations.AllocateStruct(mask) },
            };
        }

        throw new InvalidOperationException("Only IPv4 and IPv6 WFP conditions are supported.");
    }

    private static bool ConditionAddressEquals(FwpConditionValue0 value, IPAddress expected)
    {
        if (value.Value.Pointer == nint.Zero)
        {
            return false;
        }

        if (expected.AddressFamily == AddressFamily.InterNetwork && value.Type == FwpDataType.V4AddressMask)
        {
            var mask = Marshal.PtrToStructure<FwpV4AddressAndMask>(value.Value.Pointer);
            return mask.Mask == uint.MaxValue
                && mask.Address == BinaryPrimitives.ReadUInt32BigEndian(expected.GetAddressBytes());
        }

        if (expected.AddressFamily == AddressFamily.InterNetworkV6 && value.Type == FwpDataType.V6AddressMask)
        {
            var mask = Marshal.PtrToStructure<FwpV6AddressAndMask>(value.Value.Pointer);
            return mask.PrefixLength == 128 && ReadV6Address(mask).AsSpan().SequenceEqual(expected.GetAddressBytes());
        }

        return false;
    }

    private static unsafe FwpV6AddressAndMask CreateV6Mask(IPAddress address)
    {
        var result = new FwpV6AddressAndMask { PrefixLength = 128 };
        var bytes = address.GetAddressBytes();
        for (var index = 0; index < bytes.Length; index++)
        {
            result.Address[index] = bytes[index];
        }

        return result;
    }

    private static unsafe byte[] ReadV6Address(FwpV6AddressAndMask mask)
    {
        var result = new byte[16];
        for (var index = 0; index < result.Length; index++)
        {
            result[index] = mask.Address[index];
        }

        return result;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

internal sealed class WfpException : InvalidOperationException
{
    public WfpException(string operation, uint errorCode)
        : base($"{operation} failed with WFP error 0x{errorCode:X8}.")
    {
        ErrorCode = errorCode;
        HResult = unchecked((int)errorCode);
    }

    public uint ErrorCode { get; }

    public static void ThrowIfFailed(uint errorCode, string operation)
    {
        if (errorCode != WfpNativeMethods.Success)
        {
            throw new WfpException(operation, errorCode);
        }
    }
}
