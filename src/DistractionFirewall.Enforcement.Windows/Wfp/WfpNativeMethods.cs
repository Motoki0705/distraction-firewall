using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DistractionFirewall.Enforcement.Windows.Wfp;

internal static partial class WfpNativeMethods
{
    public const uint Success = 0;
    public const uint RpcAuthenticationWinNt = 10;
    public const uint ProviderFlagPersistent = 0x00000001;
    public const uint SubLayerFlagPersistent = 0x00000001;
    public const uint FilterFlagPersistent = 0x00000001;
    public const uint ErrorFilterNotFound = 0x80320003;
    public const uint ErrorProviderNotFound = 0x80320005;
    public const uint ErrorSubLayerNotFound = 0x80320007;

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint EngineOpen(
        string? serverName,
        uint authenticationService,
        nint authenticationIdentity,
        nint session,
        out nint engineHandle);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    internal static partial uint EngineClose(nint engineHandle);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmTransactionBegin0")]
    internal static partial uint TransactionBegin(SafeWfpEngineHandle engineHandle, uint flags);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmTransactionCommit0")]
    internal static partial uint TransactionCommit(SafeWfpEngineHandle engineHandle);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmTransactionAbort0")]
    internal static partial uint TransactionAbort(SafeWfpEngineHandle engineHandle);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmProviderGetByKey0")]
    internal static partial uint ProviderGetByKey(
        SafeWfpEngineHandle engineHandle,
        in Guid providerKey,
        out nint provider);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmProviderAdd0")]
    internal static partial uint ProviderAdd(
        SafeWfpEngineHandle engineHandle,
        in FwpmProvider0 provider,
        nint securityDescriptor);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmProviderDeleteByKey0")]
    internal static partial uint ProviderDeleteByKey(
        SafeWfpEngineHandle engineHandle,
        in Guid providerKey);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmSubLayerGetByKey0")]
    internal static partial uint SubLayerGetByKey(
        SafeWfpEngineHandle engineHandle,
        in Guid subLayerKey,
        out nint subLayer);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmSubLayerAdd0")]
    internal static partial uint SubLayerAdd(
        SafeWfpEngineHandle engineHandle,
        in FwpmSubLayer0 subLayer,
        nint securityDescriptor);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmSubLayerDeleteByKey0")]
    internal static partial uint SubLayerDeleteByKey(
        SafeWfpEngineHandle engineHandle,
        in Guid subLayerKey);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFilterCreateEnumHandle0")]
    internal static partial uint FilterCreateEnumHandle(
        SafeWfpEngineHandle engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFilterEnum0")]
    internal static partial uint FilterEnum(
        SafeWfpEngineHandle engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDestroyEnumHandle0")]
    internal static partial uint FilterDestroyEnumHandle(
        SafeWfpEngineHandle engineHandle,
        nint enumHandle);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFilterGetByKey0")]
    internal static partial uint FilterGetByKey(
        SafeWfpEngineHandle engineHandle,
        in Guid filterKey,
        out nint filter);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFilterAdd0")]
    internal static partial uint FilterAdd(
        SafeWfpEngineHandle engineHandle,
        in FwpmFilter0 filter,
        nint securityDescriptor,
        out ulong filterId);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDeleteByKey0")]
    internal static partial uint FilterDeleteByKey(
        SafeWfpEngineHandle engineHandle,
        in Guid filterKey);

    [LibraryImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    internal static partial void FreeMemory(ref nint memory);
}

internal sealed class SafeWfpEngineHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeWfpEngineHandle()
        : base(ownsHandle: true)
    {
    }

    public SafeWfpEngineHandle(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        return WfpNativeMethods.EngineClose(handle) == WfpNativeMethods.Success;
    }
}

internal sealed class SafeWfpAllocatedMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWfpAllocatedMemoryHandle(nint handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        var memory = handle;
        WfpNativeMethods.FreeMemory(ref memory);
        SetHandle(nint.Zero);
        return true;
    }
}

internal sealed class SafeHGlobalHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeHGlobalHandle(int byteCount)
        : base(ownsHandle: true)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(byteCount);

        SetHandle(Marshal.AllocHGlobal(byteCount));
    }

    public SafeHGlobalHandle(string value)
        : base(ownsHandle: true)
    {
        ArgumentNullException.ThrowIfNull(value);
        SetHandle(Marshal.StringToHGlobalUni(value));
    }

    public nint Pointer => DangerousGetHandle();

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }
}

internal sealed class NativeAllocationScope : IDisposable
{
    private readonly List<SafeHGlobalHandle> _allocations = [];

    public nint AllocateString(string value)
    {
        var allocation = new SafeHGlobalHandle(value);
        _allocations.Add(allocation);
        return allocation.Pointer;
    }

    public nint AllocateBytes(ReadOnlySpan<byte> value)
    {
        var allocation = new SafeHGlobalHandle(value.Length);
        _allocations.Add(allocation);
        Marshal.Copy(value.ToArray(), 0, allocation.Pointer, value.Length);
        return allocation.Pointer;
    }

    public nint AllocateStruct<T>(T value)
        where T : struct
    {
        var allocation = new SafeHGlobalHandle(Marshal.SizeOf<T>());
        _allocations.Add(allocation);
        Marshal.StructureToPtr(value, allocation.Pointer, fDeleteOld: false);
        return allocation.Pointer;
    }

    public void Dispose()
    {
        foreach (var allocation in _allocations.AsEnumerable().Reverse())
        {
            allocation.Dispose();
        }

        _allocations.Clear();
    }
}
