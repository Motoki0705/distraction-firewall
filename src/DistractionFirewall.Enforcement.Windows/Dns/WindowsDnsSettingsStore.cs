using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Wfp;

namespace DistractionFirewall.Enforcement.Windows.Dns;

internal interface IWindowsDnsSettingsStore : ICompareExchangeResourceStore
{
    bool CheckAvailable(out string summary);

    ValueTask<IReadOnlyList<DnsInterfaceSettingsState>> EnumerateActiveAsync(
        CancellationToken cancellationToken);
}

internal sealed class WindowsDnsSettingsStore : IWindowsDnsSettingsStore, IPostWriteVerificationStore
{
    private readonly WindowsMutationGate _mutationGate;

    public WindowsDnsSettingsStore(WindowsMutationGate mutationGate)
    {
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
    }

    public bool CheckAvailable(out string summary)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) || nint.Size != sizeof(long))
        {
            summary = "The native DNS adapter requires Windows 11 x64.";
            return false;
        }

        if (!NativeLibrary.TryLoad("iphlpapi.dll", out var library))
        {
            summary = "iphlpapi.dll is unavailable.";
            return false;
        }

        try
        {
            var available = NativeLibrary.TryGetExport(library, "GetInterfaceDnsSettings", out _)
                && NativeLibrary.TryGetExport(library, "SetInterfaceDnsSettings", out _)
                && NativeLibrary.TryGetExport(library, "FreeInterfaceDnsSettings", out _);
            summary = available
                ? "GetInterfaceDnsSettings and SetInterfaceDnsSettings are available."
                : "The required Windows DNS interface APIs are unavailable.";
            return available;
        }
        finally
        {
            NativeLibrary.Free(library);
        }
    }

    public ValueTask<IReadOnlyList<DnsInterfaceSettingsState>> EnumerateActiveAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshots = new List<DnsInterfaceSettingsState>();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces()
                     .OrderBy(item => item.Id, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsActiveNonLoopback(networkInterface)
                || !Guid.TryParse(networkInterface.Id, out var interfaceId))
            {
                continue;
            }

            var properties = networkInterface.GetIPProperties();
            var configuredSettings = ReadConfiguredSettings(interfaceId);
            AddFamilySnapshot(
                snapshots,
                interfaceId,
                DnsAddressFamily.IPv4,
                properties,
                configuredSettings);
            AddFamilySnapshot(
                snapshots,
                interfaceId,
                DnsAddressFamily.IPv6,
                properties,
                configuredSettings);
        }

        return ValueTask.FromResult<IReadOnlyList<DnsInterfaceSettingsState>>(snapshots);
    }

    public ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var id = DnsInterfaceResourceId.Parse(resourceId);
        var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(item => Guid.TryParse(item.Id, out var candidate) && candidate == id.InterfaceId);
        if (networkInterface is null)
        {
            return ValueTask.FromResult(OwnedResourceState.Missing);
        }

        var properties = networkInterface.GetIPProperties();
        var configured = ReadConfiguredSettings(id.InterfaceId);
        var state = CreateFamilySnapshot(
            id.InterfaceId,
            id.AddressFamily,
            properties.DnsAddresses,
            configured);
        return ValueTask.FromResult(DnsSettingsStateCodec.Encode(state));
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return DnsSettingsStateCodec.Equivalent(left, right);
    }

    public bool ReplacementWasApplied(
        OwnedResourceState actual,
        OwnedResourceState replacement)
    {
        if (!actual.Exists || !replacement.Exists)
        {
            return StatesEqual(actual, replacement);
        }

        var replacementSettings = DnsSettingsStateCodec.Decode(replacement);
        if (replacementSettings.Origin != DnsConfigurationOrigin.Dhcp)
        {
            return StatesEqual(actual, replacement);
        }

        var actualSettings = DnsSettingsStateCodec.Decode(actual);
        return actualSettings.InterfaceId == replacementSettings.InterfaceId
            && actualSettings.AddressFamily == replacementSettings.AddressFamily
            && actualSettings.Origin == DnsConfigurationOrigin.Dhcp
            && actualSettings.NameServers.Count > 0;
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        _mutationGate.Demand();
        cancellationToken.ThrowIfCancellationRequested();
        var id = DnsInterfaceResourceId.Parse(resourceId);
        var current = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        if (!expected.Exists || !replacement.Exists)
        {
            throw new InvalidOperationException("A DNS interface mutation cannot create or delete an interface.");
        }

        var expectedSettings = DnsSettingsStateCodec.Decode(expected);
        var replacementSettings = DnsSettingsStateCodec.Decode(replacement);
        ValidateMatchesResource(id, expectedSettings);
        ValidateMatchesResource(id, replacementSettings);
        var mutation = DnsSettingsMutationPlan.Create(expectedSettings, replacementSettings);
        SetNameServers(id, mutation.NameServers);
        FlushResolverCacheBestEffort();
        var verified = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!mutation.ResetsToDhcp)
        {
            return StatesEqual(verified, replacement);
        }

        if (!verified.Exists)
        {
            return false;
        }

        var verifiedSettings = DnsSettingsStateCodec.Decode(verified);
        return verifiedSettings.InterfaceId == replacementSettings.InterfaceId
            && verifiedSettings.AddressFamily == replacementSettings.AddressFamily
            && verifiedSettings.Origin == DnsConfigurationOrigin.Dhcp
            && verifiedSettings.NameServers.Count > 0;
    }

    private static bool IsActiveNonLoopback(NetworkInterface networkInterface)
    {
        return networkInterface.OperationalStatus == OperationalStatus.Up
            && networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback;
    }

    private static void AddFamilySnapshot(
        List<DnsInterfaceSettingsState> snapshots,
        Guid interfaceId,
        DnsAddressFamily family,
        IPInterfaceProperties properties,
        NativeConfiguredDnsSettings configuredSettings)
    {
        var snapshot = CreateFamilySnapshot(
            interfaceId,
            family,
            properties.DnsAddresses,
            configuredSettings);
        if (snapshot.NameServers.Count > 0)
        {
            snapshots.Add(snapshot);
        }
    }

    internal static DnsInterfaceSettingsState CreateFamilySnapshot(
        Guid interfaceId,
        DnsAddressFamily family,
        IEnumerable<IPAddress> effectiveNameServers,
        NativeConfiguredDnsSettings configuredSettings)
    {
        var expectedFamily = family == DnsAddressFamily.IPv4
            ? AddressFamily.InterNetwork
            : AddressFamily.InterNetworkV6;
        var staticAddresses = configuredSettings.NameServers
            .Where(address => address.AddressFamily == expectedFamily)
            .Select(address => address.ToString())
            .ToArray();
        var effectiveAddresses = effectiveNameServers
            .Where(address => address.AddressFamily == expectedFamily)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // A family is DHCP only when both native configured fields are empty while Windows
        // reports at least one effective resolver for that family. Profile policy remains
        // ambiguous and is never overwritten.
        var origin = configuredSettings.HasProfileNameServers
            ? DnsConfigurationOrigin.Unknown
            : staticAddresses.Length > 0
                ? DnsConfigurationOrigin.Static
                : effectiveAddresses.Length > 0
                    ? DnsConfigurationOrigin.Dhcp
                    : DnsConfigurationOrigin.Unknown;
        return new DnsInterfaceSettingsState
        {
            SchemaVersion = DnsInterfaceSettingsState.CurrentSchemaVersion,
            InterfaceId = interfaceId,
            AddressFamily = family,
            Origin = origin,
            NameServers = origin == DnsConfigurationOrigin.Static ? staticAddresses : effectiveAddresses,
        };
    }

    private static NativeConfiguredDnsSettings ReadConfiguredSettings(Guid interfaceId)
    {
        // GetInterfaceDnsSettings requires the caller to initialize only Version. Flags is
        // output-only for this API and must remain zero on input.
        var settings = DnsNativeMethods.CreateGetSettings();
        var result = DnsNativeMethods.GetInterfaceDnsSettings(interfaceId, ref settings);
        if (result != DnsNativeMethods.Success)
        {
            throw new Win32Exception((int)result, "GetInterfaceDnsSettings failed.");
        }

        try
        {
            return new NativeConfiguredDnsSettings(
                ParseNameServers(Marshal.PtrToStringUni(settings.NameServer)),
                !string.IsNullOrWhiteSpace(Marshal.PtrToStringUni(settings.ProfileNameServer)));
        }
        finally
        {
            DnsNativeMethods.FreeInterfaceDnsSettings(ref settings);
        }
    }

    private static List<IPAddress> ParseNameServers(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var addresses = new List<IPAddress>();
        foreach (var token in value.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!IPAddress.TryParse(token, out var address))
            {
                throw new InvalidDataException("GetInterfaceDnsSettings returned a non-IP nameserver value.");
            }

            addresses.Add(address);
        }

        return addresses;
    }

    private static void SetNameServers(
        DnsInterfaceResourceId resourceId,
        IReadOnlyList<string> nameServers)
    {
        // An empty managed string is marshalled as a non-null, NUL-terminated UTF-16 string.
        // SetInterfaceDnsSettings interprets that per-family nameserver value as DHCP reset.
        using var names = new SafeHGlobalHandle(string.Join(',', nameServers));
        var settings = new DnsInterfaceSettingsNative
        {
            Version = DnsNativeMethods.SettingsVersion1,
            Flags = DnsNativeMethods.CreateNameServerFlags(resourceId.AddressFamily),
            NameServer = names.Pointer,
        };
        var result = DnsNativeMethods.SetInterfaceDnsSettings(resourceId.InterfaceId, in settings);
        if (result != DnsNativeMethods.Success)
        {
            throw new Win32Exception((int)result, "SetInterfaceDnsSettings failed.");
        }
    }

    private static void FlushResolverCacheBestEffort()
    {
        try
        {
            if (!DnsNativeMethods.DnsFlushResolverCache())
            {
                System.Diagnostics.Trace.TraceWarning(
                    "DnsFlushResolverCache reported failure after a DNS settings mutation.");
            }
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or EntryPointNotFoundException)
        {
            System.Diagnostics.Trace.TraceWarning(
                "DnsFlushResolverCache is unavailable: {0}",
                exception.Message);
        }
    }

    private static void ValidateMatchesResource(
        DnsInterfaceResourceId resourceId,
        DnsInterfaceSettingsState settings)
    {
        if (resourceId.InterfaceId != settings.InterfaceId
            || resourceId.AddressFamily != settings.AddressFamily)
        {
            throw new InvalidDataException("DNS snapshot does not match its ownership resource identifier.");
        }
    }

    internal sealed record NativeConfiguredDnsSettings(
        IReadOnlyList<IPAddress> NameServers,
        bool HasProfileNameServers);
}

internal sealed record DnsSettingsMutationPlan(
    bool ResetsToDhcp,
    IReadOnlyList<string> NameServers)
{
    public static DnsSettingsMutationPlan Create(
        DnsInterfaceSettingsState expected,
        DnsInterfaceSettingsState replacement)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(replacement);
        if (expected.InterfaceId != replacement.InterfaceId
            || expected.AddressFamily != replacement.AddressFamily)
        {
            throw new InvalidDataException("DNS mutation snapshots describe different interface families.");
        }

        if (expected.Origin == DnsConfigurationOrigin.Unknown
            || replacement.Origin == DnsConfigurationOrigin.Unknown)
        {
            throw new InvalidOperationException(
                "DNS mutation was refused because a configured/profile origin is ambiguous.");
        }

        if (replacement.Origin == DnsConfigurationOrigin.Dhcp)
        {
            if (expected.Origin != DnsConfigurationOrigin.Static || !IsLoopback(expected))
            {
                throw new InvalidOperationException(
                    "DHCP reset is permitted only when restoring an owned loopback static setting.");
            }

            return new DnsSettingsMutationPlan(ResetsToDhcp: true, NameServers: []);
        }

        if (replacement.Origin != DnsConfigurationOrigin.Static)
        {
            throw new InvalidOperationException("Unsupported DNS configuration origin transition.");
        }

        if (expected.Origin == DnsConfigurationOrigin.Dhcp && !IsLoopback(replacement))
        {
            throw new InvalidOperationException(
                "A DHCP family may be changed only to the lease-bound loopback DNS setting.");
        }

        return new DnsSettingsMutationPlan(
            ResetsToDhcp: false,
            replacement.NameServers.ToArray());
    }

    private static bool IsLoopback(DnsInterfaceSettingsState settings)
    {
        var expected = settings.AddressFamily == DnsAddressFamily.IPv4
            ? IPAddress.Loopback.ToString()
            : IPAddress.IPv6Loopback.ToString();
        return settings.NameServers.Count == 1
            && string.Equals(settings.NameServers[0], expected, StringComparison.OrdinalIgnoreCase);
    }
}

[StructLayout(LayoutKind.Explicit, Size = 64)]
internal struct DnsInterfaceSettingsNative
{
    [FieldOffset(0)]
    public uint Version;

    [FieldOffset(8)]
    public ulong Flags;

    [FieldOffset(16)]
    public nint Domain;

    [FieldOffset(24)]
    public nint NameServer;

    [FieldOffset(32)]
    public nint SearchList;

    [FieldOffset(40)]
    public uint RegistrationEnabled;

    [FieldOffset(44)]
    public uint RegisterAdapterName;

    [FieldOffset(48)]
    public uint EnableLlmnr;

    [FieldOffset(52)]
    public uint QueryAdapterName;

    [FieldOffset(56)]
    public nint ProfileNameServer;
}

internal static partial class DnsNativeMethods
{
    public const uint Success = 0;
    public const uint SettingsVersion1 = 1;
    public const ulong SettingIPv6 = 0x0001;
    public const ulong SettingNameServer = 0x0002;

    public static ulong CreateNameServerFlags(DnsAddressFamily family)
    {
        return SettingNameServer | (family == DnsAddressFamily.IPv6 ? SettingIPv6 : 0);
    }

    public static DnsInterfaceSettingsNative CreateGetSettings()
    {
        return new DnsInterfaceSettingsNative
        {
            Version = SettingsVersion1,
            Flags = 0,
        };
    }

    [LibraryImport("iphlpapi.dll", EntryPoint = "GetInterfaceDnsSettings")]
    internal static partial uint GetInterfaceDnsSettings(
        Guid interfaceId,
        ref DnsInterfaceSettingsNative settings);

    [LibraryImport("iphlpapi.dll", EntryPoint = "SetInterfaceDnsSettings")]
    internal static partial uint SetInterfaceDnsSettings(
        Guid interfaceId,
        in DnsInterfaceSettingsNative settings);

    [LibraryImport("iphlpapi.dll", EntryPoint = "FreeInterfaceDnsSettings")]
    internal static partial void FreeInterfaceDnsSettings(ref DnsInterfaceSettingsNative settings);

    [LibraryImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DnsFlushResolverCache();
}
