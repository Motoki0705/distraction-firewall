using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using DistractionFirewall.Enforcement.Windows.Dns;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class DnsSettingsCodecTests
{
    [Fact]
    public void SnapshotRoundTripsCanonicalIpAddressesWithoutHostnames()
    {
        var interfaceId = Guid.Parse("918fa959-0c93-4107-902f-306b426236c0");
        var state = CreateState(
            interfaceId,
            DnsAddressFamily.IPv6,
            DnsConfigurationOrigin.Static,
            "2001:0db8:0000:0000:0000:0000:0000:0053");

        var encoded = DnsSettingsStateCodec.Encode(state);
        var decoded = DnsSettingsStateCodec.Decode(encoded);

        Assert.Equal("2001:db8::53", Assert.Single(decoded.NameServers));
        Assert.DoesNotContain("youtube", Encoding.UTF8.GetString(encoded.Data), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SnapshotRejectsDuplicateAndWrongFamilyAddresses()
    {
        var interfaceId = Guid.Parse("0fa26747-f8c5-44f6-a70a-783d42529b56");
        Assert.Throws<InvalidDataException>(() => DnsSettingsStateCodec.Encode(CreateState(
            interfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Static,
            "1.1.1.1",
            "1.1.1.1")));
        Assert.Throws<InvalidDataException>(() => DnsSettingsStateCodec.Encode(CreateState(
            interfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Static,
            "::1")));
    }

    [Fact]
    public void DhcpSnapshotRoundTripsEffectiveResolversAndRejectsEmptyEvidence()
    {
        var interfaceId = Guid.Parse("4bb4d3fe-e50f-4d30-9769-f4ab3bd1e816");
        var state = CreateState(
            interfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp,
            "192.0.2.53");

        var decoded = DnsSettingsStateCodec.Decode(DnsSettingsStateCodec.Encode(state));

        Assert.Equal(DnsConfigurationOrigin.Dhcp, decoded.Origin);
        Assert.Equal("192.0.2.53", Assert.Single(decoded.NameServers));
        Assert.Throws<InvalidDataException>(() => DnsSettingsStateCodec.Encode(CreateState(
            interfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp)));
    }

    [Fact]
    public void NativeSnapshotClassifiesOnlyUnconfiguredEffectiveFamilyAsDhcp()
    {
        var interfaceId = Guid.Parse("ec89ae91-0918-4306-927b-e36d9233ecdc");
        var dhcp = WindowsDnsSettingsStore.CreateFamilySnapshot(
            interfaceId,
            DnsAddressFamily.IPv4,
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("2001:db8::53")],
            new WindowsDnsSettingsStore.NativeConfiguredDnsSettings([], false));
        var profile = WindowsDnsSettingsStore.CreateFamilySnapshot(
            interfaceId,
            DnsAddressFamily.IPv4,
            [IPAddress.Parse("192.0.2.53")],
            new WindowsDnsSettingsStore.NativeConfiguredDnsSettings([], true));
        var configured = WindowsDnsSettingsStore.CreateFamilySnapshot(
            interfaceId,
            DnsAddressFamily.IPv6,
            [IPAddress.Parse("2001:db8::54")],
            new WindowsDnsSettingsStore.NativeConfiguredDnsSettings(
                [IPAddress.Parse("2001:db8::53")],
                false));

        Assert.Equal(DnsConfigurationOrigin.Dhcp, dhcp.Origin);
        Assert.Equal("192.0.2.53", Assert.Single(dhcp.NameServers));
        Assert.Equal(DnsConfigurationOrigin.Unknown, profile.Origin);
        Assert.Equal(DnsConfigurationOrigin.Static, configured.Origin);
        Assert.Equal("2001:db8::53", Assert.Single(configured.NameServers));
    }

    [Theory]
    [InlineData("ipv4", "192.0.2.53", "127.0.0.1", 0x0002UL)]
    [InlineData("ipv6", "2001:db8::53", "::1", 0x0003UL)]
    public void DhcpLoopbackRoundTripUsesEmptyPerFamilyReset(
        string familyName,
        string effectiveResolver,
        string loopback,
        ulong expectedNativeFlags)
    {
        var family = familyName == "ipv4" ? DnsAddressFamily.IPv4 : DnsAddressFamily.IPv6;
        var interfaceId = Guid.Parse("f5874fac-ece8-4eef-9373-2b0760bcacb0");
        var dhcp = CreateState(
            interfaceId,
            family,
            DnsConfigurationOrigin.Dhcp,
            effectiveResolver);
        var loopbackState = CreateState(
            interfaceId,
            family,
            DnsConfigurationOrigin.Static,
            loopback);

        var apply = DnsSettingsMutationPlan.Create(dhcp, loopbackState);
        var restore = DnsSettingsMutationPlan.Create(loopbackState, dhcp);

        Assert.False(apply.ResetsToDhcp);
        Assert.Equal(loopback, Assert.Single(apply.NameServers));
        Assert.True(restore.ResetsToDhcp);
        Assert.Empty(restore.NameServers);
        Assert.Equal(expectedNativeFlags, DnsNativeMethods.CreateNameServerFlags(family));
    }

    [Fact]
    public void ResourceIdRoundTripsOnlyGuidAndKnownFamily()
    {
        var expected = new DnsInterfaceResourceId(
            Guid.Parse("7d08412b-178d-4d8c-a53f-23dbec14013f"),
            DnsAddressFamily.IPv4);

        Assert.Equal(expected, DnsInterfaceResourceId.Parse(expected.ToString()));
        Assert.Throws<FormatException>(() => DnsInterfaceResourceId.Parse(
            "dns-interface:7d08412b-178d-4d8c-a53f-23dbec14013f:any"));
    }

    [Fact]
    public void NativeVersionOneLayoutMatchesWindows11X64Abi()
    {
        Assert.Equal(8, nint.Size);
        Assert.Equal(64, Marshal.SizeOf<DnsInterfaceSettingsNative>());
        Assert.Equal(0, Marshal.OffsetOf<DnsInterfaceSettingsNative>(nameof(DnsInterfaceSettingsNative.Version)).ToInt32());
        Assert.Equal(8, Marshal.OffsetOf<DnsInterfaceSettingsNative>(nameof(DnsInterfaceSettingsNative.Flags)).ToInt32());
        Assert.Equal(16, Marshal.OffsetOf<DnsInterfaceSettingsNative>(nameof(DnsInterfaceSettingsNative.Domain)).ToInt32());
        Assert.Equal(24, Marshal.OffsetOf<DnsInterfaceSettingsNative>(nameof(DnsInterfaceSettingsNative.NameServer)).ToInt32());
        Assert.Equal(56, Marshal.OffsetOf<DnsInterfaceSettingsNative>(nameof(DnsInterfaceSettingsNative.ProfileNameServer)).ToInt32());
        var getInput = DnsNativeMethods.CreateGetSettings();
        Assert.Equal(DnsNativeMethods.SettingsVersion1, getInput.Version);
        Assert.Equal(0UL, getInput.Flags);
    }

    internal static DnsInterfaceSettingsState CreateState(
        Guid interfaceId,
        DnsAddressFamily family,
        DnsConfigurationOrigin origin,
        params string[] nameServers)
    {
        return new DnsInterfaceSettingsState
        {
            SchemaVersion = DnsInterfaceSettingsState.CurrentSchemaVersion,
            InterfaceId = interfaceId,
            AddressFamily = family,
            Origin = origin,
            NameServers = nameServers,
        };
    }
}
