using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Dns;

internal enum DnsAddressFamily
{
    IPv4,
    IPv6,
}

internal enum DnsConfigurationOrigin
{
    Static,
    Dhcp,
    Unknown,
}

internal sealed record DnsInterfaceSettingsState
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }

    public required Guid InterfaceId { get; init; }

    public required DnsAddressFamily AddressFamily { get; init; }

    public required DnsConfigurationOrigin Origin { get; init; }

    public required IReadOnlyList<string> NameServers { get; init; }
}

internal readonly record struct DnsInterfaceResourceId(Guid InterfaceId, DnsAddressFamily AddressFamily)
{
    private const string Prefix = "dns-interface:";

    public override string ToString()
    {
        return Prefix + InterfaceId.ToString("D") + ":" +
            (AddressFamily == DnsAddressFamily.IPv4 ? "ipv4" : "ipv6");
    }

    public static DnsInterfaceResourceId Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new FormatException("DNS resource identifier has an invalid prefix.");
        }

        var separator = value.LastIndexOf(':');
        if (separator <= Prefix.Length || separator == value.Length - 1)
        {
            throw new FormatException("DNS resource identifier is invalid.");
        }

        if (!Guid.TryParseExact(value[Prefix.Length..separator], "D", out var interfaceId))
        {
            throw new FormatException("DNS resource identifier has an invalid interface GUID.");
        }

        var family = value[(separator + 1)..] switch
        {
            "ipv4" => DnsAddressFamily.IPv4,
            "ipv6" => DnsAddressFamily.IPv6,
            _ => throw new FormatException("DNS resource identifier has an invalid address family."),
        };
        return new DnsInterfaceResourceId(interfaceId, family);
    }
}

internal static class DnsSettingsStateCodec
{
    public const string ContentType = "windows-dns/interface-settings-v1";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static OwnedResourceState Encode(DnsInterfaceSettingsState settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var canonical = Canonicalize(settings);
        return OwnedResourceState.Present(
            ContentType,
            JsonSerializer.SerializeToUtf8Bytes(canonical, SerializerOptions));
    }

    public static DnsInterfaceSettingsState Decode(OwnedResourceState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.Exists || !string.Equals(state.ContentType, ContentType, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Ownership state is not a DNS interface settings snapshot.");
        }

        var decoded = JsonSerializer.Deserialize<DnsInterfaceSettingsState>(state.Data, SerializerOptions)
            ?? throw new InvalidDataException("DNS interface settings snapshot is invalid.");
        if (decoded.SchemaVersion != DnsInterfaceSettingsState.CurrentSchemaVersion)
        {
            throw new InvalidDataException("DNS interface settings snapshot schema is unsupported.");
        }

        return Canonicalize(decoded);
    }

    public static bool Equivalent(OwnedResourceState left, OwnedResourceState right)
    {
        if (!left.Exists || !right.Exists)
        {
            return left.Exists == right.Exists;
        }

        if (!string.Equals(left.ContentType, ContentType, StringComparison.Ordinal)
            || !string.Equals(right.ContentType, ContentType, StringComparison.Ordinal))
        {
            return false;
        }

        var leftSettings = Decode(left);
        var rightSettings = Decode(right);
        return leftSettings.InterfaceId == rightSettings.InterfaceId
            && leftSettings.AddressFamily == rightSettings.AddressFamily
            && leftSettings.Origin == rightSettings.Origin
            && leftSettings.NameServers.SequenceEqual(rightSettings.NameServers, StringComparer.OrdinalIgnoreCase);
    }

    public static DnsInterfaceSettingsState CreateLoopback(
        Guid interfaceId,
        DnsAddressFamily addressFamily)
    {
        return new DnsInterfaceSettingsState
        {
            SchemaVersion = DnsInterfaceSettingsState.CurrentSchemaVersion,
            InterfaceId = interfaceId,
            AddressFamily = addressFamily,
            Origin = DnsConfigurationOrigin.Static,
            NameServers =
            [
                addressFamily == DnsAddressFamily.IPv4
                    ? IPAddress.Loopback.ToString()
                    : IPAddress.IPv6Loopback.ToString(),
            ],
        };
    }

    private static DnsInterfaceSettingsState Canonicalize(DnsInterfaceSettingsState settings)
    {
        if (settings.InterfaceId == Guid.Empty)
        {
            throw new InvalidDataException("DNS interface settings snapshot has an empty interface GUID.");
        }

        var expectedFamily = settings.AddressFamily == DnsAddressFamily.IPv4
            ? AddressFamily.InterNetwork
            : AddressFamily.InterNetworkV6;
        var addresses = settings.NameServers
            .Select(address => IPAddress.TryParse(address, out var parsed)
                ? parsed
                : throw new InvalidDataException("DNS interface settings snapshot contains an invalid IP address."))
            .Where(address => address.AddressFamily == expectedFamily)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (addresses.Length != settings.NameServers.Count)
        {
            throw new InvalidDataException(
                "DNS interface settings snapshot contains a duplicate or wrong-family address.");
        }

        if (addresses.Length == 0 && settings.Origin != DnsConfigurationOrigin.Unknown)
        {
            throw new InvalidDataException(
                "Static and DHCP DNS snapshots require at least one effective nameserver.");
        }

        return settings with
        {
            SchemaVersion = DnsInterfaceSettingsState.CurrentSchemaVersion,
            NameServers = addresses,
        };
    }
}
