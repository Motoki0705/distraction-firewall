using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Wfp;

internal static class WfpProductConstants
{
    public static readonly Guid ProviderKey = new("f04e437b-4c16-49ca-8e6c-4d9471d6b509");
    public static readonly Guid SubLayerKey = new("60dc8631-a160-420b-ae90-d1b461efe293");
    public static readonly Guid AleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid AleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static readonly Guid OutboundTransportV4 = new("09e61aea-d214-46e2-9b21-b26b0b2f28c8");
    public static readonly Guid OutboundTransportV6 = new("e1735bde-013f-4655-b351-a49e15762df0");
    public static readonly Guid ConditionIpRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    public const ushort SubLayerWeight = 0xE000;
}

internal sealed record WfpFilterSpec
{
    public required Guid FilterKey { get; init; }

    public required Guid LayerKey { get; init; }

    public required string Address { get; init; }

    public IPAddress ParseAddress()
    {
        var address = IPAddress.Parse(Address);
        var supportedLayers = address.AddressFamily == AddressFamily.InterNetwork
            ? new[] { WfpProductConstants.AleAuthConnectV4, WfpProductConstants.OutboundTransportV4 }
            : address.AddressFamily == AddressFamily.InterNetworkV6
                ? new[] { WfpProductConstants.AleAuthConnectV6, WfpProductConstants.OutboundTransportV6 }
                : throw new InvalidOperationException($"Unsupported address family for '{Address}'.");
        if (!supportedLayers.Contains(LayerKey))
        {
            throw new InvalidDataException("WFP filter layer does not match its address family.");
        }

        return address;
    }

    public static IReadOnlyList<WfpFilterSpec> CreateForAddress(Guid leaseId, IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var normalized = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => address.MapToIPv4(),
            AddressFamily.InterNetworkV6 => address.MapToIPv6(),
            _ => throw new ArgumentException("Only IPv4 and IPv6 addresses can be blocked.", nameof(address)),
        };
        var layerKeys = normalized.AddressFamily == AddressFamily.InterNetwork
            ? new[] { WfpProductConstants.AleAuthConnectV4, WfpProductConstants.OutboundTransportV4 }
            : new[] { WfpProductConstants.AleAuthConnectV6, WfpProductConstants.OutboundTransportV6 };
        return layerKeys.Select(layerKey => CreateForLayer(leaseId, normalized, layerKey)).ToArray();
    }

    public static WfpFilterSpec CreateForLayer(Guid leaseId, IPAddress address, Guid layerKey)
    {
        ArgumentNullException.ThrowIfNull(address);
        var normalized = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => address.MapToIPv4(),
            AddressFamily.InterNetworkV6 => address.MapToIPv6(),
            _ => throw new ArgumentException("Only IPv4 and IPv6 addresses can be blocked.", nameof(address)),
        };
        var identity = string.Join('|', leaseId.ToString("N"), layerKey.ToString("N"), normalized.ToString());
        var result = new WfpFilterSpec
        {
            FilterKey = CreateDeterministicGuid(identity),
            LayerKey = layerKey,
            Address = normalized.ToString(),
        };
        _ = result.ParseAddress();
        return result;
    }

    private static Guid CreateDeterministicGuid(string identity)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
        Span<byte> guidBytes = stackalloc byte[16];
        hash.AsSpan(0, guidBytes.Length).CopyTo(guidBytes);
        guidBytes[7] = (byte)((guidBytes[7] & 0x0F) | 0x80);
        guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80);
        return new Guid(guidBytes);
    }
}

internal static class WfpFilterSpecCodec
{
    private const string ContentType = "wfp/exact-remote-address-filter-v1";

    public static OwnedResourceState Encode(WfpFilterSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return OwnedResourceState.Present(ContentType, JsonSerializer.SerializeToUtf8Bytes(spec));
    }

    public static WfpFilterSpec Decode(OwnedResourceState state)
    {
        if (!state.Exists || !string.Equals(state.ContentType, ContentType, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Ownership state is not a WFP exact-address filter.");
        }

        return JsonSerializer.Deserialize<WfpFilterSpec>(state.Data)
            ?? throw new InvalidDataException("WFP filter ownership state is invalid.");
    }

    public static string ResourceId(WfpFilterSpec spec)
    {
        return "wfp-filter:" + spec.FilterKey.ToString("D");
    }
}
