using System.Text.Json.Serialization;

namespace DistractionFirewall.Core.Targets;

public enum IpBlockMode
{
    Disabled,
    DnsObserved,
}

public enum SharedAddressAction
{
    Block,
    Observe,
    DnsBrowserOnly,
}

public sealed record IpBlockPolicyDefinition
{
    private IReadOnlyList<string> _sourceFields = Array.Empty<string>();
    private IReadOnlyList<string> _addressFamilies = Array.Empty<string>();
    private IReadOnlyList<string> _transportProtocols = Array.Empty<string>();
    private bool _followCnameChain;
    private int _maxObservationTtlSeconds;
    private SharedAddressAction _sharedAddressAction;

    public required IpBlockMode Mode { get; init; }

    public IReadOnlyList<string> SourceFields
    {
        get => _sourceFields;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _sourceFields = value;
            SourceFieldsSpecified = true;
        }
    }

    public IReadOnlyList<string> AddressFamilies
    {
        get => _addressFamilies;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _addressFamilies = value;
            AddressFamiliesSpecified = true;
        }
    }

    public IReadOnlyList<string> TransportProtocols
    {
        get => _transportProtocols;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _transportProtocols = value;
            TransportProtocolsSpecified = true;
        }
    }

    public bool FollowCnameChain
    {
        get => _followCnameChain;
        init
        {
            _followCnameChain = value;
            FollowCnameChainSpecified = true;
        }
    }

    public int MaxObservationTtlSeconds
    {
        get => _maxObservationTtlSeconds;
        init
        {
            _maxObservationTtlSeconds = value;
            MaxObservationTtlSecondsSpecified = true;
        }
    }

    public SharedAddressAction SharedAddressAction
    {
        get => _sharedAddressAction;
        init
        {
            _sharedAddressAction = value;
            SharedAddressActionSpecified = true;
        }
    }

    internal bool SourceFieldsSpecified { get; private set; }

    internal bool AddressFamiliesSpecified { get; private set; }

    internal bool TransportProtocolsSpecified { get; private set; }

    internal bool FollowCnameChainSpecified { get; private set; }

    internal bool MaxObservationTtlSecondsSpecified { get; private set; }

    internal bool SharedAddressActionSpecified { get; private set; }

    internal bool HasAnyDnsObservedSetting =>
        SourceFieldsSpecified ||
        AddressFamiliesSpecified ||
        TransportProtocolsSpecified ||
        FollowCnameChainSpecified ||
        MaxObservationTtlSecondsSpecified ||
        SharedAddressActionSpecified;

    internal bool HasAllDnsObservedSettings =>
        SourceFieldsSpecified &&
        AddressFamiliesSpecified &&
        TransportProtocolsSpecified &&
        FollowCnameChainSpecified &&
        MaxObservationTtlSecondsSpecified &&
        SharedAddressActionSpecified;
}

public sealed record KnownCollateralDefinition
{
    public required string RuleField { get; init; }

    public required string RuleValue { get; init; }

    public required string Purpose { get; init; }

    public required string Severity { get; init; }

    public required string Risk { get; init; }

    public required string Mitigation { get; init; }
}

public sealed record TargetDefinition
{
    public required string StableId { get; init; }

    public required string DisplayName { get; init; }

    public string Description { get; init; } = string.Empty;

    public required string CatalogVersion { get; init; }

    public required IReadOnlyList<string> ExactHosts { get; init; }

    public required IReadOnlyList<string> SuffixHosts { get; init; }

    public required IReadOnlyList<string> CnameSuffixes { get; init; }

    public IReadOnlyList<string> SeedHosts { get; init; } = Array.Empty<string>();

    public required IReadOnlyList<string> BrowserUrlPatterns { get; init; }

    public required IpBlockPolicyDefinition IpBlockPolicy { get; init; }

    [JsonRequired]
    public IReadOnlyList<KnownCollateralDefinition> KnownCollateral { get; init; } = Array.Empty<KnownCollateralDefinition>();

    public IReadOnlyList<string> Coverage { get; init; } = Array.Empty<string>();
}
