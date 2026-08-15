using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace DistractionFirewall.Core.Targets;

public sealed partial class TargetCatalog
{
    private const int MaximumTargets = 64;
    private const int MaximumHostsPerField = 256;
    private const int MaximumBrowserPatterns = 512;
    private const int MaximumCollateralEntries = 128;
    private const int MaximumCoverageEntries = 64;
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();
    private readonly Dictionary<string, TargetDefinition> _targets;

    public TargetCatalog(IEnumerable<TargetDefinition> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var materialized = targets.ToArray();
        if (materialized.Length is 0 or > MaximumTargets)
        {
            throw new InvalidDataException(
                $"The target catalog must contain between 1 and {MaximumTargets} targets.");
        }

        var validated = materialized.Select(ValidateAndNormalize).ToArray();
        if (validated.Select(target => target.StableId).Distinct(StringComparer.Ordinal).Count() != validated.Length)
        {
            throw new InvalidDataException("Target stable IDs must be unique.");
        }

        _targets = validated.ToDictionary(target => target.StableId, StringComparer.Ordinal);
        var catalogVersions = validated.Select(target => target.CatalogVersion).Distinct(StringComparer.Ordinal).ToArray();
        if (catalogVersions.Length != 1)
        {
            throw new InvalidDataException("All targets in one catalog file must have the same catalog version.");
        }

        CatalogVersion = catalogVersions[0];
    }

    public string CatalogVersion { get; }

    public IReadOnlyCollection<TargetDefinition> Targets => _targets.Values;

    public static async Task<TargetCatalog> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        await using var stream = File.OpenRead(path);
        var document = await JsonSerializer.DeserializeAsync<TargetDefinition[]>(
            stream,
            SerializerOptions,
            cancellationToken).ConfigureAwait(false);
        return new TargetCatalog(document ?? throw new InvalidDataException("The target catalog is empty."));
    }

    public TargetDefinition GetRequired(string stableId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stableId);
        return _targets.TryGetValue(stableId, out var target)
            ? target
            : throw new KeyNotFoundException($"Target '{stableId}' does not exist in catalog {CatalogVersion}.");
    }

    public IReadOnlyList<TargetDefinition> Resolve(IEnumerable<string> stableIds)
    {
        ArgumentNullException.ThrowIfNull(stableIds);
        var ids = stableIds.Distinct(StringComparer.Ordinal).ToArray();
        if (ids.Length == 0)
        {
            throw new InvalidDataException("At least one target must be selected.");
        }

        return ids.Select(GetRequired).ToArray();
    }

    public static string ComputeDefinitionHash(IEnumerable<TargetDefinition> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var canonicalTargets = targets
            .OrderBy(target => target.StableId, StringComparer.Ordinal)
            .Select(target => new
            {
                target.StableId,
                target.CatalogVersion,
                ExactHosts = target.ExactHosts.Order(StringComparer.Ordinal),
                SuffixHosts = target.SuffixHosts.Order(StringComparer.Ordinal),
                CnameSuffixes = target.CnameSuffixes.Order(StringComparer.Ordinal),
                SeedHosts = target.SeedHosts.Order(StringComparer.Ordinal),
                BrowserUrlPatterns = target.BrowserUrlPatterns.Order(StringComparer.Ordinal),
                target.IpBlockPolicy,
            });
        var canonicalJson = JsonSerializer.Serialize(canonicalTargets, SerializerOptions);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson)));
    }

    private static TargetDefinition ValidateAndNormalize(TargetDefinition target)
    {
        ArgumentNullException.ThrowIfNull(target);
        ValidatePatternedString(target.StableId, "stable_id", 1, 64, StableIdPattern());
        ValidatePatternedString(target.DisplayName, "display_name", 1, 128, NonWhitespacePattern());
        ValidatePatternedString(target.CatalogVersion, "catalog_version", 1, 64, CatalogVersionPattern());
        ValidateOptionalString(target.Description, "description", 512, target.StableId);

        var exactHosts = NormalizeHostList(target.ExactHosts, "exact_hosts", target.StableId);
        var suffixHosts = NormalizeHostList(target.SuffixHosts, "suffix_hosts", target.StableId);
        var cnameSuffixes = NormalizeHostList(target.CnameSuffixes, "cname_suffixes", target.StableId);
        var seedHosts = NormalizeHostList(target.SeedHosts, "seed_hosts", target.StableId);
        var browserPatterns = NormalizeBrowserPatterns(
            target.BrowserUrlPatterns,
            "browser_url_patterns",
            target.StableId);

        if (exactHosts.Length == 0 &&
            suffixHosts.Length == 0 &&
            cnameSuffixes.Length == 0 &&
            browserPatterns.Length == 0)
        {
            throw new InvalidDataException($"Target '{target.StableId}' has no match rules.");
        }

        ValidateSeedHosts(target.StableId, seedHosts, exactHosts, suffixHosts);
        var ipBlockPolicy = ValidateIpPolicy(target.StableId, target.IpBlockPolicy, seedHosts.Length > 0);
        var knownCollateral = ValidateKnownCollateral(
            target.StableId,
            target.KnownCollateral,
            exactHosts,
            suffixHosts,
            cnameSuffixes,
            seedHosts,
            browserPatterns,
            ipBlockPolicy);
        var coverage = ValidateCoverage(target.Coverage, target.StableId);

        return target with
        {
            ExactHosts = exactHosts,
            SuffixHosts = suffixHosts,
            CnameSuffixes = cnameSuffixes,
            SeedHosts = seedHosts,
            BrowserUrlPatterns = browserPatterns,
            IpBlockPolicy = ipBlockPolicy,
            KnownCollateral = knownCollateral,
            Coverage = coverage,
        };
    }

    private static string[] NormalizeHostList(
        IReadOnlyCollection<string> hosts,
        string fieldName,
        string stableId)
    {
        if (hosts is null || hosts.Count > MaximumHostsPerField)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' {fieldName} must contain at most {MaximumHostsPerField} hosts.");
        }

        var normalized = new string[hosts.Count];
        var index = 0;
        foreach (var host in hosts)
        {
            if (host is null ||
                GetUnicodeLength(host) is < 3 or > 253 ||
                !HostnamePattern().IsMatch(host))
            {
                throw new InvalidDataException(
                    $"Target '{stableId}' contains an invalid canonical hostname in {fieldName}.");
            }

            string canonicalHost;
            try
            {
                canonicalHost = DomainNameNormalizer.Normalize(host);
            }
            catch (Exception exception) when (exception is ArgumentException or FormatException)
            {
                throw new InvalidDataException(
                    $"Target '{stableId}' contains an invalid hostname in {fieldName}.",
                    exception);
            }

            if (!string.Equals(host, canonicalHost, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Target '{stableId}' contains a non-canonical hostname in {fieldName}.");
            }

            normalized[index++] = canonicalHost;
        }

        if (normalized.Distinct(StringComparer.Ordinal).Count() != normalized.Length)
        {
            throw new InvalidDataException($"Target '{stableId}' contains a duplicate in {fieldName}.");
        }

        return normalized.Order(StringComparer.Ordinal).ToArray();
    }

    private static string[] NormalizeBrowserPatterns(
        IReadOnlyCollection<string> values,
        string fieldName,
        string stableId)
    {
        if (values is null || values.Count > MaximumBrowserPatterns)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' {fieldName} must contain at most {MaximumBrowserPatterns} patterns.");
        }

        var normalized = values.ToArray();
        if (normalized.Any(value =>
                value is null ||
                GetUnicodeLength(value) is < 7 or > 2048 ||
                !BrowserUrlPattern().IsMatch(value)) ||
            normalized.Distinct(StringComparer.Ordinal).Count() != normalized.Length)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' contains an invalid or duplicate {fieldName} rule.");
        }

        return normalized.Order(StringComparer.Ordinal).ToArray();
    }

    private static string[] ValidateCoverage(IReadOnlyCollection<string> coverage, string stableId)
    {
        if (coverage is null || coverage.Count > MaximumCoverageEntries)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' coverage must contain at most {MaximumCoverageEntries} entries.");
        }

        var values = coverage.ToArray();
        if (values.Any(value =>
                value is null ||
                GetUnicodeLength(value) is < 1 or > 128 ||
                !NonWhitespacePattern().IsMatch(value)) ||
            values.Distinct(StringComparer.Ordinal).Count() != values.Length)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' contains an invalid or duplicate coverage entry.");
        }

        return values.Order(StringComparer.Ordinal).ToArray();
    }

    private static IpBlockPolicyDefinition ValidateIpPolicy(
        string stableId,
        IpBlockPolicyDefinition policy,
        bool hasSeedHosts)
    {
        if (policy is null)
        {
            throw new InvalidDataException($"Target '{stableId}' has no IP block policy.");
        }

        if (policy.Mode == IpBlockMode.Disabled)
        {
            if (policy.HasAnyDnsObservedSetting)
            {
                throw new InvalidDataException(
                    $"Target '{stableId}' disabled IP policy may only contain mode.");
            }

            return policy;
        }

        if (policy.Mode != IpBlockMode.DnsObserved || !policy.HasAllDnsObservedSettings)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' has an incomplete or unsupported IP block policy.");
        }

        if (policy.MaxObservationTtlSeconds is < 60 or > 86400 ||
            policy.SourceFields.Count is < 1 or > 4 ||
            policy.AddressFamilies.Count is < 1 or > 2 ||
            policy.TransportProtocols.Count is < 1 or > 2 ||
            policy.SourceFields.Distinct(StringComparer.Ordinal).Count() != policy.SourceFields.Count ||
            policy.AddressFamilies.Distinct(StringComparer.Ordinal).Count() != policy.AddressFamilies.Count ||
            policy.TransportProtocols.Distinct(StringComparer.Ordinal).Count() != policy.TransportProtocols.Count)
        {
            throw new InvalidDataException($"Target '{stableId}' has an invalid DNS-observed IP policy.");
        }

        var sourceFields = new HashSet<string>(
            ["exact_hosts", "suffix_hosts", "cname_suffixes", "seed_hosts"],
            StringComparer.Ordinal);
        var addressFamilies = new HashSet<string>(["ipv4", "ipv6"], StringComparer.Ordinal);
        var transports = new HashSet<string>(["tcp", "udp"], StringComparer.Ordinal);
        if (policy.SourceFields.Any(field => !sourceFields.Contains(field)) ||
            policy.AddressFamilies.Any(family => !addressFamilies.Contains(family)) ||
            policy.TransportProtocols.Any(protocol => !transports.Contains(protocol)) ||
            policy.SharedAddressAction is not (
                SharedAddressAction.Block or
                SharedAddressAction.Observe or
                SharedAddressAction.DnsBrowserOnly))
        {
            throw new InvalidDataException($"Target '{stableId}' has an unsupported DNS-observed IP policy value.");
        }

        var usesSeedHosts = policy.SourceFields.Contains("seed_hosts", StringComparer.Ordinal);
        if (usesSeedHosts != hasSeedHosts)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' must declare seed_hosts and its source field together.");
        }

        return policy with
        {
            SourceFields = policy.SourceFields.Order(StringComparer.Ordinal).ToArray(),
            AddressFamilies = policy.AddressFamilies.Order(StringComparer.Ordinal).ToArray(),
            TransportProtocols = policy.TransportProtocols.Order(StringComparer.Ordinal).ToArray(),
        };
    }

    private static void ValidateSeedHosts(
        string stableId,
        IReadOnlyCollection<string> seedHosts,
        IReadOnlyCollection<string> exactHosts,
        IReadOnlyCollection<string> suffixHosts)
    {
        foreach (var seedHost in seedHosts)
        {
            var covered = exactHosts.Contains(seedHost, StringComparer.Ordinal) || suffixHosts.Any(suffix =>
                string.Equals(seedHost, suffix, StringComparison.Ordinal) ||
                seedHost.EndsWith("." + suffix, StringComparison.Ordinal));
            if (!covered)
            {
                throw new InvalidDataException(
                    $"Target '{stableId}' seed host '{seedHost}' is not covered by an exact or suffix host rule.");
            }
        }
    }

    private static KnownCollateralDefinition[] ValidateKnownCollateral(
        string stableId,
        IReadOnlyCollection<KnownCollateralDefinition> entries,
        IReadOnlyCollection<string> exactHosts,
        IReadOnlyCollection<string> suffixHosts,
        IReadOnlyCollection<string> cnameSuffixes,
        IReadOnlyCollection<string> seedHosts,
        IReadOnlyCollection<string> browserPatterns,
        IpBlockPolicyDefinition ipBlockPolicy)
    {
        if (entries is null || entries.Count > MaximumCollateralEntries)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' known_collateral must contain at most {MaximumCollateralEntries} entries.");
        }

        var normalized = entries.Select(entry =>
        {
            if (entry is null)
            {
                throw new InvalidDataException($"Target '{stableId}' contains a null collateral entry.");
            }

            ValidateCollateralString(entry.RuleValue, "rule_value", 1, 2048, stableId, requireContent: false);
            ValidateCollateralString(entry.Purpose, "purpose", 1, 512, stableId, requireContent: true);
            ValidateCollateralString(entry.Risk, "risk", 1, 1024, stableId, requireContent: true);
            ValidateCollateralString(entry.Mitigation, "mitigation", 1, 1024, stableId, requireContent: true);
            if (entry.Severity is not ("low" or "medium" or "high"))
            {
                throw new InvalidDataException(
                    $"Target '{stableId}' contains an unsupported collateral severity.");
            }

            var normalizedRuleValue = entry.RuleField switch
            {
                "exact_hosts" => NormalizeCollateralHostReference(
                    entry.RuleValue,
                    exactHosts,
                    entry.RuleField,
                    stableId),
                "suffix_hosts" => NormalizeCollateralHostReference(
                    entry.RuleValue,
                    suffixHosts,
                    entry.RuleField,
                    stableId),
                "cname_suffixes" => NormalizeCollateralHostReference(
                    entry.RuleValue,
                    cnameSuffixes,
                    entry.RuleField,
                    stableId),
                "seed_hosts" => NormalizeCollateralHostReference(
                    entry.RuleValue,
                    seedHosts,
                    entry.RuleField,
                    stableId),
                "browser_url_patterns" when browserPatterns.Contains(entry.RuleValue, StringComparer.Ordinal) =>
                    entry.RuleValue,
                "ip_block_policy" when string.Equals(
                    entry.RuleValue,
                    GetIpPolicyReference(ipBlockPolicy),
                    StringComparison.Ordinal) => entry.RuleValue,
                "browser_url_patterns" or "ip_block_policy" => throw new InvalidDataException(
                    $"Target '{stableId}' collateral reference '{entry.RuleField}' does not resolve."),
                _ => throw new InvalidDataException(
                    $"Target '{stableId}' contains an unsupported collateral rule_field."),
            };

            return entry with { RuleValue = normalizedRuleValue };
        }).ToArray();

        if (normalized.Distinct().Count() != normalized.Length)
        {
            throw new InvalidDataException($"Target '{stableId}' contains duplicate collateral entries.");
        }

        return normalized;
    }

    private static string NormalizeCollateralHostReference(
        string value,
        IReadOnlyCollection<string> rules,
        string fieldName,
        string stableId)
    {
        string normalized;
        try
        {
            normalized = DomainNameNormalizer.Normalize(value);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' collateral reference '{fieldName}' is not a hostname.",
                exception);
        }

        if (!rules.Contains(normalized, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                $"Target '{stableId}' collateral reference '{fieldName}' does not resolve.");
        }

        return normalized;
    }

    private static string GetIpPolicyReference(IpBlockPolicyDefinition policy) => policy.Mode switch
    {
        IpBlockMode.Disabled => "disabled",
        IpBlockMode.DnsObserved =>
            $"dns_observed/shared_address_action={GetSharedAddressActionName(policy.SharedAddressAction)}",
        _ => throw new InvalidDataException("The IP block policy mode is unsupported."),
    };

    private static string GetSharedAddressActionName(SharedAddressAction action) => action switch
    {
        SharedAddressAction.Block => "block",
        SharedAddressAction.Observe => "observe",
        SharedAddressAction.DnsBrowserOnly => "dns_browser_only",
        _ => throw new InvalidDataException("The shared-address action is unsupported."),
    };

    private static void ValidatePatternedString(
        string value,
        string fieldName,
        int minimumLength,
        int maximumLength,
        Regex pattern)
    {
        if (value is null ||
            GetUnicodeLength(value) < minimumLength ||
            GetUnicodeLength(value) > maximumLength ||
            !pattern.IsMatch(value))
        {
            throw new InvalidDataException($"Target {fieldName} does not satisfy the version 1 catalog contract.");
        }
    }

    private static void ValidateOptionalString(
        string value,
        string fieldName,
        int maximumLength,
        string stableId)
    {
        if (value is null || GetUnicodeLength(value) > maximumLength)
        {
            throw new InvalidDataException(
                $"Target '{stableId}' {fieldName} exceeds the version 1 catalog limit.");
        }
    }

    private static void ValidateCollateralString(
        string value,
        string fieldName,
        int minimumLength,
        int maximumLength,
        string stableId,
        bool requireContent)
    {
        if (value is null ||
            GetUnicodeLength(value) < minimumLength ||
            GetUnicodeLength(value) > maximumLength ||
            (requireContent && !NonWhitespacePattern().IsMatch(value)))
        {
            throw new InvalidDataException(
                $"Target '{stableId}' contains an invalid collateral {fieldName}.");
        }
    }

    private static int GetUnicodeLength(string value) => value.EnumerateRunes().Count();

    [GeneratedRegex("^[a-z](?:[a-z0-9]|[._-](?=[a-z0-9]))*$", RegexOptions.CultureInvariant)]
    private static partial Regex StableIdPattern();

    [GeneratedRegex(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*))(?:\\.(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex CatalogVersionPattern();

    [GeneratedRegex(
        "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex HostnamePattern();

    [GeneratedRegex(
        "^(?:\\*|https?)://(?:\\*\\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/[^\\s]*$",
        RegexOptions.CultureInvariant)]
    private static partial Regex BrowserUrlPattern();

    [GeneratedRegex("\\S", RegexOptions.CultureInvariant)]
    private static partial Regex NonWhitespacePattern();

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.SnakeCaseLower,
            allowIntegerValues: false));
        return options;
    }
}
