namespace DistractionFirewall.Core.Targets;

public sealed class TargetMatcher
{
    private readonly HashSet<string> _exactHosts;
    private readonly string[] _suffixHosts;
    private readonly string[] _cnameSuffixes;

    public TargetMatcher(IEnumerable<TargetDefinition> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);

        var materialized = targets.ToArray();
        _exactHosts = materialized
            .SelectMany(target => target.ExactHosts)
            .Select(DomainNameNormalizer.Normalize)
            .ToHashSet(StringComparer.Ordinal);
        _suffixHosts = materialized
            .SelectMany(target => target.SuffixHosts)
            .Select(DomainNameNormalizer.Normalize)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        _cnameSuffixes = materialized
            .SelectMany(target => target.CnameSuffixes)
            .Select(DomainNameNormalizer.Normalize)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    public bool MatchesHost(string host)
    {
        var normalized = DomainNameNormalizer.Normalize(host);
        return _exactHosts.Contains(normalized) || MatchesAnySuffix(normalized, _suffixHosts);
    }

    public bool MatchesCname(string host)
    {
        var normalized = DomainNameNormalizer.Normalize(host);
        return MatchesAnySuffix(normalized, _cnameSuffixes);
    }

    private static bool MatchesAnySuffix(string host, IEnumerable<string> suffixes) =>
        suffixes.Any(suffix =>
            host.Equals(suffix, StringComparison.Ordinal) ||
            host.EndsWith('.' + suffix, StringComparison.Ordinal));
}
