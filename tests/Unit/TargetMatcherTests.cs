using DistractionFirewall.Core.Targets;

namespace DistractionFirewall.UnitTests;

public sealed class TargetMatcherTests
{
    [Theory]
    [InlineData("WWW.YouTube.COM.", "www.youtube.com")]
    [InlineData("例え.テスト", "xn--r8jz45g.xn--zckzah")]
    public void Normalize_returns_canonical_ascii_dns_name(string input, string expected)
    {
        Assert.Equal(expected, DomainNameNormalizer.Normalize(input));
    }

    [Theory]
    [InlineData("https://youtube.com")]
    [InlineData("*.youtube.com")]
    [InlineData("youtube.com/path")]
    [InlineData("-youtube.com")]
    public void Normalize_rejects_non_dns_input(string input)
    {
        Assert.Throws<FormatException>(() => DomainNameNormalizer.Normalize(input));
    }

    [Fact]
    public void Matcher_observes_label_boundaries()
    {
        var matcher = new TargetMatcher([CreateTarget()]);

        Assert.True(matcher.MatchesHost("youtube.com"));
        Assert.True(matcher.MatchesHost("www.youtube.com"));
        Assert.False(matcher.MatchesHost("notyoutube.com"));
        Assert.False(matcher.MatchesHost("youtube.com.example"));
    }

    [Fact]
    public void Definition_hash_is_independent_of_rule_order()
    {
        var first = CreateTarget();
        var second = first with
        {
            ExactHosts = first.ExactHosts.Reverse().ToArray(),
            BrowserUrlPatterns = first.BrowserUrlPatterns.Reverse().ToArray(),
        };

        Assert.Equal(
            TargetCatalog.ComputeDefinitionHash([first]),
            TargetCatalog.ComputeDefinitionHash([second]));
    }

    [Fact]
    public void RepresentativeSeedHostMustRemainInsideTheTargetsHostRules()
    {
        var target = CreateTarget();
        var invalid = target with
        {
            SeedHosts = ["unrelated.example"],
            IpBlockPolicy = target.IpBlockPolicy with
            {
                SourceFields = ["exact_hosts", "suffix_hosts", "cname_suffixes", "seed_hosts"],
            },
        };

        var exception = Assert.Throws<InvalidDataException>(() => new TargetCatalog([invalid]));

        Assert.Contains("is not covered", exception.Message, StringComparison.Ordinal);
    }

    private static TargetDefinition CreateTarget() => new()
    {
        StableId = "youtube",
        DisplayName = "YouTube",
        CatalogVersion = "1.0.0",
        ExactHosts = ["youtu.be", "youtube.com"],
        SuffixHosts = ["youtube.com"],
        CnameSuffixes = ["googlevideo.com"],
        BrowserUrlPatterns = ["*://*.youtube.com/*", "*://youtu.be/*"],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.DnsObserved,
            SourceFields = ["exact_hosts", "suffix_hosts", "cname_suffixes"],
            AddressFamilies = ["ipv4", "ipv6"],
            TransportProtocols = ["tcp", "udp"],
            FollowCnameChain = true,
            MaxObservationTtlSeconds = 900,
            SharedAddressAction = SharedAddressAction.Block,
        },
    };
}
