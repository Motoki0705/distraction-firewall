using DistractionFirewall.Core.Targets;

namespace DistractionFirewall.UnitTests;

public sealed class TargetCatalogFileTests
{
    [Fact]
    public async Task Production_catalog_loads_as_a_single_generic_youtube_target()
    {
        var path = Path.Combine(FindRepositoryRoot(), "config", "targets", "youtube.json");

        var catalog = await TargetCatalog.LoadAsync(path, CancellationToken.None);

        var target = Assert.Single(catalog.Targets);
        Assert.Equal("youtube", target.StableId);
        Assert.Equal(IpBlockMode.DnsObserved, target.IpBlockPolicy.Mode);
        Assert.Contains("www.youtube.com", target.SeedHosts);
        Assert.Contains("seed_hosts", target.IpBlockPolicy.SourceFields);
        Assert.NotEmpty(target.KnownCollateral);
        Assert.True(new TargetMatcher(catalog.Targets).MatchesHost("www.youtube.com"));
    }

    [Fact]
    public async Task Every_valid_catalog_fixture_loads()
    {
        var directory = Path.Combine(
            FindRepositoryRoot(),
            "config",
            "fixtures",
            "target-catalog",
            "v1",
            "valid");

        foreach (var path in Directory.EnumerateFiles(directory, "*.json"))
        {
            var catalog = await TargetCatalog.LoadAsync(path, CancellationToken.None);
            Assert.NotEmpty(catalog.Targets);
        }
    }

    [Fact]
    public async Task Every_invalid_catalog_fixture_is_rejected()
    {
        var directory = Path.Combine(
            FindRepositoryRoot(),
            "config",
            "fixtures",
            "target-catalog",
            "v1",
            "invalid");

        foreach (var path in Directory.EnumerateFiles(directory, "*.json"))
        {
            await Assert.ThrowsAnyAsync<Exception>(
                () => TargetCatalog.LoadAsync(path, CancellationToken.None));
        }
    }

    [Fact]
    public async Task Alternative_match_modes_metadata_and_minimum_ttl_load()
    {
        var path = Path.Combine(
            FindRepositoryRoot(),
            "config",
            "fixtures",
            "target-catalog",
            "v1",
            "valid",
            "alternative-match-modes.json");

        var catalog = await TargetCatalog.LoadAsync(path, CancellationToken.None);

        var cnameOnly = catalog.GetRequired("cname-only");
        Assert.Empty(cnameOnly.ExactHosts);
        Assert.Empty(cnameOnly.SuffixHosts);
        Assert.Single(cnameOnly.CnameSuffixes);
        Assert.Equal("Exercises a target attributed only by canonical-name suffix.", cnameOnly.Description);
        Assert.Equal(["DNS CNAME attribution"], cnameOnly.Coverage);

        var browserOnly = catalog.GetRequired("browser-only");
        Assert.Empty(browserOnly.ExactHosts);
        Assert.Empty(browserOnly.SuffixHosts);
        Assert.Empty(browserOnly.CnameSuffixes);
        Assert.Single(browserOnly.BrowserUrlPatterns);

        var minimumTtl = catalog.GetRequired("minimum-observation-ttl");
        Assert.Equal(60, minimumTtl.IpBlockPolicy.MaxObservationTtlSeconds);
        Assert.Equal(SharedAddressAction.DnsBrowserOnly, minimumTtl.IpBlockPolicy.SharedAddressAction);
    }

    [Fact]
    public void Programmatic_catalog_obeys_top_level_and_description_limits()
    {
        var maximumCatalog = new TargetCatalog(
            Enumerable.Range(0, 64).Select(index => CreateTarget($"target-{index}")));

        Assert.Equal(64, maximumCatalog.Targets.Count);
        Assert.Throws<InvalidDataException>(() => new TargetCatalog(
            Enumerable.Range(0, 65).Select(index => CreateTarget($"target-{index}"))));
        Assert.Throws<InvalidDataException>(() => new TargetCatalog(
            [CreateTarget("description-limit") with { Description = new string('x', 513) }]));
    }

    [Fact]
    public void Collateral_references_must_resolve_after_hostname_normalization()
    {
        var validCollateral = CreateCollateral("EXAMPLE.TEST", "First documented risk");
        var target = CreateTarget("collateral") with
        {
            ExactHosts = ["example.test"],
            KnownCollateral = [validCollateral],
        };

        var catalog = new TargetCatalog([target]);

        Assert.Equal("example.test", Assert.Single(catalog.Targets).KnownCollateral.Single().RuleValue);
        Assert.Throws<InvalidDataException>(() => new TargetCatalog(
            [target with { KnownCollateral = [validCollateral with { RuleValue = "other.test" }] }]));
    }

    [Fact]
    public void Distinct_collateral_entries_may_document_the_same_rule()
    {
        var first = CreateCollateral("example.test", "First documented risk");
        var second = CreateCollateral("example.test", "Second documented risk") with
        {
            Risk = "A distinct impact for the same rule.",
        };

        var catalog = new TargetCatalog(
            [CreateTarget("collateral-narratives") with
            {
                ExactHosts = ["example.test"],
                KnownCollateral = [first, second],
            }]);

        Assert.Equal(2, Assert.Single(catalog.Targets).KnownCollateral.Count);
    }

    private static TargetDefinition CreateTarget(string stableId) => new()
    {
        StableId = stableId,
        DisplayName = stableId,
        CatalogVersion = "1.0.0",
        ExactHosts = [$"{stableId}.example"],
        SuffixHosts = [],
        CnameSuffixes = [],
        BrowserUrlPatterns = [],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.Disabled,
        },
        KnownCollateral = [],
    };

    private static KnownCollateralDefinition CreateCollateral(string ruleValue, string purpose) => new()
    {
        RuleField = "exact_hosts",
        RuleValue = ruleValue,
        Purpose = purpose,
        Severity = "low",
        Risk = "A documented risk.",
        Mitigation = "A documented mitigation.",
    };

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DistractionFirewall.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
