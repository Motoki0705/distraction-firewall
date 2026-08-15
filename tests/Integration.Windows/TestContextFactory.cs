using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;

namespace DistractionFirewall.Integration.Windows.Tests;

internal static class TestContextFactory
{
    public static EnforcementContext Create(params string[] browserPatterns)
        => Create(SharedAddressAction.Block, browserPatterns);

    public static EnforcementContext Create(
        SharedAddressAction sharedAddressAction,
        params string[] browserPatterns)
    {
        return new EnforcementContext(
            Guid.Parse("8a3d329f-4638-4f1d-876f-a9c122c76d6e"),
            "rule-hash",
            new DateTimeOffset(2030, 2, 3, 4, 5, 6, TimeSpan.Zero),
            [
                new TargetDefinition
                {
                    StableId = "youtube",
                    DisplayName = "YouTube",
                    CatalogVersion = "1.0.0",
                    ExactHosts = ["youtu.be"],
                    SuffixHosts = ["youtube.com"],
                    CnameSuffixes = [],
                    BrowserUrlPatterns = browserPatterns,
                    IpBlockPolicy = new IpBlockPolicyDefinition
                    {
                        Mode = IpBlockMode.DnsObserved,
                        AddressFamilies = ["ipv4", "ipv6"],
                        TransportProtocols = ["tcp", "udp"],
                        SharedAddressAction = sharedAddressAction,
                    },
                },
            ]);
    }
}
