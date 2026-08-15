namespace DistractionFirewall.Enforcement.Windows.Dns;

public sealed record WindowsDnsUpstreamServerSet(
    Guid InterfaceId,
    string AddressFamily,
    IReadOnlyList<string> NameServers);

public sealed record WindowsDnsObservationSeedRequest(
    Guid LeaseId,
    DateTimeOffset ExpiresAtUtc,
    string TargetSnapshotPath,
    string ObservationStorePath,
    IReadOnlyList<WindowsDnsUpstreamServerSet> UpstreamServers);

public interface IWindowsDnsUpstreamObservationSeeder
{
    // Implementations resolve exact hosts from the protected target snapshot against the supplied
    // non-loopback upstreams, follow CNAMEs where supported, and persist only TTL-bounded address
    // observations. Raw DNS query names must never be written to the observation store or logs.
    Task SeedAsync(
        WindowsDnsObservationSeedRequest request,
        CancellationToken cancellationToken);
}
