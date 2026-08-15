using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;

namespace DistractionFirewall.DnsFilter.Runtime;

public sealed class FileDnsObservationStoreAdapter : IDnsObservationStore
{
    private readonly FileDnsObservedAddressStore _store;
    private readonly int _maximumTtlSeconds;

    private FileDnsObservationStoreAdapter(
        FileDnsObservedAddressStore store,
        int maximumTtlSeconds)
    {
        _store = store;
        _maximumTtlSeconds = maximumTtlSeconds;
    }

    public static async Task<FileDnsObservationStoreAdapter> CreateAsync(
        string protectedTargetSnapshotPath,
        string protectedObservationStorePath,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedTargetSnapshotPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedObservationStorePath);
        var snapshotPath = Path.GetFullPath(protectedTargetSnapshotPath);
        var observationPath = Path.GetFullPath(protectedObservationStorePath);
        RejectReparseOrDirectory(snapshotPath, expectDirectory: false);
        var catalog = await TargetCatalog.LoadAsync(snapshotPath, cancellationToken).ConfigureAwait(false);
        var ttlLimits = catalog.Targets
            .Where(target => target.IpBlockPolicy.Mode == IpBlockMode.DnsObserved)
            .Select(target => target.IpBlockPolicy.MaxObservationTtlSeconds)
            .ToArray();
        if (ttlLimits.Length == 0)
        {
            throw new InvalidDataException(
                "The protected target snapshot has no DNS-observed IP policy.");
        }

        var parent = Path.GetDirectoryName(observationPath)
            ?? throw new InvalidDataException("The protected observation store has no parent directory.");
        var store = new FileDnsObservedAddressStore(parent, observationPath, timeProvider);
        await store.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
        return new FileDnsObservationStoreAdapter(store, ttlLimits.Min());
    }

    public ValueTask AppendAsync(
        DnsObservationContext context,
        IReadOnlyList<DnsObservedAddress> addresses,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(addresses);
        if (!PathsEqual(Path.GetFullPath(context.ObservationStorePath), _store.StorePath))
        {
            throw new InvalidDataException(
                "The DNS observer context substituted the protected observation store path.");
        }

        return _store.AppendAsync(
            new DnsObservationAppendContext(
                context.LeaseId,
                context.LeaseExpiresUtc,
                _maximumTtlSeconds),
            addresses.Select(address => new DnsObservedAddressCandidate(
                address.Address,
                address.TtlSeconds)).ToArray(),
            cancellationToken);
    }

    private static void RejectReparseOrDirectory(string path, bool expectDirectory)
    {
        if (new FileInfo(path).LinkTarget is not null ||
            new DirectoryInfo(path).LinkTarget is not null)
        {
            throw new IOException("A protected DNS runtime path is a symbolic link.");
        }

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            throw new FileNotFoundException("The protected DNS runtime path does not exist.", path);
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
            ((attributes & FileAttributes.Directory) != 0) != expectDirectory)
        {
            throw new IOException("A protected DNS runtime path has an unsafe file type.");
        }
    }

    private static bool PathsEqual(string left, string right) => string.Equals(
        left,
        right,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}
