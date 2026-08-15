using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;

namespace DistractionFirewall.Enforcement.Windows.Dns;

public sealed record LiveWindowsDnsEnforcementOptions
{
    public required string ProductInstanceId { get; init; }

    public required string OwnershipLedgerDirectory { get; init; }

    public required string DnsFilterExecutablePath { get; init; }

    public required string TargetSnapshotPath { get; init; }

    public required string ObservationStorePath { get; init; }

    public required IWindowsDnsUpstreamObservationSeeder ObservationSeeder { get; init; }

    public TimeSpan ReadyTimeout { get; init; } = TimeSpan.FromSeconds(20);
}

public static class WindowsDnsEnforcementFactory
{
    public static WindowsDnsEnforcementAdapter CreateLiveWindowsDns(
        LiveWindowsDnsEnforcementOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) || nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException("Live DNS enforcement requires Windows 11 x64.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(options.ProductInstanceId);
        ArgumentNullException.ThrowIfNull(options.ObservationSeeder);
        if (options.ReadyTimeout <= TimeSpan.Zero || options.ReadyTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "ReadyTimeout must be greater than zero and no more than one minute.");
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var commonApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var filterExecutable = RequireExistingFileUnder(
            options.DnsFilterExecutablePath,
            programFiles,
            nameof(options.DnsFilterExecutablePath));
        DnsFilterTaskDefinitionBuilder.ValidateExecutablePath(filterExecutable);
        var targetSnapshot = RequireExistingFileUnder(
            options.TargetSnapshotPath,
            commonApplicationData,
            nameof(options.TargetSnapshotPath));
        var observationStore = RequireExistingPathUnder(
            options.ObservationStorePath,
            commonApplicationData,
            nameof(options.ObservationStorePath));
        var ledgerDirectory = RequireExistingDirectoryUnder(
            options.OwnershipLedgerDirectory,
            commonApplicationData,
            nameof(options.OwnershipLedgerDirectory));

        var mutationGate = WindowsMutationGate.CreateExplicitLiveWindows();
        var ledger = new FileOwnershipLedger(ledgerDirectory, options.ProductInstanceId);
        try
        {
            var coordinator = new OwnedMutationCoordinator(ledger);
            var taskStore = new WindowsDnsFilterTaskStore(mutationGate);
            var launcher = new ScheduledTaskDnsFilterLauncher(
                taskStore,
                coordinator,
                ledger,
                mutationGate,
                filterExecutable,
                options.ProductInstanceId);
            return new WindowsDnsEnforcementAdapter(
                new WindowsDnsSettingsStore(mutationGate),
                launcher,
                new LeaseBoundDnsFilterReadyProbe(),
                options.ObservationSeeder,
                coordinator,
                ledger,
                mutationGate,
                targetSnapshot,
                observationStore,
                options.ReadyTimeout,
                ledger);
        }
        catch
        {
            ledger.Dispose();
            throw;
        }
    }

    private static string RequireExistingFileUnder(string path, string root, string parameterName)
    {
        var fullPath = RequirePathUnder(path, root, parameterName);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                $"The installer-provisioned file for {parameterName} does not exist.",
                fullPath);
        }

        return fullPath;
    }

    private static string RequireExistingDirectoryUnder(string path, string root, string parameterName)
    {
        var fullPath = RequirePathUnder(path, root, parameterName);
        if (!Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException(
                $"The installer must pre-create {parameterName} with a SYSTEM/Administrators-only write ACL.");
        }

        return fullPath;
    }

    private static string RequireExistingPathUnder(string path, string root, string parameterName)
    {
        var fullPath = RequirePathUnder(path, root, parameterName);
        if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
        {
            throw new FileNotFoundException(
                $"The installer-provisioned path for {parameterName} does not exist.",
                fullPath);
        }

        return fullPath;
    }

    private static string RequirePathUnder(string path, string root, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path, parameterName);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException($"The protected root for {parameterName} is unavailable.");
        }

        var fullPath = Path.GetFullPath(path);
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root))
            + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"{parameterName} must be located under the protected directory '{normalizedRoot}'.",
                parameterName);
        }

        return fullPath;
    }
}
