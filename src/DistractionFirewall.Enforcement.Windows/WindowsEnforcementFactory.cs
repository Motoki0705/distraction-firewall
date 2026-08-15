using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows.Browser;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;
using DistractionFirewall.Enforcement.Windows.Wfp;

namespace DistractionFirewall.Enforcement.Windows;

public sealed record LiveWindowsEnforcementOptions
{
    public required string ProductInstanceId { get; init; }

    public required string OwnershipLedgerDirectory { get; init; }

    public required string WorkerExecutablePath { get; init; }

    public IWindowsObservedAddressSource? ObservedAddressSource { get; init; }
}

public static class WindowsEnforcementFactory
{
    public static WindowsEnforcementAdapter CreateLiveWindows(LiveWindowsEnforcementOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) || nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException("Live Windows enforcement requires Windows 11 x64.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(options.ProductInstanceId);
        var workerPath = Path.GetFullPath(options.WorkerExecutablePath);
        TaskDefinitionBuilder.ValidateWorkerPath(workerPath);
        EnsurePathIsUnder(
            workerPath,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "WorkerExecutablePath");
        if (!File.Exists(workerPath))
        {
            throw new FileNotFoundException("The fixed SYSTEM worker executable does not exist.", workerPath);
        }

        var ledgerDirectory = Path.GetFullPath(options.OwnershipLedgerDirectory);
        EnsurePathIsUnder(
            ledgerDirectory,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "OwnershipLedgerDirectory");
        if (!Directory.Exists(ledgerDirectory))
        {
            throw new DirectoryNotFoundException(
                "The installer must pre-create the ownership ledger directory with a SYSTEM/Administrators-only write ACL.");
        }

        var mutationGate = WindowsMutationGate.CreateExplicitLiveWindows();
        var ledger = new FileOwnershipLedger(ledgerDirectory, options.ProductInstanceId);
        var coordinator = new OwnedMutationCoordinator(ledger);
        var browser = new BrowserPolicyEnforcementAdapter(
            new WindowsRegistryPolicyStore(mutationGate),
            coordinator,
            mutationGate);
        var wfp = new WfpEnforcementAdapter(
            new WfpPolicyStore(new WfpNativeSessionFactory(options.ProductInstanceId)),
            ledger,
            options.ObservedAddressSource ?? new EmptyWindowsObservedAddressSource(),
            mutationGate);
        var scheduler = new TaskSchedulerEnforcementAdapter(
            new WindowsTaskSchedulerStore(mutationGate),
            coordinator,
            mutationGate,
            workerPath,
            options.ProductInstanceId);
        return new WindowsEnforcementAdapter([browser, wfp, scheduler], ledger);
    }

    private static void EnsurePathIsUnder(string candidate, string root, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException($"The protected root for {parameterName} is unavailable.");
        }

        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root))
            + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"{parameterName} must be located under the protected directory '{normalizedRoot}'.",
                parameterName);
        }
    }
}
