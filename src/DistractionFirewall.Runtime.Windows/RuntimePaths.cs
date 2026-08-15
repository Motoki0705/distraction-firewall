using System.Security.AccessControl;
using System.Security.Principal;

namespace DistractionFirewall.Runtime.Windows;

public enum RuntimeComponent
{
    ActivationService,
    LeaseWorker,
    Finalizer,
}

public sealed record RuntimePaths
{
    public const string ProductInstanceId = "Motoki0705.DistractionFirewall.Runtime.v1";
    public const string WorkerFileName = "distraction-firewall-lease-worker.exe";
    public const string DnsFilterFileName = "distraction-firewall-dns.exe";

    internal bool IsInstalledLayout { get; init; }

    public required RuntimeComponent Component { get; init; }

    public required string ProgramFilesRoot { get; init; }

    public required string ProgramDataRoot { get; init; }

    public required string RuntimeRoot { get; init; }

    public required string ComponentDirectory { get; init; }

    public required string WorkerExecutablePath { get; init; }

    public required string DnsFilterExecutablePath { get; init; }

    public required string TargetCatalogPath { get; init; }

    public required string DataRoot { get; init; }

    public required string LeaseStoreDirectory { get; init; }

    public required string OwnershipLedgerDirectory { get; init; }

    public required string DnsDataDirectory { get; init; }

    public required string DnsTargetSnapshotPath { get; init; }

    public required string DnsObservationStorePath { get; init; }

    public required string DnsObservedAddressesPath { get; init; }

    public required string SettingsPath { get; init; }
}

public static class RuntimePathResolver
{
    private const string RuntimeProductDirectoryName = "Distraction Firewall Lease Runtime";
    private const string DataVersionDirectoryName = "v1";

    public static RuntimePaths ResolveInstalled(
        RuntimeComponent component,
        string componentBaseDirectory)
    {
        if (!OperatingSystem.IsWindows() ||
            !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) ||
            nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException("The installed runtime requires Windows 11 x64.");
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var paths = Resolve(
            programFiles,
            programData,
            component,
            componentBaseDirectory,
            installedLayout: true);
        ValidateInstalledArtifacts(paths);
        return paths;
    }

    public static RuntimePaths ResolveForTests(
        string programFilesRoot,
        string programDataRoot,
        RuntimeComponent component,
        string componentBaseDirectory) => Resolve(
            programFilesRoot,
            programDataRoot,
            component,
            componentBaseDirectory,
            installedLayout: false);

    internal static void DemandLiveMutationPrerequisites(RuntimePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (!paths.IsInstalledLayout)
        {
            throw new InvalidOperationException("Live Windows mutation requires paths resolved from the installed layout.");
        }

        if (!OperatingSystem.IsWindows() ||
            !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) ||
            nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException("The installed runtime requires Windows 11 x64.");
        }

        ValidateInstalledArtifacts(paths);
    }

    private static RuntimePaths Resolve(
        string programFilesRoot,
        string programDataRoot,
        RuntimeComponent component,
        string componentBaseDirectory,
        bool installedLayout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(programFilesRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(programDataRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(componentBaseDirectory);
        var normalizedProgramFiles = NormalizeRoot(programFilesRoot, nameof(programFilesRoot));
        var normalizedProgramData = NormalizeRoot(programDataRoot, nameof(programDataRoot));
        var runtimeRoot = CombineUnder(
            normalizedProgramFiles,
            RuntimeProductDirectoryName);
        var componentDirectory = CombineUnder(runtimeRoot, GetComponentDirectoryName(component));
        var actualComponentDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(componentBaseDirectory));
        if (!string.Equals(componentDirectory, actualComponentDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The {component} host must run from fixed directory '{componentDirectory}'.");
        }

        var workerDirectory = CombineUnder(runtimeRoot, "lease-worker");
        var dnsFilterDirectory = CombineUnder(runtimeRoot, "dns-filter");
        var dataRoot = CombineUnder(
            normalizedProgramData,
            "DistractionFirewall",
            "Runtime",
            DataVersionDirectoryName);
        return new RuntimePaths
        {
            IsInstalledLayout = installedLayout,
            Component = component,
            ProgramFilesRoot = normalizedProgramFiles,
            ProgramDataRoot = normalizedProgramData,
            RuntimeRoot = runtimeRoot,
            ComponentDirectory = componentDirectory,
            WorkerExecutablePath = CombineUnder(workerDirectory, RuntimePaths.WorkerFileName),
            DnsFilterExecutablePath = CombineUnder(
                dnsFilterDirectory,
                RuntimePaths.DnsFilterFileName),
            TargetCatalogPath = CombineUnder(
                CombineUnder(runtimeRoot, "activation-service"),
                "config",
                "targets",
                "youtube.json"),
            DataRoot = dataRoot,
            LeaseStoreDirectory = dataRoot,
            OwnershipLedgerDirectory = CombineUnder(dataRoot, "ownership-ledger"),
            DnsDataDirectory = CombineUnder(dataRoot, "dns"),
            DnsTargetSnapshotPath = CombineUnder(
                CombineUnder(dataRoot, "dns"),
                "target-snapshot.json"),
            DnsObservationStorePath = CombineUnder(
                CombineUnder(dataRoot, "dns"),
                "observations"),
            DnsObservedAddressesPath = CombineUnder(
                CombineUnder(CombineUnder(dataRoot, "dns"), "observations"),
                "observed-addresses.json"),
            SettingsPath = CombineUnder(dataRoot, "settings.json"),
        };
    }

    private static void ValidateInstalledArtifacts(RuntimePaths paths)
    {
        RejectReparseAncestors(paths.ProgramFilesRoot, paths.RuntimeRoot);
        RejectReparseAncestors(paths.ProgramFilesRoot, paths.ComponentDirectory);
        RejectReparseAncestors(paths.ProgramFilesRoot, paths.WorkerExecutablePath);
        RejectReparseAncestors(paths.ProgramFilesRoot, paths.DnsFilterExecutablePath);
        RejectReparseAncestors(paths.ProgramDataRoot, paths.DataRoot);
        RejectReparseAncestors(paths.ProgramDataRoot, paths.OwnershipLedgerDirectory);
        RejectReparseAncestors(paths.ProgramDataRoot, paths.DnsDataDirectory);
        RejectReparseAncestors(paths.ProgramDataRoot, paths.DnsObservationStorePath);
        RequireProtectedDirectory(paths.RuntimeRoot);
        RequireProtectedDirectory(paths.ComponentDirectory);
        RequireProtectedFile(paths.WorkerExecutablePath);
        RequireProtectedFile(paths.DnsFilterExecutablePath);
        if (paths.Component == RuntimeComponent.ActivationService)
        {
            RejectReparseAncestors(paths.ProgramFilesRoot, paths.TargetCatalogPath);
            RequireProtectedFile(paths.TargetCatalogPath);
        }
        RequireProtectedDirectory(paths.DataRoot);
        RequireProtectedDirectory(paths.OwnershipLedgerDirectory);
        RequireProtectedDirectory(paths.DnsDataDirectory);
        if (File.Exists(paths.DnsTargetSnapshotPath))
        {
            RejectReparseAncestors(paths.ProgramDataRoot, paths.DnsTargetSnapshotPath);
            RequireProtectedFile(paths.DnsTargetSnapshotPath);
        }
        else if (Directory.Exists(paths.DnsTargetSnapshotPath))
        {
            throw new IOException("The protected DNS target snapshot path is a directory.");
        }
        RequireProtectedDirectory(paths.DnsObservationStorePath);
        if (File.Exists(paths.DnsObservedAddressesPath))
        {
            RejectReparseAncestors(paths.ProgramDataRoot, paths.DnsObservedAddressesPath);
            RequireProtectedFile(paths.DnsObservedAddressesPath);
        }
        else if (Directory.Exists(paths.DnsObservedAddressesPath))
        {
            throw new IOException("The protected DNS observation document path is a directory.");
        }
        if (File.Exists(paths.SettingsPath))
        {
            RejectReparseAncestors(paths.ProgramDataRoot, paths.SettingsPath);
            RequireProtectedFile(paths.SettingsPath);
        }
    }

    internal static void ValidateBootstrappedSettingsFile(RuntimePaths paths)
    {
        if (!paths.IsInstalledLayout)
        {
            return;
        }

        RejectReparseAncestors(paths.ProgramDataRoot, paths.SettingsPath);
        RequireProtectedFile(paths.SettingsPath);
    }

    private static void RejectReparseAncestors(string trustedRoot, string candidate)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trustedRoot));
        var current = File.Exists(candidate)
            ? Directory.GetParent(Path.GetFullPath(candidate))
            : new DirectoryInfo(Path.GetFullPath(candidate));
        while (current is not null &&
               !string.Equals(current.FullName, root, StringComparison.OrdinalIgnoreCase))
        {
            if (!current.Exists)
            {
                throw new DirectoryNotFoundException(
                    $"Protected runtime ancestor '{current.FullName}' does not exist.");
            }

            RejectReparsePoint(current.FullName);
            current = current.Parent;
        }

        if (current is null)
        {
            throw new InvalidOperationException(
                $"Protected path '{candidate}' is not rooted beneath '{trustedRoot}'.");
        }
    }

    private static void RequireProtectedDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException(
                $"Required installer-owned directory '{path}' does not exist.");
        }

        RejectReparsePoint(path);
        RejectBroadWriteAcl(new DirectoryInfo(path).GetAccessControl(), path);
    }

    private static void RequireProtectedFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Required installer-owned file '{path}' does not exist.", path);
        }

        RejectReparsePoint(path);
        RejectBroadWriteAcl(new FileInfo(path).GetAccessControl(), path);
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException($"Protected runtime path '{path}' must not be a reparse point.");
        }
    }

    private static void RejectBroadWriteAcl(FileSystemSecurity security, string path)
    {
        var broadSids = new HashSet<string>(StringComparer.Ordinal)
        {
            Sid(WellKnownSidType.WorldSid),
            Sid(WellKnownSidType.AuthenticatedUserSid),
            Sid(WellKnownSidType.BuiltinUsersSid),
            Sid(WellKnownSidType.AnonymousSid),
        };
        const FileSystemRights writeRights = FileSystemRights.WriteData |
            FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes |
            FileSystemRights.WriteAttributes |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.Delete |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                broadSids.Contains(rule.IdentityReference.Value) &&
                (rule.FileSystemRights & writeRights) != 0)
            {
                throw new UnauthorizedAccessException(
                    $"Protected runtime path '{path}' grants broad write access to '{rule.IdentityReference.Value}'.");
            }
        }
    }

    private static string Sid(WellKnownSidType type) =>
        new SecurityIdentifier(type, domainSid: null).Value;

    private static string NormalizeRoot(string root, string parameterName)
    {
        if (!Path.IsPathFullyQualified(root))
        {
            throw new ArgumentException("A fully-qualified root is required.", parameterName);
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
    }

    private static string CombineUnder(string root, params string[] segments)
    {
        var candidate = Path.GetFullPath(Path.Combine([root, .. segments]));
        var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Resolved runtime path '{candidate}' escapes '{root}'.");
        }

        return Path.TrimEndingDirectorySeparator(candidate);
    }

    private static string GetComponentDirectoryName(RuntimeComponent component) => component switch
    {
        RuntimeComponent.ActivationService => "activation-service",
        RuntimeComponent.LeaseWorker => "lease-worker",
        RuntimeComponent.Finalizer => "finalizer",
        _ => throw new ArgumentOutOfRangeException(nameof(component)),
    };
}
