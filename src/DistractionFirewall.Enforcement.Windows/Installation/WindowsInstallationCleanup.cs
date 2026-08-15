using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;
using DistractionFirewall.Enforcement.Windows.Wfp;

namespace DistractionFirewall.Enforcement.Windows.Installation;

public sealed record LiveWindowsInstallationCleanupOptions
{
    public required string ProductInstanceId { get; init; }

    public required string WorkerExecutablePath { get; init; }
}

internal interface IWindowsInstallationCleanupBackend
{
    string BackendId { get; }

    void ValidateReadyForCleanup();

    void CleanupValidatedResources();
}

public sealed class WindowsInstallationCleanupException : InvalidOperationException
{
    public WindowsInstallationCleanupException(
        string backendId,
        string operation,
        Exception innerException)
        : base($"Installation cleanup backend '{backendId}' failed during {operation}.", innerException)
    {
        BackendId = backendId;
        Operation = operation;
    }

    public string BackendId { get; }

    public string Operation { get; }
}

public sealed class WindowsInstallationCleanup
{
    private readonly IWindowsInstallationCleanupBackend[] _backends;

    internal WindowsInstallationCleanup(IEnumerable<IWindowsInstallationCleanupBackend> backends)
    {
        ArgumentNullException.ThrowIfNull(backends);
        _backends = backends.ToArray();
        if (_backends.Length == 0
            || _backends.Select(backend => backend.BackendId).Distinct(StringComparer.Ordinal).Count()
                != _backends.Length)
        {
            throw new ArgumentException(
                "Installation cleanup backends must be non-empty and uniquely identified.",
                nameof(backends));
        }
    }

    public static WindowsInstallationCleanup CreateLive(
        LiveWindowsInstallationCleanupOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) || nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException(
                "Live installation cleanup requires Windows 11 x64.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(options.ProductInstanceId);
        TaskDefinitionBuilder.ValidateWorkerPath(options.WorkerExecutablePath);
        var workerPath = Path.GetFullPath(options.WorkerExecutablePath);
        if (!File.Exists(workerPath))
        {
            throw new FileNotFoundException(
                "Installation cleanup requires the still-installed Worker executable.",
                workerPath);
        }

        var mutationGate = WindowsMutationGate.CreateExplicitLiveWindows();
        var wfpStore = new WfpPolicyStore(
            new WfpNativeSessionFactory(options.ProductInstanceId));
        var recoveryDefinition = TaskDefinitionBuilder.BuildRecoveryTask(
            workerPath,
            options.ProductInstanceId);
        return new WindowsInstallationCleanup(
        [
            new WfpInstallationCleanupBackend(wfpStore),
            new TaskSchedulerInstallationCleanupBackend(mutationGate, recoveryDefinition),
        ]);
    }

    public Task CleanupAsync(CancellationToken cancellationToken)
    {
        foreach (var backend in _backends)
        {
            cancellationToken.ThrowIfCancellationRequested();
            InvokeBackend(backend, "preflight validation", backend.ValidateReadyForCleanup);
        }

        foreach (var backend in _backends)
        {
            cancellationToken.ThrowIfCancellationRequested();
            InvokeBackend(backend, "compare-and-delete", backend.CleanupValidatedResources);
        }

        return Task.CompletedTask;
    }

    private static void InvokeBackend(
        IWindowsInstallationCleanupBackend backend,
        string operation,
        Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new WindowsInstallationCleanupException(
                backend.BackendId,
                operation,
                exception);
        }
    }
}

internal sealed class WfpInstallationCleanupBackend : IWindowsInstallationCleanupBackend
{
    private readonly WfpPolicyStore _policyStore;

    public WfpInstallationCleanupBackend(WfpPolicyStore policyStore)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
    }

    public string BackendId => "windows-wfp-infrastructure";

    public void ValidateReadyForCleanup() =>
        _policyStore.ValidatePersistentInfrastructureCanBeRemoved();

    public void CleanupValidatedResources() =>
        _policyStore.RemovePersistentInfrastructure();
}

internal sealed class TaskSchedulerInstallationCleanupBackend : IWindowsInstallationCleanupBackend
{
    private const int DaclSecurityInformation = 0x00000004;
    private const int TaskEnumHidden = 1;
    private const uint ErrorFileNotFound = 0x80070002;
    private const uint ErrorTaskNotFound = 0x8004130F;
    private const string RecoveryTaskName = "WorkerRecovery";
    private static readonly HashSet<string> AllowedSecurityPrincipals =
    [
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null).Value,
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null).Value,
    ];

    private readonly WindowsMutationGate _mutationGate;
    private readonly OwnedResourceState _expectedRecoveryState;

    public TaskSchedulerInstallationCleanupBackend(
        WindowsMutationGate mutationGate,
        string expectedRecoveryDefinition)
    {
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
        _expectedRecoveryState = TaskStateCodec.Encode(expectedRecoveryDefinition);
    }

    public string BackendId => "windows-task-scheduler-infrastructure";

    public void ValidateReadyForCleanup()
    {
        _mutationGate.Demand();
        object? service = null;
        try
        {
            service = Connect();
            _ = InspectFolder(service);
        }
        finally
        {
            ReleaseComObject(service);
        }
    }

    public void CleanupValidatedResources()
    {
        _mutationGate.Demand();
        object? service = null;
        object? folder = null;
        object? root = null;
        try
        {
            service = Connect();
            var snapshot = InspectFolder(service);
            if (!snapshot.FolderExists)
            {
                return;
            }

            dynamic dynamicService = service;
            folder = dynamicService.GetFolder(TaskDefinitionBuilder.FolderPath);
            dynamic dynamicFolder = folder;
            if (snapshot.RecoveryTaskExists)
            {
                // InspectFolder has just revalidated the complete definition, source marker,
                // principal, action, triggers, settings, and restricted DACL.
                dynamicFolder.DeleteTask(RecoveryTaskName, 0);
            }

            var emptySnapshot = InspectFolder(service);
            if (!emptySnapshot.FolderExists || emptySnapshot.RecoveryTaskExists)
            {
                throw new InvalidOperationException(
                    "Task Scheduler cleanup did not converge to an empty product folder.");
            }

            ReleaseComObject(folder);
            folder = null;
            root = dynamicService.GetFolder("\\");
            dynamic dynamicRoot = root;
            dynamicRoot.DeleteFolder("DistractionFirewall", 0);
            if (TryGetFolder(service, out var remainingFolder))
            {
                ReleaseComObject(remainingFolder);
                throw new InvalidOperationException(
                    "The product Task Scheduler folder remained after deletion.");
            }
        }
        finally
        {
            ReleaseComObject(root);
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    private TaskFolderCleanupSnapshot InspectFolder(object service)
    {
        if (!TryGetFolder(service, out var folder) || folder is null)
        {
            return new TaskFolderCleanupSnapshot(FolderExists: false, RecoveryTaskExists: false);
        }

        object? folders = null;
        object? tasks = null;
        object? task = null;
        try
        {
            dynamic dynamicFolder = folder;
            RequireRestrictedDacl(dynamicFolder, "Task Scheduler product folder");
            folders = dynamicFolder.GetFolders(0);
            dynamic dynamicFolders = folders;
            if ((int)dynamicFolders.Count != 0)
            {
                throw new InvalidOperationException(
                    "Task Scheduler product folder contains an unexpected subfolder.");
            }

            tasks = dynamicFolder.GetTasks(TaskEnumHidden);
            dynamic dynamicTasks = tasks;
            var count = (int)dynamicTasks.Count;
            if (count == 0)
            {
                return new TaskFolderCleanupSnapshot(FolderExists: true, RecoveryTaskExists: false);
            }

            if (count != 1)
            {
                throw new InvalidOperationException(
                    "Task Scheduler installation cleanup requires zero per-lease or foreign tasks.");
            }

            task = dynamicTasks.Item(1);
            dynamic dynamicTask = task;
            if (!string.Equals((string)dynamicTask.Name, RecoveryTaskName, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Task Scheduler product folder contains a per-lease or foreign task.");
            }

            RequireRestrictedDacl(dynamicTask, "WorkerRecovery task");
            var actualState = TaskStateCodec.Encode((string)dynamicTask.Xml);
            if (!TaskStateCodec.Equivalent(actualState, _expectedRecoveryState))
            {
                throw new InvalidOperationException(
                    "WorkerRecovery task ownership metadata or definition was altered.");
            }

            return new TaskFolderCleanupSnapshot(FolderExists: true, RecoveryTaskExists: true);
        }
        finally
        {
            ReleaseComObject(task);
            ReleaseComObject(tasks);
            ReleaseComObject(folders);
            ReleaseComObject(folder);
        }
    }

    private static void RequireRestrictedDacl(dynamic securedObject, string description)
    {
        var sddl = (string)securedObject.GetSecurityDescriptor(DaclSecurityInformation);
        var descriptor = new RawSecurityDescriptor(sddl);
        if ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0
            || descriptor.DiscretionaryAcl is null)
        {
            throw new InvalidOperationException($"{description} does not have a protected DACL.");
        }

        var principals = new HashSet<string>(StringComparer.Ordinal);
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce qualified
                || qualified.AceQualifier != AceQualifier.AccessAllowed
                || qualified.SecurityIdentifier is null
                || !AllowedSecurityPrincipals.Contains(qualified.SecurityIdentifier.Value))
            {
                throw new InvalidOperationException(
                    $"{description} grants access outside SYSTEM and Administrators.");
            }

            principals.Add(qualified.SecurityIdentifier.Value);
        }

        if (!principals.SetEquals(AllowedSecurityPrincipals))
        {
            throw new InvalidOperationException(
                $"{description} is missing its exact SYSTEM/Administrators ownership boundary.");
        }
    }

    private static bool TryGetFolder(object service, out object? folder)
    {
        try
        {
            dynamic dynamicService = service;
            folder = dynamicService.GetFolder(TaskDefinitionBuilder.FolderPath);
            return true;
        }
        catch (COMException exception) when (IsNotFound(exception))
        {
            folder = null;
            return false;
        }
    }

    private static object Connect()
    {
        var serviceType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)
            ?? throw new PlatformNotSupportedException("Task Scheduler 2.0 COM is unavailable.");
        var service = Activator.CreateInstance(serviceType)
            ?? throw new InvalidOperationException("Unable to create Schedule.Service.");
        dynamic dynamicService = service;
        dynamicService.Connect();
        return service;
    }

    private static bool IsNotFound(COMException exception)
    {
        var error = unchecked((uint)exception.HResult);
        return error is ErrorFileNotFound or ErrorTaskNotFound;
    }

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }

    private sealed record TaskFolderCleanupSnapshot(
        bool FolderExists,
        bool RecoveryTaskExists);
}
