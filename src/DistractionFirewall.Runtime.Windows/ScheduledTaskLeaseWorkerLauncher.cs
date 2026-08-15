using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Persistence;

namespace DistractionFirewall.Runtime.Windows;

public interface IRecoveryTaskController
{
    Task<LeaseWorkerLaunchResult> CheckInfrastructureAsync(CancellationToken cancellationToken);

    Task RunAsync(CancellationToken cancellationToken);
}

public sealed class ScheduledTaskLeaseWorkerLauncher : ILeaseWorkerLauncher
{
    private readonly ILeaseLifecycleStore _store;
    private readonly IRecoveryTaskController _taskController;
    private readonly TimeSpan _confirmationTimeout;
    private readonly TimeSpan _pollInterval;

    public ScheduledTaskLeaseWorkerLauncher(
        ILeaseLifecycleStore store,
        IRecoveryTaskController taskController,
        TimeSpan? confirmationTimeout = null,
        TimeSpan? pollInterval = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(taskController);
        _store = store;
        _taskController = taskController;
        _confirmationTimeout = confirmationTimeout ?? TimeSpan.FromSeconds(15);
        _pollInterval = pollInterval ?? TimeSpan.FromMilliseconds(200);
        if (_confirmationTimeout <= TimeSpan.Zero || _confirmationTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(confirmationTimeout));
        }

        if (_pollInterval <= TimeSpan.Zero || _pollInterval > _confirmationTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }
    }

    public Task<LeaseWorkerLaunchResult> CheckHealthAsync(CancellationToken cancellationToken) =>
        _taskController.CheckInfrastructureAsync(cancellationToken);

    public async Task<LeaseWorkerLaunchResult> LaunchAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        if (leaseId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty lease ID is required.", nameof(leaseId));
        }

        var activeLeaseId = await _store.GetActiveLeaseIdAsync(cancellationToken).ConfigureAwait(false);
        if (activeLeaseId != leaseId)
        {
            return new LeaseWorkerLaunchResult(
                Started: false,
                $"Lease '{leaseId}' is not the active capsule.");
        }

        var before = await _store.GetStateAsync(leaseId, cancellationToken).ConfigureAwait(false);
        if (before is null || before.State != LeaseState.Active)
        {
            return new LeaseWorkerLaunchResult(
                Started: false,
                $"Lease '{leaseId}' is not ready for Worker handoff.");
        }

        try
        {
            await _taskController.RunAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new LeaseWorkerLaunchResult(
                Started: false,
                $"The fixed SYSTEM recovery task failed to start: {exception.GetType().Name}.");
        }

        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < _confirmationTimeout)
        {
            var current = await _store.GetStateAsync(leaseId, cancellationToken).ConfigureAwait(false);
            if (current is not null &&
                (current.State == LeaseState.Completed ||
                 current.Sequence > before.Sequence && current.LastHeartbeatUtc is not null))
            {
                return new LeaseWorkerLaunchResult(
                    Started: true,
                    $"SYSTEM Worker confirmed capsule progress at sequence {current.Sequence}.");
            }

            await Task.Delay(_pollInterval, cancellationToken).ConfigureAwait(false);
        }

        return new LeaseWorkerLaunchResult(
            Started: false,
            "The fixed SYSTEM recovery task started but no Lease heartbeat was observed before timeout.");
    }
}

public sealed class WindowsRecoveryTaskController : IRecoveryTaskController
{
    public const string TaskFolderPath = @"\DistractionFirewall";
    public const string RecoveryTaskName = "WorkerRecovery";
    private const string LocalSystemSid = "S-1-5-18";
    private static readonly XNamespace TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";
    private readonly RuntimePaths _paths;
    private readonly RuntimeSettings _settings;

    public WindowsRecoveryTaskController(RuntimePaths paths, RuntimeSettings settings)
    {
        ArgumentNullException.ThrowIfNull(paths);
        _paths = paths;
        _settings = RuntimeSettingsLoader.Validate(settings);
        RuntimePathResolver.DemandLiveMutationPrerequisites(paths);
    }

    public Task<LeaseWorkerLaunchResult> CheckInfrastructureAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        object? service = null;
        try
        {
            service = Connect();
            return Task.FromResult(new LeaseWorkerLaunchResult(
                Started: true,
                "Task Scheduler 2.0 is available and the fixed Worker executable is protected."));
        }
        catch (Exception exception) when (exception is COMException or PlatformNotSupportedException)
        {
            return Task.FromResult(new LeaseWorkerLaunchResult(
                Started: false,
                $"Task Scheduler infrastructure check failed: {exception.GetType().Name}."));
        }
        finally
        {
            ReleaseComObject(service);
        }
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        object? service = null;
        object? folder = null;
        object? task = null;
        object? runningTask = null;
        try
        {
            service = Connect();
            dynamic dynamicService = service;
            folder = dynamicService.GetFolder(TaskFolderPath);
            dynamic dynamicFolder = folder;
            task = dynamicFolder.GetTask(RecoveryTaskName);
            dynamic dynamicTask = task;
            ValidateDefinition((string)dynamicTask.Xml);
            runningTask = dynamicTask.Run(null);
            return Task.CompletedTask;
        }
        finally
        {
            ReleaseComObject(runningTask);
            ReleaseComObject(task);
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    private void ValidateDefinition(string definitionXml)
    {
        var document = XDocument.Parse(definitionXml, LoadOptions.None);
        var command = RequiredValue(document, "Actions", "Exec", "Command");
        var arguments = document.Descendants(TaskNamespace + "Arguments").SingleOrDefault()?.Value;
        var userId = RequiredValue(document, "Principals", "Principal", "UserId");
        var logonType = RequiredValue(document, "Principals", "Principal", "LogonType");
        var source = RequiredValue(document, "RegistrationInfo", "Source");
        var expectedSource = "DistractionFirewall/Task/v1/Recovery/" + _settings.ProductInstanceId;
        if (!string.Equals(
                Path.GetFullPath(command),
                _paths.WorkerExecutablePath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(arguments) ||
            !string.Equals(userId, LocalSystemSid, StringComparison.Ordinal) ||
            !string.Equals(logonType, "ServiceAccount", StringComparison.Ordinal) ||
            !string.Equals(source, expectedSource, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The fixed recovery task action, SYSTEM principal, or ownership marker was altered.");
        }
    }

    private static string RequiredValue(XContainer document, params string[] path)
    {
        IEnumerable<XElement> selected = document.Elements();
        foreach (var segment in path)
        {
            selected = selected.SelectMany(element => element.Name.LocalName == segment
                ? [element]
                : element.Elements().Where(child => child.Name.LocalName == segment));
        }

        return selected.SingleOrDefault()?.Value
            ?? throw new InvalidDataException($"Recovery task is missing '{string.Join('/', path)}'.");
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

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }
}
