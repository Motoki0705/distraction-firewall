using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;

namespace DistractionFirewall.Enforcement.Windows.Dns;

internal sealed record DnsFilterLaunchRequest(
    Guid LeaseId,
    DateTimeOffset ExpiresAtUtc,
    string TargetSnapshotPath,
    string ObservationStorePath,
    string ReadyToken,
    IReadOnlyList<string> UpstreamNameServers);

internal sealed record DnsFilterLaunchResult(
    string TaskResourceId,
    string? OwnershipRecordId);

internal interface IDnsFilterLauncher
{
    bool CheckAvailable(out string summary);

    Task<DnsFilterLaunchResult> EnsureStartedAsync(
        DnsFilterLaunchRequest request,
        string? expectedCurrentOwnershipRecordId,
        CancellationToken cancellationToken);

    Task<OwnedRestoreResult?> RestoreTaskAsync(
        string? ownershipRecordId,
        CancellationToken cancellationToken);
}

internal interface IDnsFilterTaskStore : ITaskSchedulerStore
{
    Task RestartAsync(string resourceId, CancellationToken cancellationToken);

    Task StopAsync(string resourceId, CancellationToken cancellationToken);
}

internal sealed class WindowsDnsFilterTaskStore : IDnsFilterTaskStore
{
    private readonly WindowsTaskSchedulerStore _inner;
    private readonly WindowsMutationGate _mutationGate;

    public WindowsDnsFilterTaskStore(WindowsMutationGate mutationGate)
    {
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
        _inner = new WindowsTaskSchedulerStore(mutationGate);
    }

    public bool CheckAvailable(out string summary) => _inner.CheckAvailable(out summary);

    public ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken) => _inner.ReadAsync(resourceId, cancellationToken);

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right) =>
        _inner.StatesEqual(left, right);

    public ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken) =>
        _inner.TryWriteAsync(resourceId, expected, replacement, cancellationToken);

    public void Run(string resourceId) => _inner.Run(resourceId);

    public async Task RestartAsync(string resourceId, CancellationToken cancellationToken)
    {
        await StopAsync(resourceId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        _inner.Run(resourceId);
    }

    public async Task StopAsync(string resourceId, CancellationToken cancellationToken)
    {
        _mutationGate.Demand();
        StopRegisteredTask(resourceId);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        while (ReadTaskState(resourceId) is 2 or 4)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (stopwatch.Elapsed >= TimeSpan.FromSeconds(5))
            {
                throw new TimeoutException("The owned DNS filter task did not stop within five seconds.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void StopRegisteredTask(string resourceId)
    {
        var taskName = ParseTaskName(resourceId);
        object? service = null;
        object? folder = null;
        object? task = null;
        try
        {
            service = Connect();
            dynamic dynamicService = service;
            folder = dynamicService.GetFolder(TaskDefinitionBuilder.FolderPath);
            dynamic dynamicFolder = folder;
            task = dynamicFolder.GetTask(taskName);
            dynamic dynamicTask = task;
            dynamicTask.Stop(0);
        }
        catch (COMException exception) when (unchecked((uint)exception.HResult) == 0x8004130B)
        {
            // SCHED_E_TASK_NOT_RUNNING is the requested stopped state.
        }
        finally
        {
            ReleaseComObject(task);
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    private static int ReadTaskState(string resourceId)
    {
        var taskName = ParseTaskName(resourceId);
        object? service = null;
        object? folder = null;
        object? task = null;
        try
        {
            service = Connect();
            dynamic dynamicService = service;
            folder = dynamicService.GetFolder(TaskDefinitionBuilder.FolderPath);
            dynamic dynamicFolder = folder;
            task = dynamicFolder.GetTask(taskName);
            dynamic dynamicTask = task;
            return (int)dynamicTask.State;
        }
        finally
        {
            ReleaseComObject(task);
            ReleaseComObject(folder);
            ReleaseComObject(service);
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

    private static string ParseTaskName(string resourceId)
    {
        const string prefix = "task:\\DistractionFirewall\\";
        if (!resourceId.StartsWith(prefix, StringComparison.Ordinal)
            || resourceId.Length == prefix.Length
            || resourceId[prefix.Length..].Contains('\\', StringComparison.Ordinal))
        {
            throw new FormatException("DNS filter task resource identifier is outside the product folder.");
        }

        return resourceId[prefix.Length..];
    }

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }
}

internal sealed class ScheduledTaskDnsFilterLauncher : IDnsFilterLauncher
{
    private const string TaskAdapterId = "windows-dns-filter-task";

    private readonly IDnsFilterTaskStore _taskStore;
    private readonly OwnedMutationCoordinator _coordinator;
    private readonly IOwnershipLedger _ledger;
    private readonly WindowsMutationGate _mutationGate;
    private readonly string _executablePath;
    private readonly string _productInstanceId;

    public ScheduledTaskDnsFilterLauncher(
        IDnsFilterTaskStore taskStore,
        OwnedMutationCoordinator coordinator,
        IOwnershipLedger ledger,
        WindowsMutationGate mutationGate,
        string executablePath,
        string productInstanceId)
    {
        _taskStore = taskStore ?? throw new ArgumentNullException(nameof(taskStore));
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
        DnsFilterTaskDefinitionBuilder.ValidateExecutablePath(executablePath);
        _executablePath = Path.GetFullPath(executablePath);
        _productInstanceId = string.IsNullOrWhiteSpace(productInstanceId)
            ? throw new ArgumentException("Product instance ID is required.", nameof(productInstanceId))
            : productInstanceId;
    }

    public bool CheckAvailable(out string summary)
    {
        var schedulerAvailable = _taskStore.CheckAvailable(out var schedulerSummary);
        var executableExists = File.Exists(_executablePath);
        summary = executableExists
            ? schedulerSummary
            : schedulerSummary + " The fixed DNS filter executable is missing.";
        return schedulerAvailable && executableExists;
    }

    public async Task<DnsFilterLaunchResult> EnsureStartedAsync(
        DnsFilterLaunchRequest request,
        string? expectedCurrentOwnershipRecordId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        _mutationGate.Demand();
        var taskName = DnsFilterTaskDefinitionBuilder.TaskName(request.LeaseId);
        var resourceId = WindowsTaskSchedulerStore.ResourceId(taskName);
        var desired = TaskStateCodec.Encode(DnsFilterTaskDefinitionBuilder.Build(
            _executablePath,
            _productInstanceId,
            request));
        var current = await _taskStore.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (expectedCurrentOwnershipRecordId is not null)
        {
            await ValidateOwnedCurrentTaskAsync(
                resourceId,
                current,
                expectedCurrentOwnershipRecordId,
                cancellationToken).ConfigureAwait(false);
        }
        else if (current.Exists)
        {
            throw new OwnershipConflictException(
                resourceId,
                "A preexisting per-lease DNS filter SYSTEM task is not owned by this apply operation.");
        }

        var snapshotBoundStore = new SnapshotBoundTaskStore(_taskStore, resourceId, current, desired);
        var applied = await _coordinator.ApplyAsync(
            snapshotBoundStore,
            TaskAdapterId + "/" + desired.ComputeHash()[..16],
            request.LeaseId,
            resourceId,
            desired,
            failIfPresent: false,
            cancellationToken).ConfigureAwait(false);
        try
        {
            await _taskStore.RestartAsync(resourceId, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (applied.RecordId is not null)
            {
                try
                {
                    _ = await RestoreOwnedTaskAsync(applied.RecordId, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    // The durable task ownership record remains for the recovery worker.
                }
            }

            throw;
        }

        return new DnsFilterLaunchResult(resourceId, applied.RecordId);
    }

    public Task<OwnedRestoreResult?> RestoreTaskAsync(
        string? ownershipRecordId,
        CancellationToken cancellationToken)
    {
        _mutationGate.Demand();
        return ownershipRecordId is null
            ? Task.FromResult<OwnedRestoreResult?>(null)
            : RestoreOwnedTaskAsync(ownershipRecordId, cancellationToken);
    }

    private async Task<OwnedRestoreResult?> RestoreOwnedTaskAsync(
        string ownershipRecordId,
        CancellationToken cancellationToken)
    {
        var record = await _ledger.GetAsync(ownershipRecordId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"DNS filter task ownership record '{ownershipRecordId}' is missing.");
        var current = await _taskStore.ReadAsync(record.ResourceId, cancellationToken).ConfigureAwait(false);
        var ownsRunningDefinition = record.Phase != OwnershipMutationPhase.Restored
            && record.AdapterId.StartsWith(TaskAdapterId + "/", StringComparison.Ordinal)
            && _taskStore.StatesEqual(current, record.DesiredState);
        if (ownsRunningDefinition)
        {
            await _taskStore.StopAsync(record.ResourceId, cancellationToken).ConfigureAwait(false);
        }

        var restored = await _coordinator.RestoreAsync(_taskStore, ownershipRecordId, cancellationToken)
            .ConfigureAwait(false);
        if (restored.Restored && ownsRunningDefinition && record.OriginalState.Exists)
        {
            await _taskStore.RestartAsync(record.ResourceId, cancellationToken).ConfigureAwait(false);
        }

        return restored;
    }

    private async Task ValidateOwnedCurrentTaskAsync(
        string resourceId,
        OwnedResourceState current,
        string? expectedCurrentOwnershipRecordId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(expectedCurrentOwnershipRecordId))
        {
            throw new OwnershipConflictException(
                resourceId,
                "A conflicting per-lease DNS filter SYSTEM task already exists.");
        }

        var record = await _ledger.GetAsync(expectedCurrentOwnershipRecordId, cancellationToken)
            .ConfigureAwait(false);
        if (record is null
            || record.Phase != OwnershipMutationPhase.Applied
            || !string.Equals(record.ResourceId, resourceId, StringComparison.Ordinal)
            || !record.AdapterId.StartsWith(TaskAdapterId + "/", StringComparison.Ordinal)
            || !_taskStore.StatesEqual(current, record.DesiredState))
        {
            throw new OwnershipConflictException(
                resourceId,
                "The current DNS filter task is not the expected owned definition; CAS update was refused.");
        }
    }

    private sealed class SnapshotBoundTaskStore : ICompareExchangeResourceStore
    {
        private readonly IDnsFilterTaskStore _inner;
        private readonly string _resourceId;
        private readonly OwnedResourceState _expected;
        private readonly OwnedResourceState _desired;

        public SnapshotBoundTaskStore(
            IDnsFilterTaskStore inner,
            string resourceId,
            OwnedResourceState expected,
            OwnedResourceState desired)
        {
            _inner = inner;
            _resourceId = resourceId;
            _expected = expected;
            _desired = desired;
        }

        public async ValueTask<OwnedResourceState> ReadAsync(
            string resourceId,
            CancellationToken cancellationToken)
        {
            ValidateResource(resourceId);
            var current = await _inner.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
            if (!_inner.StatesEqual(current, _expected) && !_inner.StatesEqual(current, _desired))
            {
                throw new OwnershipConflictException(
                    resourceId,
                    "DNS filter task changed after preflight; CAS update was refused.");
            }

            return current;
        }

        public bool StatesEqual(OwnedResourceState left, OwnedResourceState right) =>
            _inner.StatesEqual(left, right);

        public ValueTask<bool> TryWriteAsync(
            string resourceId,
            OwnedResourceState expected,
            OwnedResourceState replacement,
            CancellationToken cancellationToken)
        {
            ValidateResource(resourceId);
            return _inner.TryWriteAsync(resourceId, expected, replacement, cancellationToken);
        }

        private void ValidateResource(string resourceId)
        {
            if (!string.Equals(resourceId, _resourceId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Snapshot-bound task store received another resource ID.");
            }
        }
    }
}

internal static class DnsFilterTaskDefinitionBuilder
{
    private static readonly XNamespace TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static string TaskName(Guid leaseId)
    {
        if (leaseId == Guid.Empty)
        {
            throw new ArgumentException("DNS filter task lease ID must not be empty.", nameof(leaseId));
        }

        return "DnsFilter-" + leaseId.ToString("N");
    }

    public static string Build(
        string executablePath,
        string productInstanceId,
        DnsFilterLaunchRequest request)
    {
        ValidateExecutablePath(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(productInstanceId);
        ArgumentNullException.ThrowIfNull(request);
        if (request.LeaseId == Guid.Empty)
        {
            throw new ArgumentException("DNS filter task lease ID must not be empty.", nameof(request));
        }

        ValidateDataPath(request.TargetSnapshotPath, nameof(request.TargetSnapshotPath));
        ValidateDataPath(request.ObservationStorePath, nameof(request.ObservationStorePath));
        ValidateReadyToken(request.ReadyToken);
        _ = NormalizeUpstreams(request.UpstreamNameServers);
        var taskName = TaskName(request.LeaseId);
        var marker = "DistractionFirewall/DnsFilter/v1/" + productInstanceId + "/" +
            request.LeaseId.ToString("N");
        var arguments = BuildArguments(request);
        var principalId = "System";
        var document = new XDocument(
            new XDeclaration("1.0", "UTF-16", null),
            new XElement(TaskNamespace + "Task",
                new XAttribute("version", "1.4"),
                new XElement(TaskNamespace + "RegistrationInfo",
                    new XElement(TaskNamespace + "URI",
                        TaskDefinitionBuilder.FolderPath + "\\" + taskName),
                    new XElement(TaskNamespace + "Source", marker),
                    new XElement(TaskNamespace + "Author", "Distraction Firewall"),
                    new XElement(TaskNamespace + "Description",
                        "Product-owned, lease-bound loopback DNS filter task.")),
                new XElement(TaskNamespace + "Triggers",
                    new XElement(TaskNamespace + "BootTrigger",
                        new XElement(TaskNamespace + "Enabled", true))),
                new XElement(TaskNamespace + "Principals",
                    new XElement(TaskNamespace + "Principal",
                        new XAttribute("id", principalId),
                        new XElement(TaskNamespace + "UserId", "S-1-5-18"),
                        new XElement(TaskNamespace + "LogonType", "ServiceAccount"),
                        new XElement(TaskNamespace + "RunLevel", "HighestAvailable"))),
                new XElement(TaskNamespace + "Settings",
                    new XElement(TaskNamespace + "MultipleInstancesPolicy", "IgnoreNew"),
                    new XElement(TaskNamespace + "DisallowStartIfOnBatteries", false),
                    new XElement(TaskNamespace + "StopIfGoingOnBatteries", false),
                    new XElement(TaskNamespace + "AllowHardTerminate", true),
                    new XElement(TaskNamespace + "StartWhenAvailable", true),
                    new XElement(TaskNamespace + "RunOnlyIfNetworkAvailable", false),
                    new XElement(TaskNamespace + "AllowStartOnDemand", true),
                    new XElement(TaskNamespace + "Enabled", true),
                    new XElement(TaskNamespace + "Hidden", false),
                    new XElement(TaskNamespace + "RunOnlyIfIdle", false),
                    new XElement(TaskNamespace + "WakeToRun", false),
                    new XElement(TaskNamespace + "ExecutionTimeLimit", "PT0S"),
                    new XElement(TaskNamespace + "Priority", 7),
                    new XElement(TaskNamespace + "RestartOnFailure",
                        new XElement(TaskNamespace + "Interval", "PT1M"),
                        new XElement(TaskNamespace + "Count", 10))),
                new XElement(TaskNamespace + "Data", marker),
                new XElement(TaskNamespace + "Actions",
                    new XAttribute("Context", principalId),
                    new XElement(TaskNamespace + "Exec",
                        new XElement(TaskNamespace + "Command", Path.GetFullPath(executablePath)),
                        new XElement(TaskNamespace + "Arguments", arguments),
                        new XElement(TaskNamespace + "WorkingDirectory",
                            Path.GetDirectoryName(Path.GetFullPath(executablePath)))))));
        return document.ToString(SaveOptions.DisableFormatting);
    }

    public static void ValidateExecutablePath(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        if (!Path.IsPathFullyQualified(executablePath)
            || executablePath.Contains('%', StringComparison.Ordinal)
            || executablePath.IndexOfAny(['"', '\r', '\n']) >= 0
            || !string.Equals(Path.GetExtension(executablePath), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The DNS filter path must be a literal, fully-qualified .exe path.",
                nameof(executablePath));
        }
    }

    public static void ValidateDataPath(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path, parameterName);
        if (!Path.IsPathFullyQualified(path)
            || path.Contains('%', StringComparison.Ordinal)
            || path.IndexOfAny(['"', '\r', '\n']) >= 0)
        {
            throw new ArgumentException(
                "DNS filter data paths must be literal and fully qualified.",
                parameterName);
        }
    }

    public static string[] NormalizeUpstreams(IReadOnlyList<string> upstreamNameServers)
    {
        ArgumentNullException.ThrowIfNull(upstreamNameServers);
        var normalized = upstreamNameServers
            .Select(value => IPAddress.TryParse(value, out var address)
                ? address
                : throw new ArgumentException(
                    "Every DNS filter upstream must be a literal IP address.",
                    nameof(upstreamNameServers)))
            .Where(IsAllowedUpstream)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (normalized.Length == 0 || normalized.Length != upstreamNameServers.Count)
        {
            throw new ArgumentException(
                "DNS filter upstreams must be a non-empty, duplicate-free list of non-loopback IP literals.",
                nameof(upstreamNameServers));
        }

        return normalized;
    }

    private static bool IsAllowedUpstream(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.None)
            || address.Equals(IPAddress.IPv6None)
            || address.IsIPv6Multicast)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || (bytes[0] is not (>= 224 and <= 239) && !bytes.All(value => value == byte.MaxValue));
    }

    public static void ValidateReadyToken(string readyToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(readyToken);
        if (readyToken.Length != 64 || readyToken.Any(character => character is not
                (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                "DNS filter readiness token must be 32 bytes encoded as 64 lower-case hexadecimal characters.",
                nameof(readyToken));
        }
    }

    private static string BuildArguments(DnsFilterLaunchRequest request)
    {
        var arguments = new List<string>
        {
            "dns-filter",
            "--lease-id",
            request.LeaseId.ToString("D"),
            "--lease-expires-utc",
            request.ExpiresAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            "--target-snapshot",
            QuoteWindowsArgument(Path.GetFullPath(request.TargetSnapshotPath)),
            "--observation-store",
            QuoteWindowsArgument(Path.GetFullPath(request.ObservationStorePath)),
            "--ready-token",
            request.ReadyToken,
        };
        foreach (var upstream in NormalizeUpstreams(request.UpstreamNameServers))
        {
            arguments.Add("--upstream");
            arguments.Add(upstream);
        }

        return string.Join(' ', arguments);
    }

    private static string QuoteWindowsArgument(string value)
    {
        var result = new StringBuilder(value.Length + 2);
        result.Append('"');
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                result.Append('\\', (backslashes * 2) + 1);
                result.Append(character);
                backslashes = 0;
                continue;
            }

            result.Append('\\', backslashes);
            backslashes = 0;
            result.Append(character);
        }

        result.Append('\\', backslashes * 2);
        result.Append('"');
        return result.ToString();
    }
}
