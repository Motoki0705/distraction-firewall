using System.Runtime.InteropServices;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Tasks;

internal interface ITaskSchedulerStore : ICompareExchangeResourceStore
{
    bool CheckAvailable(out string summary);

    void Run(string resourceId);
}

internal sealed class WindowsTaskSchedulerStore : ITaskSchedulerStore
{
    private const int TaskCreate = 2;
    private const int TaskLogonServiceAccount = 5;
    private const string SystemAccount = "S-1-5-18";
    private const string RestrictedSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    private const uint ErrorFileNotFound = 0x80070002;
    private const uint ErrorTaskNotFound = 0x8004130F;

    private readonly WindowsMutationGate _mutationGate;

    public WindowsTaskSchedulerStore(WindowsMutationGate mutationGate)
    {
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
    }

    public bool CheckAvailable(out string summary)
    {
        object? service = null;
        try
        {
            service = Connect();
            summary = "Task Scheduler 2.0 COM service is available.";
            return true;
        }
        catch (COMException exception)
        {
            summary = $"Task Scheduler COM connection failed: 0x{exception.HResult:X8}.";
            return false;
        }
        finally
        {
            ReleaseComObject(service);
        }
    }

    public ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var taskName = ParseResourceId(resourceId);
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
            var xml = (string)dynamicTask.Xml;
            return ValueTask.FromResult(TaskStateCodec.Encode(xml));
        }
        catch (COMException exception) when (IsNotFound(exception))
        {
            return ValueTask.FromResult(OwnedResourceState.Missing);
        }
        finally
        {
            ReleaseComObject(task);
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return TaskStateCodec.Equivalent(left, right);
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        _mutationGate.Demand();
        cancellationToken.ThrowIfCancellationRequested();
        var current = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        var taskName = ParseResourceId(resourceId);
        object? service = null;
        object? folder = null;
        try
        {
            service = Connect();
            folder = GetOrCreateFolder(service, create: replacement.Exists);
            if (folder is null)
            {
                return !replacement.Exists;
            }

            dynamic dynamicFolder = folder;
            if (replacement.Exists)
            {
                var xml = TaskStateCodec.Decode(replacement).DefinitionXml;
                object? registeredTask = null;
                try
                {
                    registeredTask = dynamicFolder.RegisterTask(
                        taskName,
                        xml,
                        TaskCreate,
                        SystemAccount,
                        null,
                        TaskLogonServiceAccount,
                        RestrictedSddl);
                }
                finally
                {
                    ReleaseComObject(registeredTask);
                }
            }
            else
            {
                dynamicFolder.DeleteTask(taskName, 0);
            }
        }
        catch (COMException exception) when (!replacement.Exists && IsNotFound(exception))
        {
            // Deleting an already absent task is equivalent to the requested state.
        }
        finally
        {
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }

        var verified = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        return StatesEqual(verified, replacement);
    }

    public void Run(string resourceId)
    {
        _mutationGate.Demand();
        var taskName = ParseResourceId(resourceId);
        object? service = null;
        object? folder = null;
        object? task = null;
        object? runningTask = null;
        try
        {
            service = Connect();
            dynamic dynamicService = service;
            folder = dynamicService.GetFolder(TaskDefinitionBuilder.FolderPath);
            dynamic dynamicFolder = folder;
            task = dynamicFolder.GetTask(taskName);
            dynamic dynamicTask = task;
            runningTask = dynamicTask.Run(null);
        }
        finally
        {
            ReleaseComObject(runningTask);
            ReleaseComObject(task);
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    internal static string ResourceId(string taskName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(taskName);
        if (taskName.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException("Task name must not contain a folder separator.", nameof(taskName));
        }

        return "task:" + TaskDefinitionBuilder.FolderPath + "\\" + taskName;
    }

    private static string ParseResourceId(string resourceId)
    {
        const string prefix = "task:\\DistractionFirewall\\";
        if (!resourceId.StartsWith(prefix, StringComparison.Ordinal)
            || resourceId.Length == prefix.Length
            || resourceId[prefix.Length..].Contains('\\', StringComparison.Ordinal))
        {
            throw new FormatException("Task resource identifier is outside the product folder.");
        }

        return resourceId[prefix.Length..];
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

    private static object? GetOrCreateFolder(object service, bool create)
    {
        dynamic dynamicService = service;
        try
        {
            return dynamicService.GetFolder(TaskDefinitionBuilder.FolderPath);
        }
        catch (COMException exception) when (create && IsNotFound(exception))
        {
            object? root = null;
            try
            {
                root = dynamicService.GetFolder("\\");
                dynamic dynamicRoot = root;
                return dynamicRoot.CreateFolder("DistractionFirewall", RestrictedSddl);
            }
            finally
            {
                ReleaseComObject(root);
            }
        }
        catch (COMException exception) when (!create && IsNotFound(exception))
        {
            return null;
        }
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
}
