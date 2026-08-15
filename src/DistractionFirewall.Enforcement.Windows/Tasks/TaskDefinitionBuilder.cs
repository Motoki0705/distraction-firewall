using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Tasks;

internal static class TaskDefinitionBuilder
{
    private static readonly XNamespace TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public const string FolderPath = @"\DistractionFirewall";
    public const string RecoveryTaskName = "WorkerRecovery";

    public static string DeadlineTaskName(Guid leaseId)
    {
        return "Deadline-" + leaseId.ToString("N");
    }

    public static string BuildRecoveryTask(string workerPath, string productInstanceId)
    {
        ValidateWorkerPath(workerPath);
        return Build(
            uri: FolderPath + "\\" + RecoveryTaskName,
            marker: "DistractionFirewall/Task/v1/Recovery/" + productInstanceId,
            trigger: new XElement(TaskNamespace + "BootTrigger",
                new XElement(TaskNamespace + "Enabled", true)),
            workerPath,
            arguments: string.Empty,
            executionTimeLimit: "PT0S",
            restartCount: 10,
            wakeToRun: false);
    }

    public static string BuildDeadlineTask(
        string workerPath,
        string productInstanceId,
        Guid leaseId,
        DateTimeOffset expiresAtUtc)
    {
        ValidateWorkerPath(workerPath);
        var utc = expiresAtUtc.ToUniversalTime();
        return Build(
            uri: FolderPath + "\\" + DeadlineTaskName(leaseId),
            marker: "DistractionFirewall/Task/v1/Deadline/" + productInstanceId + "/" + leaseId.ToString("N"),
            trigger: new XElement(TaskNamespace + "TimeTrigger",
                new XElement(TaskNamespace + "StartBoundary", utc.ToString(
                    "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    System.Globalization.CultureInfo.InvariantCulture)),
                new XElement(TaskNamespace + "Enabled", true)),
            workerPath,
            arguments: "reconcile --session " + leaseId.ToString("D"),
            executionTimeLimit: "PT5M",
            restartCount: 3,
            wakeToRun: true);
    }

    public static void ValidateWorkerPath(string workerPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerPath);
        if (!Path.IsPathFullyQualified(workerPath)
            || workerPath.Contains('%', StringComparison.Ordinal)
            || !string.Equals(Path.GetExtension(workerPath), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The Task Scheduler worker path must be a literal, fully-qualified .exe path.",
                nameof(workerPath));
        }
    }

    private static string Build(
        string uri,
        string marker,
        XElement trigger,
        string workerPath,
        string arguments,
        string executionTimeLimit,
        int restartCount,
        bool wakeToRun)
    {
        var principalId = "System";
        var document = new XDocument(
            new XDeclaration("1.0", "UTF-16", null),
            new XElement(TaskNamespace + "Task",
                new XAttribute("version", "1.4"),
                new XElement(TaskNamespace + "RegistrationInfo",
                    new XElement(TaskNamespace + "URI", uri),
                    new XElement(TaskNamespace + "Source", marker),
                    new XElement(TaskNamespace + "Author", "Distraction Firewall"),
                    new XElement(TaskNamespace + "Description", "Product-owned SYSTEM reconciliation task.")),
                new XElement(TaskNamespace + "Triggers", trigger),
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
                    new XElement(TaskNamespace + "WakeToRun", wakeToRun),
                    new XElement(TaskNamespace + "ExecutionTimeLimit", executionTimeLimit),
                    new XElement(TaskNamespace + "Priority", 7),
                    new XElement(TaskNamespace + "RestartOnFailure",
                        new XElement(TaskNamespace + "Interval", "PT1M"),
                        new XElement(TaskNamespace + "Count", restartCount))),
                new XElement(TaskNamespace + "Data", marker),
                new XElement(TaskNamespace + "Actions",
                    new XAttribute("Context", principalId),
                    new XElement(TaskNamespace + "Exec",
                        new XElement(TaskNamespace + "Command", workerPath),
                        string.IsNullOrEmpty(arguments)
                            ? null
                            : new XElement(TaskNamespace + "Arguments", arguments),
                        new XElement(TaskNamespace + "WorkingDirectory", Path.GetDirectoryName(workerPath))))));
        return document.ToString(SaveOptions.DisableFormatting);
    }
}

internal sealed record TaskStateEnvelope
{
    public required string DefinitionXml { get; init; }

    public required string Fingerprint { get; init; }
}

internal static class TaskStateCodec
{
    public const string ContentType = "task-scheduler/definition-v1";

    public static OwnedResourceState Encode(string definitionXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(definitionXml);
        var projection = CreateSecurityProjection(definitionXml);
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(projection)));
        var envelope = new TaskStateEnvelope
        {
            DefinitionXml = definitionXml,
            Fingerprint = fingerprint,
        };
        return OwnedResourceState.Present(ContentType, JsonSerializer.SerializeToUtf8Bytes(envelope));
    }

    public static TaskStateEnvelope Decode(OwnedResourceState state)
    {
        if (!state.Exists || !string.Equals(state.ContentType, ContentType, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Ownership state is not a Task Scheduler definition.");
        }

        return JsonSerializer.Deserialize<TaskStateEnvelope>(state.Data)
            ?? throw new InvalidDataException("Task Scheduler ownership state is invalid.");
    }

    public static bool Equivalent(OwnedResourceState left, OwnedResourceState right)
    {
        if (!left.Exists || !right.Exists)
        {
            return left.Exists == right.Exists;
        }

        if (!string.Equals(left.ContentType, ContentType, StringComparison.Ordinal)
            || !string.Equals(right.ContentType, ContentType, StringComparison.Ordinal))
        {
            return false;
        }

        return string.Equals(Decode(left).Fingerprint, Decode(right).Fingerprint, StringComparison.Ordinal);
    }

    private static string CreateSecurityProjection(string definitionXml)
    {
        var document = XDocument.Parse(definitionXml, LoadOptions.None);
        var root = document.Root ?? throw new InvalidDataException("Task definition has no root element.");
        var projection = new
        {
            Version = (string?)root.Attribute("version"),
            Registration = ProjectElements(root, "RegistrationInfo"),
            Triggers = ProjectElements(root, "Triggers"),
            Principals = ProjectElements(root, "Principals"),
            Settings = ProjectElements(root, "Settings"),
            Data = ProjectElements(root, "Data"),
            Actions = ProjectElements(root, "Actions"),
        };
        return JsonSerializer.Serialize(projection);
    }

    private static string[] ProjectElements(XElement root, string localName)
    {
        var selected = root.Elements().Where(element => element.Name.LocalName == localName);
        return selected
            .SelectMany(element => element.DescendantsAndSelf())
            .Select(element =>
                element.Name.LocalName + "[" +
                string.Join(',', element.Attributes()
                    .OrderBy(attribute => attribute.Name.LocalName, StringComparer.Ordinal)
                    .Select(attribute => attribute.Name.LocalName + "=" + attribute.Value)) +
                "]=" + (element.HasElements ? string.Empty : element.Value))
            .ToArray();
    }
}
