using System.Xml.Linq;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class TaskSchedulerEnforcementAdapterTests
{
    private const string WorkerPath = @"C:\Program Files\Distraction Firewall\DistractionFirewall.Worker.exe";

    [Theory]
    [InlineData("worker.exe")]
    [InlineData("%PROGRAMFILES%\\Distraction Firewall\\worker.exe")]
    [InlineData(@"C:\Program Files\Distraction Firewall\worker.cmd")]
    public void WorkerPathMustBeLiteralAbsoluteExe(string path)
    {
        Assert.Throws<ArgumentException>(() => TaskDefinitionBuilder.ValidateWorkerPath(path));
    }

    [Fact]
    public void RecoveryDefinitionUsesSystemFixedPathAndFailureRecovery()
    {
        var xml = TaskDefinitionBuilder.BuildRecoveryTask(WorkerPath, "test-install");
        var document = XDocument.Parse(xml);

        Assert.Equal("S-1-5-18", Value(document, "UserId"));
        Assert.Equal("ServiceAccount", Value(document, "LogonType"));
        Assert.Equal("HighestAvailable", Value(document, "RunLevel"));
        Assert.Equal(WorkerPath, Value(document, "Command"));
        Assert.Equal(Path.GetDirectoryName(WorkerPath), Value(document, "WorkingDirectory"));
        Assert.Equal("IgnoreNew", Value(document, "MultipleInstancesPolicy"));
        Assert.Equal("PT0S", Value(document, "ExecutionTimeLimit"));
        Assert.Equal("PT1M", Value(document, "Interval"));
        Assert.Equal("10", Value(document, "Count"));
        Assert.NotNull(document.Descendants().SingleOrDefault(element => element.Name.LocalName == "BootTrigger"));
    }

    [Fact]
    public void DeadlineDefinitionUsesUtcBoundaryAndReconcileOnlyAction()
    {
        var leaseId = Guid.Parse("8a3d329f-4638-4f1d-876f-a9c122c76d6e");
        var xml = TaskDefinitionBuilder.BuildDeadlineTask(
            WorkerPath,
            "test-install",
            leaseId,
            new DateTimeOffset(2030, 2, 3, 13, 5, 6, TimeSpan.FromHours(9)));
        var document = XDocument.Parse(xml);

        Assert.Equal("2030-02-03T04:05:06Z", Value(document, "StartBoundary"));
        Assert.Equal("reconcile --session " + leaseId.ToString("D"), Value(document, "Arguments"));
        Assert.Equal("true", Value(document, "WakeToRun"));
        Assert.Equal("PT5M", Value(document, "ExecutionTimeLimit"));
        Assert.Equal("3", Value(document, "Count"));
    }

    [Fact]
    public async Task ApplyPersistsRecoveryWithoutStartingWorkerAndRestoreDeletesOnlyDeadlineTask()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var store = new FakeTaskSchedulerStore();
            var adapter = new TaskSchedulerEnforcementAdapter(
                store,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.CreateForTests(),
                WorkerPath,
                "test-install");
            var context = TestContextFactory.Create("*://*.youtube.com/*");

            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);

            Assert.Single(artifact.OwnedResourceIds);
            Assert.Empty(store.Runs);
            Assert.True((await store.ReadAsync(
                artifact.Properties["recovery_task"],
                CancellationToken.None)).Exists);
            Assert.True((await store.ReadAsync(
                artifact.Properties["deadline_task"],
                CancellationToken.None)).Exists);
            Assert.True((await adapter.VerifyAsync(context, artifact, CancellationToken.None)).TargetBlocked);

            var restored = await adapter.RestoreAsync(context, artifact, CancellationToken.None);

            Assert.True(restored.Restored);
            Assert.True((await store.ReadAsync(
                artifact.Properties["recovery_task"],
                CancellationToken.None)).Exists);
            Assert.False((await store.ReadAsync(
                artifact.Properties["deadline_task"],
                CancellationToken.None)).Exists);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ConflictingDeadlineTaskFailsBeforeCreatingRecoveryTask()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var store = new FakeTaskSchedulerStore();
            var context = TestContextFactory.Create("*://*.youtube.com/*");
            var deadline = WindowsTaskSchedulerStore.ResourceId(TaskDefinitionBuilder.DeadlineTaskName(context.LeaseId));
            store.Seed(deadline, TaskStateCodec.Encode(TaskDefinitionBuilder.BuildDeadlineTask(
                WorkerPath,
                "foreign-install",
                context.LeaseId,
                context.ExpiresAtUtc)));
            var adapter = new TaskSchedulerEnforcementAdapter(
                store,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.CreateForTests(),
                WorkerPath,
                "test-install");

            await Assert.ThrowsAsync<OwnershipConflictException>(() => adapter.ApplyAsync(
                context,
                CancellationToken.None));
            Assert.Equal(0, store.MutationCount);
            Assert.Empty(store.Runs);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact(Skip = "Requires an isolated disposable Windows 11 x64 VM; registers SYSTEM tasks in the live Task Scheduler service.")]
    public void LiveSystemBootDeadlineAndRecoveryTaskLifecycle()
    {
        throw new NotSupportedException("This gate is intentionally VM-only.");
    }

    private static string Value(XDocument document, string localName)
    {
        return document.Descendants().Single(element => element.Name.LocalName == localName).Value;
    }

    private static string CreateTemporaryDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "DistractionFirewall.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
