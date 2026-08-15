using System.Xml.Linq;
using DistractionFirewall.Enforcement.Windows.Dns;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class DnsFilterScheduledTaskTests
{
    [Fact]
    public void DefinitionUsesSystemAndOnlyFixedStructuredArguments()
    {
        var leaseId = Guid.Parse("2961068c-33f0-409e-b716-8ffc37de9d87");
        var request = new DnsFilterLaunchRequest(
            leaseId,
            new DateTimeOffset(2030, 3, 4, 5, 6, 7, TimeSpan.Zero),
            @"C:\ProgramData\DistractionFirewall\targets\active targets.json",
            @"C:\ProgramData\DistractionFirewall\observations",
            new string('a', 64),
            ["1.1.1.1", "2606:4700:4700::1111"]);

        var xml = DnsFilterTaskDefinitionBuilder.Build(
            @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
            "install-a",
            request);
        var document = XDocument.Parse(xml);
        var values = document.Descendants().ToLookup(
            element => element.Name.LocalName,
            element => element.Value,
            StringComparer.Ordinal);

        Assert.Equal("S-1-5-18", Assert.Single(values["UserId"]));
        Assert.Equal("ServiceAccount", Assert.Single(values["LogonType"]));
        Assert.Equal("HighestAvailable", Assert.Single(values["RunLevel"]));
        Assert.Equal(
            @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
            Assert.Single(values["Command"]));
        var arguments = Assert.Single(values["Arguments"]);
        Assert.Contains("dns-filter --lease-id " + leaseId.ToString("D"), arguments, StringComparison.Ordinal);
        Assert.Contains("--target-snapshot \"C:\\ProgramData\\DistractionFirewall\\targets\\active targets.json\"", arguments, StringComparison.Ordinal);
        Assert.Contains("--observation-store \"C:\\ProgramData\\DistractionFirewall\\observations\"", arguments, StringComparison.Ordinal);
        Assert.Contains("--ready-token " + new string('a', 64), arguments, StringComparison.Ordinal);
        Assert.Contains("--upstream 1.1.1.1", arguments, StringComparison.Ordinal);
        Assert.Contains("--upstream 2606:4700:4700::1111", arguments, StringComparison.Ordinal);
        Assert.DoesNotContain("youtube", arguments, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", arguments, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"%ProgramFiles%\filter.exe")]
    [InlineData("C:\\Program Files\\filter.exe\"")]
    [InlineData(@"C:\Program Files\filter.cmd")]
    public void DefinitionRejectsExpandableOrNonExecutableCommand(string executablePath)
    {
        var request = new DnsFilterLaunchRequest(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddHours(1),
            @"C:\ProgramData\DistractionFirewall\targets.json",
            @"C:\ProgramData\DistractionFirewall\observations",
            new string('b', 64),
            ["1.1.1.1"]);

        Assert.Throws<ArgumentException>(() => DnsFilterTaskDefinitionBuilder.Build(
            executablePath,
            "install-a",
            request));
    }

    [Fact]
    public async Task LauncherOwnsRunsAndCasRestoresPerLeaseTask()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var taskStore = new FakeDnsFilterTaskStore();
            var launcher = new ScheduledTaskDnsFilterLauncher(
                taskStore,
                coordinator,
                ledger,
                WindowsMutationGate.CreateForTests(),
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "test-install");
            var request = new DnsFilterLaunchRequest(
                Guid.Parse("3a778ca3-8be5-409a-943f-f674a0bac777"),
                new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero),
                @"C:\ProgramData\DistractionFirewall\targets.json",
                @"C:\ProgramData\DistractionFirewall\observations",
                new string('c', 64),
                ["1.1.1.1"]);

            var result = await launcher.EnsureStartedAsync(request, null, CancellationToken.None);

            Assert.NotNull(result.OwnershipRecordId);
            Assert.Equal(result.TaskResourceId, Assert.Single(taskStore.Restarts));
            Assert.True((await taskStore.ReadAsync(result.TaskResourceId, CancellationToken.None)).Exists);

            var restored = await launcher.RestoreTaskAsync(result.OwnershipRecordId, CancellationToken.None);
            Assert.NotNull(restored);
            Assert.True(restored.Restored);
            Assert.Equal(result.TaskResourceId, Assert.Single(taskStore.Stops));
            Assert.False((await taskStore.ReadAsync(result.TaskResourceId, CancellationToken.None)).Exists);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task OwnedUpstreamChangeCasUpdatesRestartsAndRestoresTaskChain()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var taskStore = new FakeDnsFilterTaskStore();
            var launcher = new ScheduledTaskDnsFilterLauncher(
                taskStore,
                coordinator,
                ledger,
                WindowsMutationGate.CreateForTests(),
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "test-install");
            var firstRequest = CreateRequest("1.1.1.1");
            var first = await launcher.EnsureStartedAsync(firstRequest, null, CancellationToken.None);
            var secondRequest = firstRequest with { UpstreamNameServers = ["9.9.9.9"] };

            var second = await launcher.EnsureStartedAsync(
                secondRequest,
                first.OwnershipRecordId,
                CancellationToken.None);

            Assert.NotNull(second.OwnershipRecordId);
            Assert.NotEqual(first.OwnershipRecordId, second.OwnershipRecordId);
            Assert.Equal(2, taskStore.Restarts.Count);
            var current = TaskStateCodec.Decode(
                await taskStore.ReadAsync(second.TaskResourceId, CancellationToken.None));
            Assert.Contains("--upstream 9.9.9.9", current.DefinitionXml, StringComparison.Ordinal);

            var restoredUpdate = await launcher.RestoreTaskAsync(second.OwnershipRecordId, CancellationToken.None);
            Assert.True(restoredUpdate?.Restored);
            current = TaskStateCodec.Decode(
                await taskStore.ReadAsync(first.TaskResourceId, CancellationToken.None));
            Assert.Contains("--upstream 1.1.1.1", current.DefinitionXml, StringComparison.Ordinal);
            Assert.Equal(3, taskStore.Restarts.Count);

            var restoredOriginal = await launcher.RestoreTaskAsync(first.OwnershipRecordId, CancellationToken.None);
            Assert.True(restoredOriginal?.Restored);
            Assert.False((await taskStore.ReadAsync(first.TaskResourceId, CancellationToken.None)).Exists);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RestoreNeverStopsForeignReplacementTask()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var taskStore = new FakeDnsFilterTaskStore();
            var launcher = new ScheduledTaskDnsFilterLauncher(
                taskStore,
                coordinator,
                ledger,
                WindowsMutationGate.CreateForTests(),
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "test-install");
            var applied = await launcher.EnsureStartedAsync(CreateRequest("1.1.1.1"), null, CancellationToken.None);
            taskStore.Stops.Clear();
            var foreign = TaskStateCodec.Encode(DnsFilterTaskDefinitionBuilder.Build(
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "foreign-install",
                CreateRequest("9.9.9.9")));
            taskStore.Seed(applied.TaskResourceId, foreign);

            var restored = await launcher.RestoreTaskAsync(applied.OwnershipRecordId, CancellationToken.None);

            Assert.NotNull(restored);
            Assert.True(restored.Conflict);
            Assert.Empty(taskStore.Stops);
            Assert.True(taskStore.StatesEqual(
                foreign,
                await taskStore.ReadAsync(applied.TaskResourceId, CancellationToken.None)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FailedOwnedTaskRestartRollsBackAndRestartsPriorDefinition()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var taskStore = new FakeDnsFilterTaskStore();
            var launcher = new ScheduledTaskDnsFilterLauncher(
                taskStore,
                coordinator,
                ledger,
                WindowsMutationGate.CreateForTests(),
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "test-install");
            var first = await launcher.EnsureStartedAsync(
                CreateRequest("1.1.1.1"),
                null,
                CancellationToken.None);
            taskStore.ThrowOnRestartCall = 2;

            await Assert.ThrowsAsync<InvalidOperationException>(() => launcher.EnsureStartedAsync(
                CreateRequest("9.9.9.9"),
                first.OwnershipRecordId,
                CancellationToken.None));

            Assert.Equal(3, taskStore.Restarts.Count);
            var current = TaskStateCodec.Decode(
                await taskStore.ReadAsync(first.TaskResourceId, CancellationToken.None));
            Assert.Contains("--upstream 1.1.1.1", current.DefinitionXml, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task MatchingButUnownedTaskIsNeitherOverwrittenNorRestarted()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var taskStore = new FakeDnsFilterTaskStore();
            var launcher = new ScheduledTaskDnsFilterLauncher(
                taskStore,
                coordinator,
                ledger,
                WindowsMutationGate.CreateForTests(),
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "test-install");
            var request = CreateRequest("1.1.1.1");
            var resourceId = WindowsTaskSchedulerStore.ResourceId(
                DnsFilterTaskDefinitionBuilder.TaskName(request.LeaseId));
            var matching = TaskStateCodec.Encode(DnsFilterTaskDefinitionBuilder.Build(
                @"C:\Program Files\Distraction Firewall\distraction-firewall-dns.exe",
                "test-install",
                request));
            taskStore.Seed(resourceId, matching);

            await Assert.ThrowsAsync<OwnershipConflictException>(() => launcher.EnsureStartedAsync(
                request,
                null,
                CancellationToken.None));

            Assert.Empty(taskStore.Restarts);
            Assert.True(taskStore.StatesEqual(
                matching,
                await taskStore.ReadAsync(resourceId, CancellationToken.None)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static DnsFilterLaunchRequest CreateRequest(string upstream)
    {
        return new DnsFilterLaunchRequest(
            Guid.Parse("3a778ca3-8be5-409a-943f-f674a0bac777"),
            new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero),
            @"C:\ProgramData\DistractionFirewall\targets.json",
            @"C:\ProgramData\DistractionFirewall\observations",
            new string('d', 64),
            [upstream]);
    }

    private static string CreateTemporaryDirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "DistractionFirewall.DnsTask.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
