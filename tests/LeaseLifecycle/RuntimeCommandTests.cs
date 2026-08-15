using DistractionFirewall.Finalizer;
using DistractionFirewall.LeaseWorker;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class RuntimeCommandTests
{
    [Fact]
    public void Worker_no_arguments_selects_boot_recovery()
    {
        var command = LeaseWorkerCommand.Parse(Array.Empty<string>());

        Assert.Equal(LeaseWorkerMode.BootRecovery, command.Mode);
        Assert.Null(command.LeaseId);
    }

    [Fact]
    public void Worker_reconcile_contract_matches_scheduled_task_action()
    {
        var leaseId = Guid.NewGuid();
        var command = LeaseWorkerCommand.Parse(
            ["reconcile", "--session", leaseId.ToString("D")]);

        Assert.Equal(LeaseWorkerMode.ReconcileSession, command.Mode);
        Assert.Equal(leaseId, command.LeaseId);
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("reconcile")]
    [InlineData("reconcile --session not-a-guid")]
    public void Worker_rejects_unrecognized_or_unsafe_arguments(string commandLine)
    {
        Assert.Throws<ArgumentException>(() => LeaseWorkerCommand.Parse(commandLine.Split(' ')));
    }

    [Fact]
    public void Finalizer_accepts_only_explicit_release_session_contract()
    {
        var leaseId = Guid.NewGuid();
        var command = FinalizerCommand.Parse(["release", "--session", leaseId.ToString("D")]);

        Assert.Equal(FinalizerMode.ReleaseSession, command.Mode);
        Assert.Equal(leaseId, command.LeaseId);
        Assert.Throws<ArgumentException>(() => FinalizerCommand.Parse([leaseId.ToString("D")]));
    }

    [Fact]
    public void Finalizer_accepts_only_fixed_runtime_uninstall_guard_contract()
    {
        var command = FinalizerCommand.Parse(["guard-runtime-uninstall"]);

        Assert.Equal(FinalizerMode.GuardRuntimeUninstall, command.Mode);
        Assert.Null(command.LeaseId);
        Assert.Throws<ArgumentException>(() =>
            FinalizerCommand.Parse(["guard-runtime-uninstall", "--root", @"C:\temp"]));
    }

    [Fact]
    public void Finalizer_accepts_only_fixed_runtime_installation_cleanup_contract()
    {
        var command = FinalizerCommand.Parse(["cleanup-runtime-installation"]);

        Assert.Equal(FinalizerMode.CleanupRuntimeInstallation, command.Mode);
        Assert.Null(command.LeaseId);
        Assert.Throws<ArgumentException>(() =>
            FinalizerCommand.Parse(["cleanup-runtime-installation", "--force"]));
    }
}
