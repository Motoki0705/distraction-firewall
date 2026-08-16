using System.Security.Principal;
using DistractionFirewall.Contracts;
using DistractionFirewall.Enforcement.Windows.Installation;
using DistractionFirewall.Finalizer;
using DistractionFirewall.Runtime.Windows;

FinalizerCommand command;
try
{
    command = FinalizerCommand.Parse(args);
}
catch (ArgumentException)
{
    Console.Error.WriteLine(FinalizerCommand.Usage);
    return 2;
}

using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

RuntimePaths? paths = null;
var cleanupStage = CleanupFailureStage.ResolveInstalledPaths;
try
{
    paths = RuntimePathResolver.ResolveInstalled(
        RuntimeComponent.Finalizer,
        AppContext.BaseDirectory);
    if (command.Mode is FinalizerMode.GuardRuntimeUninstall or
        FinalizerMode.CleanupRuntimeInstallation)
    {
        cleanupStage = CleanupFailureStage.VerifyExecutionIdentity;
        DemandLocalSystem();
        cleanupStage = CleanupFailureStage.VerifyInactiveLease;
        var guard = new RuntimeUninstallGuard(paths);
        await guard.VerifyInactiveAsync(
            RuntimeUninstallGuard.DefaultLockTimeout,
            shutdown.Token).ConfigureAwait(false);
        if (command.Mode == FinalizerMode.GuardRuntimeUninstall)
        {
            return 0;
        }

        _ = CleanupFailureDiagnostic.TryDelete(paths);
        cleanupStage = CleanupFailureStage.ResolveProductIdentity;
        var cleanupProductInstanceId = await RuntimeSettingsLoader.ResolveInstallationCleanupProductInstanceIdAsync(
            paths,
            shutdown.Token).ConfigureAwait(false);
        cleanupStage = CleanupFailureStage.CreateCleanupBackends;
        var cleanup = WindowsInstallationCleanup.CreateLive(
            new LiveWindowsInstallationCleanupOptions
            {
                ProductInstanceId = cleanupProductInstanceId,
                WorkerExecutablePath = paths.WorkerExecutablePath,
            });
        cleanupStage = CleanupFailureStage.RemoveOwnedInstallationResources;
        await cleanup.CleanupAsync(shutdown.Token).ConfigureAwait(false);
        return 0;
    }

    var settings = await RuntimeSettingsLoader.LoadOrBootstrapRequiredAsync(
        paths,
        new RegistryRuntimeInstallerSeedSource(),
        shutdown.Token).ConfigureAwait(false);
    using var composition = WindowsRuntimeComposition.CreateLive(
        paths,
        settings,
        requireLocalSystem: true);
    var finalizer = new LeaseFinalizer(composition.Runtime);
    var host = new FinalizerHost(composition.Store, composition.TimeAuthority, finalizer);
    var state = await host.RunExpiredOrPendingAsync(
        command.LeaseId!.Value,
        shutdown.Token).ConfigureAwait(false);
    if (state.State == LeaseState.Completed)
    {
        return 0;
    }

    Console.Error.WriteLine($"Lease release remains pending in state {state.State}.");
    return 3;
}
catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
{
    return 1;
}
catch (ActiveLeasePresentException exception)
{
    Console.Error.WriteLine($"Lease Runtime uninstall guard blocked removal: {exception.Message}");
    return 5;
}
catch (Exception exception) when (command.Mode == FinalizerMode.CleanupRuntimeInstallation)
{
    var diagnostic = CleanupFailureDiagnostic.Create(cleanupStage, exception);
    var persisted = paths is not null && CleanupFailureDiagnostic.TryWrite(paths, diagnostic);
    Console.Error.WriteLine(
        $"Lease Runtime installation cleanup failed closed: " +
        $"{CleanupFailureDiagnostic.FormatConsoleSummary(diagnostic)}; " +
        $"diagnostic_persisted={persisted.ToString().ToLowerInvariant()}.");
    return 6;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"Lease Finalizer failed closed: {exception.GetType().Name}: {exception.Message}");
    return 4;
}

static void DemandLocalSystem()
{
    using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
    if (identity.User is null || !identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
    {
        throw new UnauthorizedAccessException(
            "The Runtime uninstall guard must execute as LocalSystem.");
    }
}
