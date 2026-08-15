using DistractionFirewall.LeaseWorker;
using DistractionFirewall.Runtime.Windows;

LeaseWorkerCommand command;
try
{
    command = LeaseWorkerCommand.Parse(args);
}
catch (ArgumentException)
{
    Console.Error.WriteLine(LeaseWorkerCommand.Usage);
    return 2;
}

using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

try
{
    var paths = RuntimePathResolver.ResolveInstalled(
        RuntimeComponent.LeaseWorker,
        AppContext.BaseDirectory);
    var settings = await RuntimeSettingsLoader.LoadOrBootstrapRequiredAsync(
        paths,
        new RegistryRuntimeInstallerSeedSource(),
        shutdown.Token).ConfigureAwait(false);
    using var composition = WindowsRuntimeComposition.CreateLive(
        paths,
        settings,
        requireLocalSystem: true);
    var worker = new LeaseWorkerHost(composition.Store, composition.Runtime);
    var state = command.Mode == LeaseWorkerMode.BootRecovery
        ? await worker.RecoverActiveAsync(shutdown.Token).ConfigureAwait(false)
        : await worker.RunAsync(command.LeaseId!.Value, shutdown.Token).ConfigureAwait(false);
    if (state is null)
    {
        Console.Error.WriteLine("Lease Worker recovery found no active capsule.");
        return 0;
    }

    return state.State == DistractionFirewall.Contracts.LeaseState.Completed ? 0 : 3;
}
catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
{
    return 1;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"Lease Worker failed closed: {exception.GetType().Name}: {exception.Message}");
    return 4;
}
