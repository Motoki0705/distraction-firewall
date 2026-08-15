using DistractionFirewall.ActivationService;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Runtime.Windows;

var serviceMode = args.Length == 1 && string.Equals(args[0], "--service", StringComparison.Ordinal);
if (args.Length != 0 && !serviceMode)
{
    Console.Error.WriteLine(
        "Usage: distraction-firewall-activation-service [--service]");
    return 2;
}

try
{
    var paths = RuntimePathResolver.ResolveInstalled(
        RuntimeComponent.ActivationService,
        AppContext.BaseDirectory);
    var settings = await RuntimeSettingsLoader.LoadOrBootstrapRequiredAsync(
        paths,
        new RegistryRuntimeInstallerSeedSource()).ConfigureAwait(false);
    using var composition = WindowsRuntimeComposition.CreateLive(
        paths,
        settings,
        requireLocalSystem: serviceMode);
    var catalog = await TargetCatalog.LoadAsync(paths.TargetCatalogPath).ConfigureAwait(false);
    var nonceService = LeaseNonceService.LoadOrCreate(composition.Store.RootPath);
    ILeaseWorkerLauncher workerLauncher = new ScheduledTaskLeaseWorkerLauncher(
        composition.Store,
        new WindowsRecoveryTaskController(paths, settings));
    var coordinator = new LeaseActivationCoordinator(
        catalog,
        composition.Store,
        composition.Runtime,
        composition.TimeAuthority,
        nonceService,
        workerLauncher);
    var authorization = new AllowListedCallerAuthorizationPolicy(settings.OwnerSids);
    var handler = new ActivationRpcHandler(coordinator, authorization);
    var server = new NamedPipeActivationServer(
        handler,
        new WindowsNamedPipeCallerIdentityResolver(),
        new WindowsAclActivationPipeFactory(settings.OwnerSids),
        Console.Error);

    async Task RunServiceAsync(CancellationToken cancellationToken)
    {
        _ = await coordinator.RecoverOnStartupAsync(cancellationToken).ConfigureAwait(false);
        await server.RunAsync(cancellationToken).ConfigureAwait(false);
    }

    return await WindowsServiceOrConsoleHost.RunAsync(
        "DistractionFirewallActivation",
        serviceMode,
        RunServiceAsync,
        Console.Error).ConfigureAwait(false);
}
catch (Exception exception)
{
    Console.Error.WriteLine(
        $"Activation Service startup failed closed: {exception.GetType().Name}: {exception.Message}");
    return 3;
}
