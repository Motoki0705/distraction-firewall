using System.Net.Sockets;
using DistractionFirewall.DnsFilter.Runtime;

namespace DistractionFirewall.DnsFilter;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = DnsFilterOptions.Parse(args);
            var observationStore = await FileDnsObservationStoreAdapter.CreateAsync(
                options.TargetSnapshotPath,
                options.ObservationStorePath,
                TimeProvider.System).ConfigureAwait(false);
            var host = new DnsFilterHost(
                new ObservationStoreTargetAddressObserverFactory(observationStore),
                new LoopbackDnsServerFactory(),
                TimeProvider.System);

            using var shutdown = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                shutdown.Cancel();
            };

            await host.RunAsync(options, shutdown.Token).ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            InvalidDataException or
            InvalidOperationException or
            IOException or
            SocketException or
            UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"DNS filter failed: {exception.Message}");
            return 2;
        }
    }
}
