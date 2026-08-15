using System.Globalization;
using System.Text.Json;
using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.Cli;

internal static class Program
{
    private static readonly TimeSpan RpcTimeout = TimeSpan.FromSeconds(15);

    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await RunAsync(args, CancellationToken.None).ConfigureAwait(false);
        }
        catch (RpcClientException exception)
        {
            Console.Error.WriteLine($"サービスエラー ({exception.ErrorCode}): {exception.Message}");
            return exception.Retryable ? 3 : 2;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or IOException or TimeoutException)
        {
            Console.Error.WriteLine($"エラー: {exception.Message}");
            return 2;
        }
    }

    private static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            PrintUsage();
            return 0;
        }

        var client = new NamedPipeRpcClient();
        return args[0].ToLowerInvariant() switch
        {
            "start" => await StartAsync(client, args[1..], cancellationToken).ConfigureAwait(false),
            "status" => await StatusAsync(client, args[1..], cancellationToken).ConfigureAwait(false),
            "targets" => await TargetsAsync(client, args[1..], cancellationToken).ConfigureAwait(false),
            "diagnose" => await DiagnoseAsync(client, args[1..], cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"不明なコマンドです: {args[0]}"),
        };
    }

    private static async Task<int> StartAsync(
        NamedPipeRpcClient client,
        string[] args,
        CancellationToken cancellationToken)
    {
        var options = StartOptions.Parse(args);
        var request = new PrepareLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            options.TargetIds,
            options.End);
        var prepared = await client.CallAsync<PrepareLeaseRequest, PrepareLeaseResponse>(
            RpcMethods.PrepareLease,
            request,
            RpcTimeout,
            cancellationToken).ConfigureAwait(false);

        Console.WriteLine("次の制限を開始します。");
        Console.WriteLine($"対象: {string.Join(", ", prepared.Targets.Select(target => target.DisplayName))}");
        Console.WriteLine($"終了: {prepared.ResolvedExpiresAtUtc.ToLocalTime():yyyy-MM-dd HH:mm zzz}");
        Console.WriteLine("開始後は、アプリから解除・短縮・延長・対象変更できません。");
        foreach (var warning in prepared.Warnings)
        {
            Console.WriteLine($"注意: {warning.Message}");
        }

        if (!options.AssumeYes)
        {
            Console.Write("開始するには START と入力してください: ");
            if (!string.Equals(Console.ReadLine(), "START", StringComparison.Ordinal))
            {
                Console.WriteLine("開始しませんでした。準備情報は短時間で失効します。");
                return 1;
            }
        }

        var commit = new CommitLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            prepared.PreparationId,
            prepared.Nonce);
        var active = await client.CallAsync<CommitLeaseRequest, CommitLeaseResponse>(
            RpcMethods.CommitLease,
            commit,
            RpcTimeout,
            cancellationToken).ConfigureAwait(false);
        Console.WriteLine($"制限を開始しました。Lease: {active.LeaseId:D}");
        Console.WriteLine($"終了: {active.ExpiresAtUtc.ToLocalTime():yyyy-MM-dd HH:mm zzz}");
        return 0;
    }

    private static async Task<int> StatusAsync(
        NamedPipeRpcClient client,
        string[] args,
        CancellationToken cancellationToken)
    {
        EnsureOnlyJsonOption(args);
        var status = await client.CallAsync<ProtocolRequest, LeaseStatusResponse>(
            RpcMethods.GetStatus,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            RpcTimeout,
            cancellationToken).ConfigureAwait(false);
        if (args.Contains("--json", StringComparer.Ordinal))
        {
            Console.WriteLine(JsonSerializer.Serialize(status, ProtocolJson.CreateOptions()));
            return 0;
        }

        Console.WriteLine($"状態: {status.State}");
        if (status.LeaseId is not null)
        {
            Console.WriteLine($"Lease: {status.LeaseId:D}");
            Console.WriteLine($"対象: {string.Join(", ", status.Targets.Select(target => target.DisplayName))}");
            Console.WriteLine($"終了: {status.ExpiresAtUtc?.ToLocalTime():yyyy-MM-dd HH:mm zzz}");
            Console.WriteLine($"健全性: {status.Health}");
        }

        return 0;
    }

    private static async Task<int> TargetsAsync(
        NamedPipeRpcClient client,
        string[] args,
        CancellationToken cancellationToken)
    {
        EnsureOnlyJsonOption(args);
        var catalog = await client.CallAsync<ProtocolRequest, GetTargetCatalogResponse>(
            RpcMethods.GetTargetCatalog,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            RpcTimeout,
            cancellationToken).ConfigureAwait(false);
        if (args.Contains("--json", StringComparer.Ordinal))
        {
            Console.WriteLine(JsonSerializer.Serialize(catalog, ProtocolJson.CreateOptions()));
            return 0;
        }

        foreach (var target in catalog.Targets)
        {
            Console.WriteLine($"{target.StableId}: {target.DisplayName}");
            if (!string.IsNullOrWhiteSpace(target.Description))
            {
                Console.WriteLine($"  {target.Description}");
            }
        }

        return 0;
    }

    private static async Task<int> DiagnoseAsync(
        NamedPipeRpcClient client,
        string[] args,
        CancellationToken cancellationToken)
    {
        EnsureOnlyJsonOption(args);
        var diagnostics = await client.CallAsync<ProtocolRequest, DiagnosticsResponse>(
            RpcMethods.GetDiagnostics,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            RpcTimeout,
            cancellationToken).ConfigureAwait(false);
        if (args.Contains("--json", StringComparer.Ordinal))
        {
            Console.WriteLine(JsonSerializer.Serialize(diagnostics, ProtocolJson.CreateOptions()));
            return diagnostics.Checks.All(check => check.IsHealthy) ? 0 : 4;
        }

        foreach (var check in diagnostics.Checks)
        {
            Console.WriteLine($"[{(check.IsHealthy ? "OK" : check.Severity.ToString().ToUpperInvariant())}] {check.DisplayName}: {check.Summary}");
        }

        return diagnostics.Checks.All(check => check.IsHealthy) ? 0 : 4;
    }

    private static void EnsureOnlyJsonOption(IEnumerable<string> args)
    {
        var invalid = args.FirstOrDefault(argument => !string.Equals(argument, "--json", StringComparison.Ordinal));
        if (invalid is not null)
        {
            throw new ArgumentException($"不明なオプションです: {invalid}");
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Distraction Firewall CLI");
        Console.WriteLine();
        Console.WriteLine("  distraction-firewall-cli targets [--json]");
        Console.WriteLine("  distraction-firewall-cli status [--json]");
        Console.WriteLine("  distraction-firewall-cli diagnose [--json]");
        Console.WriteLine("  distraction-firewall-cli start --target <id> --minutes <1..720> [--yes]");
        Console.WriteLine("  distraction-firewall-cli start --target <id> --until <ISO-8601> [--yes]");
        Console.WriteLine();
        Console.WriteLine("制限開始後の cancel / shorten / extend コマンドはありません。");
    }

    private sealed record StartOptions(
        IReadOnlyList<string> TargetIds,
        LeaseEndRequest End,
        bool AssumeYes)
    {
        public static StartOptions Parse(string[] args)
        {
            var targetIds = new List<string>();
            int? minutes = null;
            DateTimeOffset? until = null;
            var assumeYes = false;

            for (var index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--target":
                        targetIds.Add(ReadValue(args, ref index, "--target"));
                        break;
                    case "--minutes":
                        var minuteText = ReadValue(args, ref index, "--minutes");
                        if (!int.TryParse(minuteText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedMinutes))
                        {
                            throw new FormatException("--minutes には整数を指定してください。");
                        }

                        minutes = parsedMinutes;
                        break;
                    case "--until":
                        var untilText = ReadValue(args, ref index, "--until");
                        if (!DateTimeOffset.TryParse(
                            untilText,
                            CultureInfo.InvariantCulture,
                            DateTimeStyles.RoundtripKind,
                            out var parsedUntil))
                        {
                            throw new FormatException("--until にはUTC offsetを含むISO-8601日時を指定してください。");
                        }

                        until = parsedUntil;
                        break;
                    case "--yes":
                        assumeYes = true;
                        break;
                    default:
                        throw new ArgumentException($"不明なオプションです: {args[index]}");
                }
            }

            if (targetIds.Count == 0)
            {
                throw new ArgumentException("少なくとも一つの --target が必要です。");
            }

            if ((minutes is null) == (until is null))
            {
                throw new ArgumentException("--minutes と --until のどちらか一つだけを指定してください。");
            }

            var end = minutes is not null
                ? new LeaseEndRequest(LeaseEndMode.Duration, minutes, null)
                : new LeaseEndRequest(LeaseEndMode.Until, null, until);
            return new StartOptions(targetIds.Distinct(StringComparer.Ordinal).ToArray(), end, assumeYes);
        }

        private static string ReadValue(string[] args, ref int index, string option)
        {
            if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"{option} の値がありません。");
            }

            return args[index];
        }
    }
}
