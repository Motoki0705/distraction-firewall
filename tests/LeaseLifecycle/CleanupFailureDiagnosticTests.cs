using System.Diagnostics;
using System.Text;
using System.Text.Json;
using DistractionFirewall.Enforcement.Windows.Installation;
using DistractionFirewall.Finalizer;
using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class CleanupFailureDiagnosticTests
{
    [Fact]
    public void Diagnostic_persists_only_bounded_nonsecret_failure_metadata()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        const string secret = @"C:\Users\private-owner\token-value";
        var exception = new WindowsInstallationCleanupException(
            "windows-wfp-infrastructure",
            "preflight validation",
            new NativeCodeException(0x80320005, secret));
        var occurredAtUtc = new DateTimeOffset(2026, 8, 16, 6, 30, 0, TimeSpan.Zero);
        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.RemoveOwnedInstallationResources,
            exception,
            occurredAtUtc);

        var persisted = CleanupFailureDiagnostic.TryWrite(paths, diagnostic);

        Assert.True(persisted);
        var diagnosticPath = Path.Combine(paths.DataRoot, CleanupFailureDiagnostic.FileName);
        var json = File.ReadAllText(diagnosticPath);
        Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
        Assert.DoesNotContain("message", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("stack", json, StringComparison.OrdinalIgnoreCase);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schema_version").GetInt32());
        Assert.Equal("2026-08-16T06:30:00+00:00", root.GetProperty("occurred_at_utc").GetString());
        Assert.Equal("runtime-installation-cleanup", root.GetProperty("operation").GetString());
        Assert.Equal(
            "remove-owned-installation-resources",
            root.GetProperty("stage").GetString());
        Assert.Equal("windows-wfp-infrastructure", root.GetProperty("backend").GetString());
        Assert.Equal("preflight-validation", root.GetProperty("backend_operation").GetString());
        var exceptions = root.GetProperty("exceptions").EnumerateArray().ToArray();
        Assert.Equal(2, exceptions.Length);
        Assert.Equal(
            typeof(WindowsInstallationCleanupException).FullName,
            exceptions[0].GetProperty("type").GetString());
        Assert.Equal(
            typeof(NativeCodeException).FullName,
            exceptions[1].GetProperty("type").GetString());
        Assert.Equal("0x80320005", exceptions[1].GetProperty("h_result").GetString());
        Assert.All(
            exceptions,
            descriptor => Assert.Matches(
                "^0x[0-9A-F]{8}$",
                descriptor.GetProperty("h_result").GetString()));
        Assert.Empty(Directory.EnumerateFiles(paths.DataRoot, $".{CleanupFailureDiagnostic.FileName}.*.tmp"));
    }

    [Fact]
    public void Persisted_diagnostic_is_accepted_by_the_live_validation_reader()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.RemoveOwnedInstallationResources,
            new WindowsInstallationCleanupException(
                "windows-task-scheduler-infrastructure",
                "compare-and-delete",
                new InvalidOperationException("secret")));
        Assert.True(CleanupFailureDiagnostic.TryWrite(paths, diagnostic));

        var repositoryRoot = FindRepositoryRoot();
        var childTemplate = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "eng",
            "live-validation",
            "templates",
            "Invoke-ElevatedPhase.ps1.template"));
        var reader = ExtractBetween(
            childTemplate,
            "function Copy-ProtectedCleanupDiagnostic {",
            "function Assert-RecoveryProductInstalledDefault {");
        var evidenceRoot = Path.Combine(workspace.RootPath, "evidence");
        Directory.CreateDirectory(evidenceRoot);
        var script = """
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest
            function Assert-Condition {
                param([bool]$Condition, [string]$Message)
                if (-not $Condition) { throw $Message }
            }
            function Get-LowerSha256 {
                param([Parameter(Mandatory)][string]$Path)
                return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $campaign = [pscustomobject]@{
                paths = [pscustomobject]@{ runtime_data_root = $env:DF_DIAGNOSTIC_ROOT }
            }
            $stageEvidenceRoot = $env:DF_EVIDENCE_ROOT
            """ + Environment.NewLine +
            "function Copy-ProtectedCleanupDiagnostic {" + reader + Environment.NewLine +
            """
            $result = Copy-ProtectedCleanupDiagnostic 'contract'
            Assert-Condition ($null -ne $result) 'The diagnostic reader returned no evidence.'
            Assert-Condition ([string]$result.evidence_name -ceq 'contract-installation-cleanup-diagnostic.json') 'The diagnostic reader returned an unexpected evidence name.'
            """;
        var result = RunWindowsPowerShell(
            script,
            new Dictionary<string, string?>
            {
                ["DF_DIAGNOSTIC_ROOT"] = paths.DataRoot,
                ["DF_EVIDENCE_ROOT"] = evidenceRoot,
            });

        Assert.True(
            result.ExitCode == 0,
            $"Live-validation reader rejected the product diagnostic.{Environment.NewLine}{result.StandardError}{Environment.NewLine}{result.StandardOutput}");
        Assert.Equal(
            File.ReadAllBytes(Path.Combine(paths.DataRoot, CleanupFailureDiagnostic.FileName)),
            File.ReadAllBytes(Path.Combine(
                evidenceRoot,
                "contract-installation-cleanup-diagnostic.json")));
    }

    [Fact]
    public void Diagnostic_suppresses_unrecognized_backend_values()
    {
        const string secretBackend = "foreign-backend-secret";
        const string secretOperation = "foreign-operation-secret";
        var exception = new WindowsInstallationCleanupException(
            secretBackend,
            secretOperation,
            new InvalidOperationException("another-secret"));

        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.RemoveOwnedInstallationResources,
            exception);
        var summary = CleanupFailureDiagnostic.FormatConsoleSummary(diagnostic);

        Assert.Null(diagnostic.Backend);
        Assert.Null(diagnostic.BackendOperation);
        Assert.DoesNotContain(secretBackend, summary, StringComparison.Ordinal);
        Assert.DoesNotContain(secretOperation, summary, StringComparison.Ordinal);
        Assert.DoesNotContain("another-secret", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Diagnostic_bounds_the_exception_type_chain()
    {
        Exception exception = new IOException("deep-secret");
        for (var depth = 0; depth < 12; depth++)
        {
            exception = new InvalidOperationException("wrapper-secret", exception);
        }

        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.RemoveOwnedInstallationResources,
            exception);

        Assert.Equal(8, diagnostic.Exceptions.Count);
        Assert.All(
            diagnostic.Exceptions,
            descriptor => Assert.Equal(typeof(InvalidOperationException).FullName, descriptor.Type));
    }

    [Fact]
    public void Diagnostic_write_is_best_effort_for_fixed_leaf_collision()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var diagnosticPath = Path.Combine(paths.DataRoot, CleanupFailureDiagnostic.FileName);
        Directory.CreateDirectory(diagnosticPath);
        var sentinelPath = Path.Combine(diagnosticPath, "sentinel.txt");
        File.WriteAllText(sentinelPath, "keep");
        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.ResolveProductIdentity,
            new InvalidDataException("secret"));

        var persisted = CleanupFailureDiagnostic.TryWrite(paths, diagnostic);

        Assert.False(persisted);
        Assert.Equal("keep", File.ReadAllText(sentinelPath));
        Assert.Empty(Directory.EnumerateFiles(paths.DataRoot, $".{CleanupFailureDiagnostic.FileName}.*.tmp"));
    }

    [Fact]
    public void Diagnostic_delete_removes_only_the_fixed_diagnostic_leaf()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var sentinelPath = Path.Combine(paths.DataRoot, "sentinel.txt");
        File.WriteAllText(sentinelPath, "keep");
        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.CreateCleanupBackends,
            new InvalidOperationException("secret"));
        Assert.True(CleanupFailureDiagnostic.TryWrite(paths, diagnostic));

        var deleted = CleanupFailureDiagnostic.TryDelete(paths);

        Assert.True(deleted);
        Assert.False(File.Exists(Path.Combine(paths.DataRoot, CleanupFailureDiagnostic.FileName)));
        Assert.Equal("keep", File.ReadAllText(sentinelPath));
    }

    [Fact]
    public void Diagnostic_atomically_replaces_the_previous_fixed_leaf()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var first = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.ResolveProductIdentity,
            new InvalidDataException("first-secret"));
        var second = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.CreateCleanupBackends,
            new InvalidOperationException("second-secret"));
        Assert.True(CleanupFailureDiagnostic.TryWrite(paths, first));

        var replaced = CleanupFailureDiagnostic.TryWrite(paths, second);

        Assert.True(replaced);
        using var document = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(paths.DataRoot, CleanupFailureDiagnostic.FileName)));
        Assert.Equal("create-cleanup-backends", document.RootElement.GetProperty("stage").GetString());
        Assert.Empty(Directory.EnumerateFiles(paths.DataRoot, $".{CleanupFailureDiagnostic.FileName}.*.tmp"));
    }

    [Fact]
    public void Diagnostic_refuses_a_data_root_outside_the_program_data_boundary()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var escapedRoot = Path.Combine(workspace.RootPath, "escaped");
        Directory.CreateDirectory(escapedRoot);
        var escapedPaths = paths with { DataRoot = escapedRoot };
        var diagnostic = CleanupFailureDiagnostic.Create(
            CleanupFailureStage.ResolveProductIdentity,
            new InvalidDataException("secret"));

        var persisted = CleanupFailureDiagnostic.TryWrite(escapedPaths, diagnostic);

        Assert.False(persisted);
        Assert.False(File.Exists(Path.Combine(escapedRoot, CleanupFailureDiagnostic.FileName)));
    }

    private static RuntimePaths CreateRuntimePaths(string rootPath)
    {
        var programFilesRoot = Path.Combine(rootPath, "program-files");
        var programDataRoot = Path.Combine(rootPath, "program-data");
        var componentDirectory = Path.Combine(
            programFilesRoot,
            "Distraction Firewall Lease Runtime",
            "finalizer");
        Directory.CreateDirectory(componentDirectory);
        var paths = RuntimePathResolver.ResolveForTests(
            programFilesRoot,
            programDataRoot,
            RuntimeComponent.Finalizer,
            componentDirectory);
        Directory.CreateDirectory(paths.DataRoot);
        return paths;
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "DistractionFirewall.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ??
            throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private static string ExtractBetween(string value, string startMarker, string endMarker)
    {
        var start = value.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Start marker not found: {startMarker}");
        start += startMarker.Length;
        var end = value.IndexOf(endMarker, start, StringComparison.Ordinal);
        Assert.True(end >= start, $"End marker not found: {endMarker}");
        return value[start..end];
    }

    private static PowerShellResult RunWindowsPowerShell(
        string script,
        IReadOnlyDictionary<string, string?> environment)
    {
        var executable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
        foreach (var (name, value) in environment)
        {
            startInfo.Environment[name] = value;
        }

        using var process = new Process { StartInfo = startInfo };
        Assert.True(process.Start(), "Windows PowerShell 5.1 did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Windows PowerShell 5.1 validation timed out.");
        }

        return new PowerShellResult(
            process.ExitCode,
            stdout.GetAwaiter().GetResult(),
            stderr.GetAwaiter().GetResult());
    }

    private sealed record PowerShellResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private sealed class NativeCodeException : Exception
    {
        public NativeCodeException(uint errorCode, string message)
            : base(message)
        {
            HResult = unchecked((int)errorCode);
        }
    }
}
