using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class RuntimePathsAndSettingsTests
{
    private const string OwnerSid = "S-1-5-21-1000-1000-1000-1001";

    [Fact]
    public void Resolver_centralizes_fixed_runtime_and_data_paths()
    {
        using var workspace = new TestWorkspace();
        var programFiles = Path.Combine(workspace.RootPath, "ProgramFiles");
        var programData = Path.Combine(workspace.RootPath, "ProgramData");
        var workerDirectory = Path.Combine(
            programFiles,
            "Distraction Firewall Lease Runtime",
            "lease-worker");

        var paths = RuntimePathResolver.ResolveForTests(
            programFiles,
            programData,
            RuntimeComponent.LeaseWorker,
            workerDirectory);

        Assert.Equal(
            Path.Combine(workerDirectory, RuntimePaths.WorkerFileName),
            paths.WorkerExecutablePath);
        Assert.Equal(
            Path.Combine(programData, "DistractionFirewall", "Runtime", "v1"),
            paths.LeaseStoreDirectory);
        Assert.Equal(
            Path.Combine(paths.DataRoot, "ownership-ledger"),
            paths.OwnershipLedgerDirectory);
        Assert.Equal(Path.Combine(paths.DataRoot, "settings.json"), paths.SettingsPath);
        Assert.Equal(
            Path.Combine(paths.DataRoot, "dns", "observations", "observed-addresses.json"),
            paths.DnsObservedAddressesPath);
        Assert.Equal(
            Path.Combine(paths.DataRoot, "dns", "target-snapshot.json"),
            paths.DnsTargetSnapshotPath);
        var appRoot = Path.Combine(programFiles, "Distraction Firewall");
        Assert.False(
            paths.RuntimeRoot.StartsWith(
                Path.TrimEndingDirectorySeparator(appRoot) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Resolver_rejects_component_started_outside_fixed_directory()
    {
        using var workspace = new TestWorkspace();
        var programFiles = Path.Combine(workspace.RootPath, "ProgramFiles");
        var programData = Path.Combine(workspace.RootPath, "ProgramData");

        Assert.Throws<InvalidOperationException>(() => RuntimePathResolver.ResolveForTests(
            programFiles,
            programData,
            RuntimeComponent.Finalizer,
            Path.Combine(workspace.RootPath, "copied-finalizer")));
    }

    [Fact]
    public void Test_layout_cannot_enable_live_windows_mutation()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        var settings = ValidSettings();

        Assert.Throws<InvalidOperationException>(() => WindowsRuntimeComposition.CreateLive(
            paths,
            settings,
            requireLocalSystem: false));
    }

    [Fact]
    public async Task Settings_loader_accepts_strict_owner_allowlist()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.DataRoot);
        await File.WriteAllTextAsync(
            paths.SettingsPath,
            $$"""
            {
              "schema_version": 1,
              "product_instance_id": "{{RuntimePaths.ProductInstanceId}}",
              "owner_sids": ["{{OwnerSid}}"]
            }
            """,
            CancellationToken.None);

        var settings = await RuntimeSettingsLoader.LoadRequiredAsync(paths, CancellationToken.None);

        Assert.Equal(RuntimePaths.ProductInstanceId, settings.ProductInstanceId);
        Assert.Equal(OwnerSid, Assert.Single(settings.OwnerSids));
    }

    [Fact]
    public async Task Settings_loader_rejects_unknown_fields()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.DataRoot);
        await File.WriteAllTextAsync(
            paths.SettingsPath,
            $$"""
            {
              "schema_version": 1,
              "product_instance_id": "{{RuntimePaths.ProductInstanceId}}",
              "owner_sids": ["{{OwnerSid}}"],
              "allow_cancel": true
            }
            """,
            CancellationToken.None);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            RuntimeSettingsLoader.LoadRequiredAsync(paths, CancellationToken.None));
    }

    [Fact]
    public async Task Missing_settings_bootstrap_once_from_strict_installer_seed()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.DataRoot);
        var seed = new FakeInstallerSeedSource(new RuntimeInstallerSeed(
            OwnerSid,
            RuntimePaths.ProductInstanceId));

        var first = await RuntimeSettingsLoader.LoadOrBootstrapRequiredAsync(
            paths,
            seed,
            CancellationToken.None);
        var second = await RuntimeSettingsLoader.LoadOrBootstrapRequiredAsync(
            paths,
            seed,
            CancellationToken.None);

        Assert.Equal(OwnerSid, Assert.Single(first.OwnerSids));
        Assert.Equal(first.ProductInstanceId, second.ProductInstanceId);
        Assert.Equal(first.OwnerSids, second.OwnerSids);
        Assert.Equal(1, seed.ReadCount);
        Assert.True(File.Exists(paths.SettingsPath));
        Assert.Empty(Directory.EnumerateFiles(paths.DataRoot, ".settings.*.tmp"));
    }

    [Fact]
    public async Task Invalid_installer_seed_does_not_create_settings()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.DataRoot);
        var seed = new FakeInstallerSeedSource(new RuntimeInstallerSeed(
            "S-1-5-18",
            RuntimePaths.ProductInstanceId));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            RuntimeSettingsLoader.LoadOrBootstrapRequiredAsync(
                paths,
                seed,
                CancellationToken.None));

        Assert.False(File.Exists(paths.SettingsPath));
    }

    [Fact]
    public async Task Never_started_install_cleanup_uses_fixed_seed_without_creating_settings()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.DataRoot);
        var seed = new FakeInstallerSeedSource(new RuntimeInstallerSeed(
            "S-1-5-18",
            RuntimePaths.ProductInstanceId));

        var productInstanceId =
            await RuntimeSettingsLoader.ResolveInstallationCleanupProductInstanceIdAsync(
                paths,
                seed,
                CancellationToken.None);

        Assert.Equal(RuntimePaths.ProductInstanceId, productInstanceId);
        Assert.Equal(1, seed.ReadCount);
        Assert.False(File.Exists(paths.SettingsPath));
    }

    [Fact]
    public async Task Never_started_install_cleanup_rejects_foreign_seed()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.DataRoot);
        var seed = new FakeInstallerSeedSource(new RuntimeInstallerSeed(
            "S-1-5-18",
            "foreign-product"));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            RuntimeSettingsLoader.ResolveInstallationCleanupProductInstanceIdAsync(
                paths,
                seed,
                CancellationToken.None));

        Assert.False(File.Exists(paths.SettingsPath));
    }

    [Fact]
    public async Task Installation_cleanup_does_not_fall_back_when_settings_path_is_not_a_file()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateTestPaths(workspace);
        Directory.CreateDirectory(paths.SettingsPath);
        var seed = new FakeInstallerSeedSource(new RuntimeInstallerSeed(
            "S-1-5-18",
            RuntimePaths.ProductInstanceId));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            RuntimeSettingsLoader.ResolveInstallationCleanupProductInstanceIdAsync(
                paths,
                seed,
                CancellationToken.None));

        Assert.Equal(0, seed.ReadCount);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[\"S-1-0-0\"]")]
    [InlineData("[\"S-1-1-0\"]")]
    [InlineData("[\"S-1-2-0\"]")]
    [InlineData("[\"S-1-5-7\"]")]
    [InlineData("[\"S-1-5-11\"]")]
    [InlineData("[\"S-1-5-18\"]")]
    [InlineData("[\"S-1-5-19\"]")]
    [InlineData("[\"S-1-5-20\"]")]
    [InlineData("[\"S-1-5-32-544\"]")]
    [InlineData("[\"S-1-5-32-545\"]")]
    [InlineData("[\"S-1-5-32-546\"]")]
    [InlineData("[\"not-a-sid\"]")]
    public void Settings_validation_fails_closed_for_missing_or_privileged_owner(string ownersJson)
    {
        var settings = new RuntimeSettings
        {
            SchemaVersion = RuntimeSettings.CurrentSchemaVersion,
            ProductInstanceId = RuntimePaths.ProductInstanceId,
            OwnerSids = System.Text.Json.JsonSerializer.Deserialize<string[]>(ownersJson)!,
        };

        Assert.Throws<InvalidDataException>(() => RuntimeSettingsLoader.Validate(settings));
    }

    private static RuntimePaths CreateTestPaths(TestWorkspace workspace)
    {
        var programFiles = Path.Combine(workspace.RootPath, "ProgramFiles");
        var programData = Path.Combine(workspace.RootPath, "ProgramData");
        var activationDirectory = Path.Combine(
            programFiles,
            "Distraction Firewall Lease Runtime",
            "activation-service");
        return RuntimePathResolver.ResolveForTests(
            programFiles,
            programData,
            RuntimeComponent.ActivationService,
            activationDirectory);
    }

    private static RuntimeSettings ValidSettings() => new()
    {
        SchemaVersion = RuntimeSettings.CurrentSchemaVersion,
        ProductInstanceId = RuntimePaths.ProductInstanceId,
        OwnerSids = [OwnerSid],
    };

    private sealed class FakeInstallerSeedSource : IRuntimeInstallerSeedSource
    {
        private readonly RuntimeInstallerSeed _seed;

        public FakeInstallerSeedSource(RuntimeInstallerSeed seed)
        {
            _seed = seed;
        }

        public int ReadCount { get; private set; }

        public RuntimeInstallerSeed ReadRequired()
        {
            ReadCount++;
            return _seed;
        }
    }
}
