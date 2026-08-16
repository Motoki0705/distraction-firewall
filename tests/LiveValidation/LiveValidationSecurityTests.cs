using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

namespace DistractionFirewall.LiveValidation.Tests;

public sealed class LiveValidationSecurityTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string LiveValidationRoot = Path.Combine(RepositoryRoot, "eng", "live-validation");
    private static readonly Lazy<JsonSchema> CandidateSchemaValue = new(() => JsonSchema.FromFile(SchemaPath("build-once-candidate-manifest.schema.json")));
    private static readonly Lazy<JsonSchema> ProvenanceSchemaValue = new(() => JsonSchema.FromFile(SchemaPath("provenance-envelope.schema.json")));
    private static readonly Lazy<JsonSchema> RecoverySchemaValue = new(() => JsonSchema.FromFile(SchemaPath("runtime-recovery-manifest.schema.json")));

    [Theory]
    [InlineData("build-once-candidate-manifest.schema.json")]
    [InlineData("provenance-envelope.schema.json")]
    [InlineData("runtime-recovery-manifest.schema.json")]
    public void Schemas_conform_to_draft_2020_12(string fileName)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(SchemaPath(fileName)));

        var result = MetaSchemas.Draft202012.Evaluate(document.RootElement);

        Assert.Equal(MetaSchemas.Draft202012Id.OriginalString, document.RootElement.GetProperty("$schema").GetString());
        Assert.True(result.IsValid, $"Schema is not valid draft 2020-12: {fileName}");
    }

    [Theory]
    [InlineData("build-once-candidate-manifest.schema.json", "canonical-candidate-manifest.json")]
    [InlineData("provenance-envelope.schema.json", "canonical-provenance-envelope.json")]
    [InlineData("runtime-recovery-manifest.schema.json", "canonical-runtime-recovery-manifest.json")]
    public void Canonical_contract_fixtures_are_accepted(string schemaName, string fixtureName)
    {
        var schema = GetSchema(schemaName);
        var json = File.ReadAllText(FixturePath(fixtureName));

        Assert.True(Evaluate(schema, json), $"Canonical fixture was rejected: {fixtureName}");
    }

    [Theory]
    [InlineData("0.1.0")]
    [InlineData("1.2.3-alpha")]
    [InlineData("1.2.3-alpha.1")]
    [InlineData("1.2.3-0")]
    public void Candidate_schema_accepts_strict_semver(string version)
    {
        var candidate = ReadFixtureObject("canonical-candidate-manifest.json");
        candidate["version"] = version;

        Assert.True(Evaluate(CandidateSchema(), candidate.ToJsonString()));
    }

    [Theory]
    [InlineData("01.2.3")]
    [InlineData("1.02.3")]
    [InlineData("1.2.03")]
    [InlineData("1.2")]
    [InlineData("1.2.3-01")]
    [InlineData("1.2.3-alpha.01")]
    [InlineData("1.2.3-alpha..1")]
    [InlineData("1.2.3-alpha_1")]
    [InlineData("1.2.3+build")]
    [InlineData("1٢.3.4")]
    [InlineData("1.2.3-1٢")]
    [InlineData("1.2.3\r")]
    [InlineData("1.2.3\n")]
    [InlineData("1.2.3\r\n")]
    public void Candidate_schema_rejects_non_strict_semver(string version)
    {
        var candidate = ReadFixtureObject("canonical-candidate-manifest.json");
        candidate["version"] = version;

        Assert.False(Evaluate(CandidateSchema(), candidate.ToJsonString()));
    }

    [Fact]
    public void Candidate_schema_rejects_shape_drift_and_payload_claims_about_post_upload_identity()
    {
        var candidate = ReadFixtureObject("canonical-candidate-manifest.json");
        candidate["source"]!["artifactId"] = 987654;
        Assert.False(Evaluate(CandidateSchema(), candidate.ToJsonString()));

        candidate = ReadFixtureObject("canonical-candidate-manifest.json");
        candidate["source"]!["workflowRef"] = "fork/repo/.github/workflows/release-candidate.yml@refs/heads/main";
        Assert.False(Evaluate(CandidateSchema(), candidate.ToJsonString()));

        candidate = ReadFixtureObject("canonical-candidate-manifest.json");
        candidate["artifacts"]!["sbom"]!["scope"] = "unreviewed-extension";
        Assert.False(Evaluate(CandidateSchema(), candidate.ToJsonString()));
    }

    [Fact]
    public void Recovery_schema_rejects_unapproved_or_extensible_cleanup_targets()
    {
        var schema = RecoverySchemaValue.Value;
        var recovery = ReadFixtureObject("canonical-runtime-recovery-manifest.json");
        recovery["approvedForMachineRecovery"] = false;
        Assert.False(Evaluate(schema, recovery.ToJsonString()));

        recovery = ReadFixtureObject("canonical-runtime-recovery-manifest.json");
        recovery["orphanPackageCaches"]![0]!["deleteRoot"] = "C:\\";
        Assert.False(Evaluate(schema, recovery.ToJsonString()));

        recovery = ReadFixtureObject("canonical-runtime-recovery-manifest.json");
        recovery["runtimeMsi"]!["productCode"] = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}";
        Assert.False(Evaluate(schema, recovery.ToJsonString()));

        recovery = ReadFixtureObject("canonical-runtime-recovery-manifest.json");
        recovery["runtimeMsi"]!["sha256"] = new string('0', 64);
        Assert.False(Evaluate(schema, recovery.ToJsonString()));

        recovery = ReadFixtureObject("canonical-runtime-recovery-manifest.json");
        var caches = recovery["orphanPackageCaches"]!.AsArray();
        var firstCache = caches[0]!.DeepClone();
        var secondCache = caches[1]!.DeepClone();
        caches[0] = secondCache;
        caches[1] = firstCache;
        Assert.False(Evaluate(schema, recovery.ToJsonString()));
    }

    [Fact]
    public void Recovery_execution_is_triply_bound_to_the_single_code_approved_incident()
    {
        var schema = ReadLiveValidationFile("schemas", "runtime-recovery-manifest.schema.json");
        var generator = ReadLiveValidationFile("New-LiveValidationCampaign.ps1");
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        var expectedManifestHash = "29962be5b7992ac17b13ac4aaa0c46320c5a5b4fba481e3b1e46a36bad9366e2";
        var expectedMsiHash = "ef35d8ccb1a110f70dd4f6a9989bbc2b30a0b2b467b4fdc380ce6973b83c50da";
        var expectedProductCode = "{1B676614-3B1F-4646-9788-889C071DAAA0}";

        foreach (var source in new[] { schema, generator, child })
        {
            Assert.Contains(expectedMsiHash, source, StringComparison.Ordinal);
            Assert.Contains(expectedProductCode, source, StringComparison.Ordinal);
            Assert.Contains("pretag-alpha2-runtime-uninstall-1603", source, StringComparison.Ordinal);
            Assert.Contains("{247145F8-425B-46EA-B22F-560F2EE43DAE}", source, StringComparison.Ordinal);
            Assert.Contains("{40C25BD0-2C4F-4697-AE8D-42B6E24EBB41}", source, StringComparison.Ordinal);
        }
        Assert.Contains(expectedManifestHash, generator, StringComparison.Ordinal);
        Assert.Contains(expectedManifestHash, child, StringComparison.Ordinal);
        Assert.Contains("Assert-ApprovedRecoveryIncident", generator, StringComparison.Ordinal);
        Assert.Contains("Assert-ApprovedRecoveryCampaign", child, StringComparison.Ordinal);
        Assert.Contains("approved_manifest_sha256", generator, StringComparison.Ordinal);
        Assert.Contains("approved_manifest_sha256", child, StringComparison.Ordinal);
        Assert.Contains("28ceaabde4f29903813e1431f6599c5072385f7162b7309fa2bb97ea9f67626b", child, StringComparison.Ordinal);
        Assert.Contains("code-approved pre-recovery activation service executable", child, StringComparison.Ordinal);
    }

    [Fact]
    public void Recovery_rejects_absent_advertised_unknown_or_broken_product_state_before_mutation()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        var recovery = ExtractBetween(child, "function Invoke-RecoveryIfPresent", "function Invoke-CandidateUninstall");
        Assert.Contains("Assert-RecoveryProductInstalledDefault $record.productCode", recovery, StringComparison.Ordinal);
        Assert.Contains("INSTALLSTATE_DEFAULT", child, StringComparison.Ordinal);
        Assert.Contains("GetProductInfo($ProductCode, 'VersionString')", child, StringComparison.Ordinal);
        Assert.DoesNotContain("Install-or-repair recovery", recovery, StringComparison.Ordinal);
        Assert.True(
            recovery.IndexOf("Assert-RecoveryProductInstalledDefault", StringComparison.Ordinal) <
            recovery.IndexOf("Invoke-InstallerProcess $msiexec", StringComparison.Ordinal),
            "The exact installed state must be checked before the first recovery mutation.");

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            foreach ($name in @('Assert-Condition', 'Assert-RecoveryProductInstalledDefault')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            function Get-ProductState { param([string]$ProductCode); return $script:fixtureState }
            foreach ($state in @(-1, 0, 1, 2)) {
              $script:fixtureState = $state
              try { Assert-RecoveryProductInstalledDefault '{1B676614-3B1F-4646-9788-889C071DAAA0}'; throw "State $state unexpectedly passed." }
              catch { if ($_.Exception.Message -ceq "State $state unexpectedly passed.") { throw } }
            }
            $script:fixtureState = 5
            Assert-RecoveryProductInstalledDefault '{1B676614-3B1F-4646-9788-889C071DAAA0}'
            'recovery-product-state=passed'
            """;

        var result = RunWindowsPowerShell(script);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("recovery-product-state=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_recovery_machine_state_mismatch_fails_before_the_first_installer_invocation()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        var recovery = ExtractBetween(child, "function Invoke-RecoveryIfPresent", "function Invoke-CandidateUninstall");
        var preflight = ExtractBetween(child, "function Assert-RecoveryMachinePreflight", "function Remove-ExactOrphanPackageCaches");
        Assert.True(
            recovery.IndexOf("Assert-RecoveryMachinePreflight", StringComparison.Ordinal) <
            recovery.IndexOf("Invoke-InstallerProcess $msiexec", StringComparison.Ordinal));
        Assert.True(
            recovery.IndexOf("Assert-AppAbsent", StringComparison.Ordinal) <
            recovery.IndexOf("Invoke-InstallerProcess $msiexec", StringComparison.Ordinal));
        foreach (var required in new[]
                 {
                     "Get-BundleRegistration", "Test-DependencyProvider", "Get-ProductState", "Get-RelatedProducts",
                     "Get-InstalledProductVersion", "Assert-ServiceConfiguration", "Assert-NoOwnedSystemObjects", "Get-ValidatedOrphanPackageCache", "unapproved orphan Bundle cache",
                 })
        {
            Assert.Contains(required, preflight, StringComparison.Ordinal);
        }

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            foreach ($name in @('Assert-Condition', 'Assert-RecoveryMachinePreflight', 'Invoke-RecoveryIfPresent')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            $runtimeProduct = '{1B676614-3B1F-4646-9788-889C071DAAA0}'
            $appProduct = '{40C25BD0-2C4F-4697-AE8D-42B6E24EBB41}'
            $bundle = '{247145F8-425B-46EA-B22F-560F2EE43DAE}'
            $runtimeUpgrade = '{275EC377-2EB2-487F-AD4B-BA0BA85C2FFB}'
            $appUpgrade = '{F6467493-5819-4046-900A-C9FDF87DF7C1}'
            $campaign = [pscustomobject]@{
              fixed = [pscustomobject]@{ RuntimeUpgradeCode = $runtimeUpgrade }
              paths = [pscustomobject]@{ package_cache_root = 'C:\ProgramData\Package Cache' }
              recovery = [pscustomobject]@{
                manifest_path = 'manifest.json'; manifest_size = 1; manifest_sha256 = ('a' * 64); msi_path = 'recovery.msi'
                manifest = [pscustomobject]@{
                  mode = 'repair_then_uninstall'; incidentId = 'fixture'; orphanBundleProviderKeys = @($bundle)
                  expectedInstalled = [pscustomobject]@{ productVersion = '0.1.0'; packageCode = '{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}'; localPackage = [pscustomobject]@{ sizeBytes = 1; sha256 = ('b' * 64) } }
                  runtimeMsi = [pscustomobject]@{ productCode = $runtimeProduct; packageCode = '{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}'; upgradeCode = $runtimeUpgrade; productVersion = '0.1.0'; size = 1; sha256 = ('c' * 64); authenticodeStatus = 'NotSigned' }
                  orphanPackageCaches = @(
                    [pscustomobject]@{ productCode = $appProduct; upgradeCode = $appUpgrade; dependencyProviderKey = 'app-provider'; directoryName = 'app-cache'; payload = [pscustomobject]@{} },
                    [pscustomobject]@{ productCode = $runtimeProduct; upgradeCode = $runtimeUpgrade; dependencyProviderKey = 'runtime-provider'; directoryName = 'runtime-cache'; payload = [pscustomobject]@{} }
                  )
                }
              }
            }
            function Assert-ApprovedRecoveryCampaign { }
            function Assert-AppAbsent { }
            function Assert-LeafFingerprint {
              param($Path, $Size, $Sha256, $AuthenticodeStatus, $Description)
              if ($script:fixtureCase -ceq 'service-binary-fingerprint' -and [string]$Description -ceq 'code-approved pre-recovery activation service executable') { throw 'service-binary-fingerprint' }
            }
            function Assert-MsiRecordIdentity { }
            function Assert-RecoveryProductInstalledDefault { param($ProductCode); if ($script:fixtureCase -ceq 'runtime-state') { throw 'runtime-state' } }
            function Get-InstalledProductVersion { if ($script:fixtureCase -ceq 'product-version') { return '9.9.9' }; return '0.1.0' }
            function Assert-ServiceConfiguration { if ($script:fixtureCase -ceq 'service-config') { throw 'service-config' }; return [pscustomobject]@{} }
            function Assert-NoOwnedSystemObjects { if ($script:fixtureCase -ceq 'owned-object-state') { throw 'owned-object-state' }; return [pscustomobject]@{} }
            function Get-LocalPackage { return 'C:\Windows\Installer\fixture.msi' }
            function Assert-LocalPackageFingerprint { if ($script:fixtureCase -ceq 'local-package') { throw 'local-package' } }
            function Get-BundleRegistration { if ($script:fixtureCase -ceq 'bundle-registration') { return @('registered') }; return @() }
            function Test-DependencyProvider {
              param($Key)
              return ($script:fixtureCase -ceq 'bundle-dependency' -and $Key -ceq $bundle) -or ($script:fixtureCase -ceq 'cache-dependency' -and $Key -ceq 'app-provider')
            }
            function Test-Path { param([string]$LiteralPath, $PathType); return $script:fixtureCase -ceq 'bundle-cache' }
            function Get-ProductState {
              param($ProductCode)
              if ($ProductCode -ceq $appProduct) { return $(if ($script:fixtureCase -ceq 'old-app-state') { 5 } else { -1 }) }
              return 5
            }
            function Get-RelatedProducts {
              param($UpgradeCode)
              if ($UpgradeCode -ceq $runtimeUpgrade) { return @($runtimeProduct) }
              if ($script:fixtureCase -ceq 'old-app-family') { return @($appProduct) }
              return @()
            }
            function Get-ValidatedOrphanPackageCache { if ($script:fixtureCase -ceq 'cache-content') { throw 'cache-content' }; return [pscustomobject]@{ present = $false } }
            function Invoke-InstallerProcess { $script:installerInvocations++; return 0 }
            foreach ($case in @('runtime-state', 'product-version', 'local-package', 'service-config', 'service-binary-fingerprint', 'owned-object-state', 'bundle-registration', 'bundle-dependency', 'bundle-cache', 'old-app-state', 'old-app-family', 'cache-dependency', 'cache-content')) {
              $script:fixtureCase = $case
              $script:installerInvocations = 0
              try { Invoke-RecoveryIfPresent; throw "$case unexpectedly passed" }
              catch { if ($_.Exception.Message -ceq "$case unexpectedly passed") { throw } }
              if ($script:installerInvocations -ne 0) { throw "$case reached an installer invocation" }
            }
            'recovery-preflight-order=passed'
            """;

        var result = RunWindowsPowerShell(script);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("recovery-preflight-order=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Elevated_template_never_reads_Count_directly_from_a_command_pipeline()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest
            function Find-DirectPipelineCount {
              param([Parameter(Mandatory)][Management.Automation.Language.Ast]$Root)
              return @($Root.FindAll({
                param($node)
                if ($node -isnot [Management.Automation.Language.MemberExpressionAst]) { return $false }
                if ($node.Member -isnot [Management.Automation.Language.StringConstantExpressionAst] -or $node.Member.Value -cne 'Count') { return $false }
                if ($node.Expression -isnot [Management.Automation.Language.ParenExpressionAst]) { return $false }
                return @($node.Expression.Pipeline.PipelineElements | Where-Object { $_ -is [Management.Automation.Language.CommandAst] }).Count -gt 0
              }, $true))
            }
            function Parse-Fixture {
              param([Parameter(Mandatory)][string]$Text)
              $tokens = $null
              $errors = $null
              $parsed = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
              if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
              return $parsed
            }
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $templateAst = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            $unsafe = @(Find-DirectPipelineCount $templateAst)
            if ($unsafe.Count -ne 0) { throw "Direct pipeline Count access remains: $($unsafe.Extent.Text -join '; ')" }
            if (@(Find-DirectPipelineCount (Parse-Fixture '(Get-FixtureValue).Count')).Count -ne 1) { throw 'The direct-pipeline detector missed its unsafe fixture.' }
            if (@(Find-DirectPipelineCount (Parse-Fixture '@(Get-FixtureValue).Count')).Count -ne 0) { throw 'The direct-pipeline detector rejected array materialization.' }
            'direct-pipeline-count=passed'
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("direct-pipeline-count=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Absent_product_family_checks_handle_empty_single_and_multiple_outputs_under_windows_powershell_5_1_strict_mode()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            foreach ($name in @('Assert-Condition', 'Assert-RuntimeAbsent', 'Assert-AppAbsent')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              if ($null -eq $functionAst) { throw "Missing function: $name" }
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            $campaign = [pscustomobject]@{
              fixed = [pscustomobject]@{ RuntimeUpgradeCode = 'runtime-upgrade'; AppUpgradeCode = 'app-upgrade' }
              paths = [pscustomobject]@{ runtime_root = 'runtime-root'; runtime_data_root = 'runtime-data'; runtime_seed_key = 'runtime-seed'; app_root = 'app-root' }
            }
            $serviceName = 'fixture-service'
            function Get-Service { return $null }
            function Test-Path { return $false }
            function Get-RelatedProducts {
              switch ($script:fixtureResultCount) {
                0 { return @() }
                1 { return 'product-one' }
                default { return 'product-one', 'product-two', 'product-three' }
              }
            }
            $checks = @(
              [pscustomobject]@{ name = 'Assert-AppAbsent'; error = 'An App MSI remains in the fixed UpgradeCode family.' },
              [pscustomobject]@{ name = 'Assert-RuntimeAbsent'; error = 'A Runtime MSI remains in the fixed UpgradeCode family.' }
            )
            foreach ($check in $checks) {
              foreach ($count in @(0, 1, 3)) {
                $script:fixtureResultCount = $count
                try {
                  & $check.name
                  if ($count -ne 0) { throw "fixture-$($check.name)-$count-unexpectedly-passed" }
                }
                catch {
                  if ($count -eq 0) { throw }
                  if ($_.FullyQualifiedErrorId -match 'PropertyNotFoundStrict') { throw "fixture-$($check.name)-$count-used-scalar-Count" }
                  if ($_.Exception.Message -cne $check.error) { throw }
                }
              }
            }
            'strict-result-cardinality=passed'
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("strict-result-cardinality=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Fatal_diagnostic_preserves_the_bounded_campaign_body_error_when_postflight_also_throws()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        Assert.True(
            child.IndexOf("$script:campaignError = $null", StringComparison.Ordinal) <
            child.IndexOf("$windowsDirectory =", StringComparison.Ordinal),
            "campaignError must be initialized before the first operation that can throw.");
        Assert.Contains("secondary_error = $fatalSecondaryError", child, StringComparison.Ordinal);

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var fixtureRoot = Path.Combine(Path.GetTempPath(), $"df-fatal-diagnostic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(fixtureRoot);
        try
        {
            const string script = """
                $ErrorActionPreference = 'Stop'
                $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
                $tokens = $null
                $errors = $null
                $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
                if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
                $parts = [Collections.Generic.List[string]]::new()
                $parts.Add('Set-StrictMode -Version Latest')
                foreach ($name in @('ConvertTo-BoundedDiagnosticText', 'Write-NewJson')) {
                  $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
                  if ($null -eq $functionAst) { throw "Missing function: $name" }
                  $parts.Add($functionAst.Extent.Text)
                }
                $trapAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.TrapStatementAst] }, $true)
                if ($null -eq $trapAst) { throw 'Missing top-level trap.' }
                $parts.Add('$script:stageCreatedByCampaign = $false')
                $parts.Add('$script:campaignError = ''campaign-body-sentinel''')
                $parts.Add('$returnedEvidenceRoot = $env:LIVE_VALIDATION_FATAL_FIXTURE_ROOT')
                $parts.Add('$campaign = [pscustomobject]@{ campaign_id = ''fatal-fixture'' }')
                $parts.Add($trapAst.Extent.Text)
                $parts.Add("throw ('postflight-sentinel-' + ('x' * 4096))")
                & ([ScriptBlock]::Create(($parts -join "`r`n")))
                """;

            var result = RunWindowsPowerShell(
                script,
                new Dictionary<string, string?> { ["LIVE_VALIDATION_FATAL_FIXTURE_ROOT"] = fixtureRoot });

            Assert.Equal(1, result.ExitCode);
            Assert.DoesNotContain("VariableIsUndefined", result.StandardOutput + result.StandardError, StringComparison.Ordinal);
            var fatalPath = Path.Combine(fixtureRoot, "fatal-error.json");
            Assert.True(File.Exists(fatalPath), $"Fatal evidence was not written. stdout={result.StandardOutput}; stderr={result.StandardError}");
            using var fatal = JsonDocument.Parse(File.ReadAllText(fatalPath));
            var root = fatal.RootElement;
            Assert.Equal("campaign-body-sentinel", root.GetProperty("error").GetString());
            var secondary = root.GetProperty("secondary_error").GetString();
            Assert.NotNull(secondary);
            Assert.Equal(2048, secondary.Length);
            Assert.StartsWith("postflight-sentinel-", secondary, StringComparison.Ordinal);
            Assert.EndsWith("... [truncated]", secondary, StringComparison.Ordinal);
            Assert.Equal(JsonValueKind.Null, root.GetProperty("protected_stage_teardown_error").ValueKind);
        }
        finally
        {
            Directory.Delete(fixtureRoot, recursive: true);
        }
    }

    [Fact]
    public void PowerShell_sources_and_generated_template_shapes_parse_under_windows_powershell_5_1()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $root = $env:LIVE_VALIDATION_REPOSITORY_ROOT
            $files = @(
              'eng\live-validation\Get-BuildOnceCandidate.ps1',
              'eng\live-validation\New-LiveValidationCampaign.ps1',
              'eng\live-validation\templates\Start-Campaign.ps1.template',
              'eng\live-validation\templates\Invoke-ElevatedPhase.ps1.template'
            )
            foreach ($relative in $files) {
              $path = Join-Path $root $relative
              $tokens = $null
              $errors = $null
              [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
              if ($errors.Count -ne 0) { throw "$relative : $($errors.Message -join '; ')" }
            }
            $campaign = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"schema":"fixture"}'))
            $child = [IO.File]::ReadAllText((Join-Path $root 'eng\live-validation\templates\Invoke-ElevatedPhase.ps1.template')).Replace('__CAMPAIGN_BASE64__', $campaign)
            $parent = [IO.File]::ReadAllText((Join-Path $root 'eng\live-validation\templates\Start-Campaign.ps1.template')).Replace('__CAMPAIGN_BASE64__', $campaign).Replace('__ELEVATED_RUNNER_SHA256__', ('a' * 64))
            foreach ($generated in @($child, $parent)) {
              $tokens = $null
              $errors = $null
              [void][System.Management.Automation.Language.Parser]::ParseInput($generated, [ref]$tokens, [ref]$errors)
              if ($errors.Count -ne 0) { throw "generated script: $($errors.Message -join '; ')" }
            }
            "PS=$($PSVersionTable.PSVersion);Edition=$($PSVersionTable.PSEdition);Parsed=4"
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Edition=Desktop", result.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("Parsed=4", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_json_file_read_is_strict_utf8_and_preserves_non_ascii_text_under_windows_powershell_5_1()
    {
        var sources = new[]
        {
            ReadLiveValidationFile("Get-BuildOnceCandidate.ps1"),
            ReadLiveValidationFile("New-LiveValidationCampaign.ps1"),
            ReadLiveValidationFile("templates", "Start-Campaign.ps1.template"),
            ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template"),
        };

        foreach (var source in sources)
        {
            Assert.Contains("function Read-StrictUtf8Json", source, StringComparison.Ordinal);
            Assert.Contains("[Text.UTF8Encoding]::new($false, $true)", source, StringComparison.Ordinal);
            Assert.Contains("[IO.File]::ReadAllBytes($Path)", source, StringComparison.Ordinal);
            Assert.DoesNotContain("Get-Content", source, StringComparison.OrdinalIgnoreCase);
        }

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest
            $root = $env:LIVE_VALIDATION_REPOSITORY_ROOT
            $fixtureRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), "dfw-strict-utf8-$([Guid]::NewGuid().ToString('N'))")
            [void][IO.Directory]::CreateDirectory($fixtureRoot)
            try {
              $validPath = [IO.Path]::Combine($fixtureRoot, 'system-baseline.json')
              $invalidPath = [IO.Path]::Combine($fixtureRoot, 'invalid-utf8.json')
              [IO.File]::WriteAllText($validPath, '{"interfaceAlias":"イーサネット"}', [Text.UTF8Encoding]::new($false, $true))
              [IO.File]::WriteAllBytes($invalidPath, [byte[]]@(0x7B,0x22,0x76,0x61,0x6C,0x75,0x65,0x22,0x3A,0x22,0xC3,0x28,0x22,0x7D))
              $files = @(
                'eng\live-validation\Get-BuildOnceCandidate.ps1',
                'eng\live-validation\New-LiveValidationCampaign.ps1',
                'eng\live-validation\templates\Start-Campaign.ps1.template',
                'eng\live-validation\templates\Invoke-ElevatedPhase.ps1.template'
              )
              foreach ($relative in $files) {
                $path = [IO.Path]::Combine($root, $relative)
                $tokens = $null
                $errors = $null
                $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
                if ($errors.Count -ne 0) { throw "$relative : $($errors.Message -join '; ')" }
                $functionAst = $ast.Find({
                  param($node)
                  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-StrictUtf8Json'
                }, $true)
                if ($null -eq $functionAst) { throw "$relative does not define Read-StrictUtf8Json." }
                . ([ScriptBlock]::Create($functionAst.Extent.Text))
                $record = Read-StrictUtf8Json $validPath
                if ([string]$record.interfaceAlias -cne 'イーサネット') { throw "$relative corrupted a UTF-8 interface alias." }
                $invalidRejected = $false
                try { $null = Read-StrictUtf8Json $invalidPath }
                catch { $invalidRejected = $true }
                if (-not $invalidRejected) { throw "$relative accepted malformed UTF-8." }
              }
              'strict-utf8=passed'
            }
            finally {
              if ([IO.Directory]::Exists($fixtureRoot)) { [IO.Directory]::Delete($fixtureRoot, $true) }
            }
            """;

        var result = RunWindowsPowerShell(script);

        Assert.True(
            result.ExitCode == 0,
            $"Windows PowerShell strict UTF-8 fixture failed.{Environment.NewLine}stdout:{Environment.NewLine}{result.StandardOutput}{Environment.NewLine}stderr:{Environment.NewLine}{result.StandardError}");
        Assert.Contains("strict-utf8=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Elevated_memory_script_initializes_script_scoped_teardown_and_installer_state()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        Assert.Contains("$script:installerRoot = [IO.Path]::Combine($windowsDirectory, 'Installer')", child, StringComparison.Ordinal);
        Assert.Contains("$script:stageCreatedByCampaign = $false", child, StringComparison.Ordinal);
        Assert.Contains("$script:campaignError = $null", child, StringComparison.Ordinal);
        Assert.Contains("[IO.Path]::GetFullPath($script:installerRoot)", child, StringComparison.Ordinal);
        Assert.Contains("if ($script:stageCreatedByCampaign)", child, StringComparison.Ordinal);
        Assert.DoesNotContain("\n$installerRoot = [IO.Path]::Combine($windowsDirectory, 'Installer')", child, StringComparison.Ordinal);
        Assert.DoesNotContain("\n$stageCreatedByCampaign = $false", child, StringComparison.Ordinal);
        var strictMode = child.IndexOf("Set-StrictMode -Version Latest", StringComparison.Ordinal);
        var stageInitializer = child.IndexOf("$script:stageCreatedByCampaign = $false", StringComparison.Ordinal);
        var campaignErrorInitializer = child.IndexOf("$script:campaignError = $null", StringComparison.Ordinal);
        var firstThrow = child.IndexOf("throw ", strictMode, StringComparison.Ordinal);
        Assert.True(
            strictMode >= 0 && stageInitializer > strictMode && stageInitializer < firstThrow,
            "Trap state must be initialized immediately after StrictMode and before the first throwable operation.");
        Assert.True(
            campaignErrorInitializer > strictMode && campaignErrorInitializer < firstThrow,
            "Campaign error state must be initialized before the first throwable operation.");

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            $installerInit = $ast.Find({
              param($node)
              $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Extent.Text -ceq '$script:installerRoot = [IO.Path]::Combine($windowsDirectory, ''Installer'')'
            }, $true)
            $stageInit = $ast.Find({
              param($node)
              $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Extent.Text -ceq '$script:stageCreatedByCampaign = $false'
            }, $true)
            if ($null -eq $installerInit -or $null -eq $stageInit) { throw 'Script-scoped initializers were not found.' }
            $memoryText = @"
            Set-StrictMode -Version Latest
            `$windowsDirectory = 'C:\Windows'
            $($installerInit.Extent.Text)
            $($stageInit.Extent.Text)
            function Get-ScopeProbe {
              [pscustomobject]@{
                installerRoot = `$script:installerRoot
                stageCreatedByCampaign = `$script:stageCreatedByCampaign
              }
            }
            `$probe = Get-ScopeProbe
            if (`$probe.installerRoot -cne 'C:\Windows\Installer') { throw 'installerRoot was not visible from function script scope.' }
            if (`$probe.stageCreatedByCampaign -ne `$false) { throw 'stageCreatedByCampaign was not visible from function script scope.' }
            'memory-script-scope=passed'
            "@
            $output = & ([ScriptBlock]::Create($memoryText))
            if ($output -notcontains 'memory-script-scope=passed') { throw 'Memory ScriptBlock scope probe did not complete.' }
            $output
            """;

        var result = RunWindowsPowerShell(script);

        Assert.True(
            result.ExitCode == 0,
            $"Windows PowerShell memory ScriptBlock fixture failed.{Environment.NewLine}stdout:{Environment.NewLine}{result.StandardOutput}{Environment.NewLine}stderr:{Environment.NewLine}{result.StandardError}");
        Assert.Contains("memory-script-scope=passed", result.StandardOutput, StringComparison.Ordinal);

        const string earlyFatalScript = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            $stageInit = $ast.Find({
              param($node)
              $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Extent.Text -ceq '$script:stageCreatedByCampaign = $false'
            }, $true)
            $campaignErrorInit = $ast.Find({
              param($node)
              $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Extent.Text -ceq '$script:campaignError = $null'
            }, $true)
            $boundedDiagnostic = $ast.Find({
              param($node)
              $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'ConvertTo-BoundedDiagnosticText'
            }, $true)
            $trapAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.TrapStatementAst] }, $true)
            if ($null -eq $stageInit -or $null -eq $campaignErrorInit -or $null -eq $boundedDiagnostic -or $null -eq $trapAst) { throw 'Early-fatal fixture could not find the initializers, diagnostic helper, or trap.' }
            $memoryText = @"
            Set-StrictMode -Version Latest
            $($boundedDiagnostic.Extent.Text)
            $($stageInit.Extent.Text)
            $($campaignErrorInit.Extent.Text)
            $($trapAst.Extent.Text)
            throw 'deliberate-early-fatal'
            "@
            & ([ScriptBlock]::Create($memoryText))
            """;

        var earlyFatalResult = RunWindowsPowerShell(earlyFatalScript);
        var earlyFatalDiagnostics = earlyFatalResult.StandardOutput + Environment.NewLine + earlyFatalResult.StandardError;
        Assert.Equal(1, earlyFatalResult.ExitCode);
        Assert.Contains("deliberate-early-fatal", earlyFatalDiagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("Variable '$script:stageCreatedByCampaign' cannot be retrieved", earlyFatalDiagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("VariableIsUndefined", earlyFatalDiagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void Embedded_native_inspection_code_compiles_under_windows_powershell_5_1_without_calling_native_APIs()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        Assert.Contains("uint capacity = checked(length + 1);", child, StringComparison.Ordinal);
        Assert.Contains("MsiGetProductInfoW(productCode, property, value, ref capacity)", child, StringComparison.Ordinal);
        Assert.DoesNotContain("MsiGetProductInfoW(productCode, property, value, ref length)", child, StringComparison.Ordinal);

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $path = Join-Path $env:LIVE_VALIDATION_REPOSITORY_ROOT 'eng\live-validation\templates\Invoke-ElevatedPhase.ps1.template'
            $text = [IO.File]::ReadAllText($path)
            $match = [regex]::Match($text, "Add-Type -TypeDefinition @'\r?\n(?<source>.*?)\r?\n'@", [Text.RegularExpressions.RegexOptions]::Singleline)
            if (-not $match.Success) { throw 'Native source block was not found.' }
            Add-Type -TypeDefinition $match.Groups['source'].Value
            if ($null -eq ('DistractionFirewall.LiveValidation.NativeInspection' -as [type])) { throw 'Native inspection type did not compile.' }
            'native-compile=passed'
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("native-compile=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Uac_boundary_is_one_short_hash_pinned_in_memory_bootstrap()
    {
        var parent = ReadLiveValidationFile("templates", "Start-Campaign.ps1.template");
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");

        Assert.Equal(1, CountOccurrences(parent, "-Verb RunAs"));
        Assert.Contains("Microsoft.PowerShell.Management\\Start-Process", parent, StringComparison.Ordinal);
        Assert.Contains("'-EncodedCommand', $EncodedBootstrap", parent, StringComparison.Ordinal);
        Assert.Contains("[IO.FileShare]::None", parent, StringComparison.Ordinal);
        Assert.Contains("ComputeHash($bytes)", parent, StringComparison.Ordinal);
        Assert.Contains("[ScriptBlock]::Create($text)", parent, StringComparison.Ordinal);
        Assert.Contains("$stream.CopyTo($memory)", parent, StringComparison.Ordinal);
        Assert.Contains("Start-TrustedElevatedPowerShell", parent, StringComparison.Ordinal);
        Assert.Contains("Invoke-WithSanitizedElevationEnvironment", parent, StringComparison.Ordinal);
        Assert.Contains("-WorkingDirectory $systemDirectory", parent, StringComparison.Ordinal);
        Assert.DoesNotContain("'-File', $elevatedRunner", parent, StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-Expression", parent, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-Expression", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Start-Process -FilePath $windowsPowerShell", child, StringComparison.Ordinal);

        var bootstrap = ExtractBetween(parent, "$bootstrapTemplate = @'", "'@");
        bootstrap = bootstrap.Replace("__RUNNER_PATH__", new string('x', 1024), StringComparison.Ordinal)
            .Replace("__RUNNER_SHA256__", new string('a', 64), StringComparison.Ordinal);
        var encodedLength = Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap)).Length;
        Assert.True(encodedLength < 24000, $"Encoded bootstrap is too long: {encodedLength}");
    }

    [Fact]
    public void PowerShell_module_resolution_is_pinned_before_any_path_or_security_cmdlet()
    {
        var sources = new[]
        {
            ReadLiveValidationFile("Get-BuildOnceCandidate.ps1"),
            ReadLiveValidationFile("New-LiveValidationCampaign.ps1"),
            ReadLiveValidationFile("templates", "Start-Campaign.ps1.template"),
            ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template"),
        };

        foreach (var source in sources)
        {
            var pin = source.IndexOf("$env:PSModulePath = $trustedPowerShellModuleRoot", StringComparison.Ordinal);
            var firstJoinPath = source.IndexOf("Join-Path", StringComparison.Ordinal);
            Assert.True(pin >= 0 && firstJoinPath > pin, "PSModulePath must be pinned before the first Join-Path command.");
            Assert.Contains("[IO.Path]::Combine($trustedPowerShellModuleRoot, $moduleName, \"$moduleName.psd1\")", source, StringComparison.Ordinal);
            Assert.Contains("Microsoft.PowerShell.Core\\Import-Module -Name $moduleManifest", source, StringComparison.Ordinal);
            Assert.Contains("$PSModuleAutoLoadingPreference = 'None'", source, StringComparison.Ordinal);
        }

        var parent = sources[2];
        var child = sources[3];
        Assert.Contains("DnsClient\\Get-DnsClientServerAddress", parent, StringComparison.Ordinal);
        Assert.Contains("DnsClient\\Get-DnsClientServerAddress", child, StringComparison.Ordinal);
        Assert.Contains("CimCmdlets\\Get-CimInstance", child, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Command 'Get-DnsClientServerAddress'", parent, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Command 'Get-DnsClientServerAddress'", child, StringComparison.Ordinal);
    }

    [Fact]
    public void Parent_startup_ignores_a_user_PATH_module_named_like_management()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var fixtureRoot = Path.Combine(Path.GetTempPath(), $"df-malicious-module-{Guid.NewGuid():N}");
        var moduleRoot = Path.Combine(fixtureRoot, "Microsoft.PowerShell.Management");
        var marker = Path.Combine(fixtureRoot, "fake-module-loaded.txt");
        Directory.CreateDirectory(moduleRoot);
        File.WriteAllText(
            Path.Combine(moduleRoot, "Microsoft.PowerShell.Management.psd1"),
            "@{ RootModule = 'Microsoft.PowerShell.Management.psm1'; ModuleVersion = '1.0.0'; FunctionsToExport = @('Join-Path','Start-Process') }");
        File.WriteAllText(
            Path.Combine(moduleRoot, "Microsoft.PowerShell.Management.psm1"),
            "[IO.File]::WriteAllText($env:LIVE_VALIDATION_MODULE_MARKER, 'loaded'); function Join-Path { throw 'fake Join-Path' }; function Start-Process { throw 'fake Start-Process' }; Export-ModuleMember -Function Join-Path,Start-Process");

        const string script = """
            $ErrorActionPreference = 'Stop'
            $source = [IO.File]::ReadAllText($env:LIVE_VALIDATION_SOURCE)
            $start = $source.IndexOf('$windowsDirectory = ', [StringComparison]::Ordinal)
            $endMarker = "`$PSModuleAutoLoadingPreference = 'None'"
            $end = $source.IndexOf($endMarker, $start, [StringComparison]::Ordinal) + $endMarker.Length
            if ($start -lt 0 -or $end -lt $endMarker.Length) { throw 'Trusted startup prefix was not found.' }
            $prefix = $source.Substring($start, $end - $start)
            & ([ScriptBlock]::Create($prefix))
            $module = @(Microsoft.PowerShell.Core\Get-Module -Name Microsoft.PowerShell.Management)
            if ($module.Count -ne 1) { throw 'The trusted Management module was not loaded exactly once.' }
            if (-not $module[0].Path.StartsWith($PSHOME, [StringComparison]::OrdinalIgnoreCase)) { throw "Untrusted module loaded: $($module[0].Path)" }
            if ([IO.File]::Exists($env:LIVE_VALIDATION_MODULE_MARKER)) { throw 'The fake module executed.' }
            'malicious-module=ignored'
            """;

        try
        {
            var result = RunWindowsPowerShell(script, new Dictionary<string, string?>
            {
                ["LIVE_VALIDATION_SOURCE"] = Path.Combine(LiveValidationRoot, "templates", "Start-Campaign.ps1.template"),
                ["LIVE_VALIDATION_MODULE_MARKER"] = marker,
                ["PSModulePath"] = fixtureRoot,
            });

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("malicious-module=ignored", result.StandardOutput, StringComparison.Ordinal);
            Assert.False(File.Exists(marker), "The fake Management module executed before the trust pin.");
        }
        finally
        {
            if (Directory.Exists(fixtureRoot))
            {
                Directory.Delete(fixtureRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void Privileged_path_checks_use_effective_mandatory_integrity_and_reject_low_or_unknown_labels()
    {
        var sources = new[]
        {
            ReadLiveValidationFile("Get-BuildOnceCandidate.ps1"),
            ReadLiveValidationFile("New-LiveValidationCampaign.ps1"),
            ReadLiveValidationFile("templates", "Start-Campaign.ps1.template"),
            ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template"),
        };
        foreach (var source in sources)
        {
            Assert.Contains("GetNamedSecurityInfoW", source, StringComparison.Ordinal);
            Assert.Contains("LabelSecurityInformation = 0x00000010", source, StringComparison.Ordinal);
            Assert.Contains("Assert-AcceptableMandatoryIntegritySddl", source, StringComparison.Ordinal);
            Assert.Contains("S-1-16-8192", source, StringComparison.Ordinal);
            Assert.Contains("S-1-16-12288", source, StringComparison.Ordinal);
            Assert.Contains("S-1-16-16384", source, StringComparison.Ordinal);
        }

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Start-Campaign.ps1.template')
            $source = [IO.File]::ReadAllText($templatePath)
            $typeMatch = [regex]::Match($source, "Microsoft\.PowerShell\.Utility\\Add-Type -TypeDefinition @'\r?\n(?<source>.*?MandatoryIntegrityInspection.*?)\r?\n'@", [Text.RegularExpressions.RegexOptions]::Singleline)
            if (-not $typeMatch.Success) { throw 'Mandatory-integrity native source was not found.' }
            Add-Type -TypeDefinition $typeMatch.Groups['source'].Value
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            foreach ($name in @('Assert-Condition', 'Assert-AcceptableMandatoryIntegritySddl')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              if ($null -eq $functionAst) { throw "Function not found: $name" }
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }

            foreach ($accepted in @('', 'S:(ML;;NW;;;ME)', 'S:(ML;;NW;;;HI)', 'S:(ML;;NW;;;SI)')) {
              Assert-AcceptableMandatoryIntegritySddl $accepted 'accepted fixture'
            }
            foreach ($rejected in @(
              'S:(ML;;NW;;;UI)',
              'S:(ML;;NW;;;LW)',
              'S:(ML;;NW;;;S-1-16-8448)',
              'S:(ML;;NR;;;ME)',
              'S:(ML;;NW;;;ME)(ML;;NW;;;HI)',
              'S:not-valid'
            )) {
              try { Assert-AcceptableMandatoryIntegritySddl $rejected 'rejected fixture'; throw "Rejected label passed: $rejected" }
              catch { if ($_.Exception.Message -ceq "Rejected label passed: $rejected") { throw } }
            }

            $actualPaths = @(
              [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
              [Environment]::GetFolderPath([Environment+SpecialFolder]::System),
              [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData), 'Package Cache')
            )
            foreach ($path in $actualPaths) {
              if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) {
                $sddl = [DistractionFirewall.LiveValidation.MandatoryIntegrityInspection]::GetLabelSddl($path)
                Assert-AcceptableMandatoryIntegritySddl $sddl "actual protected path $path"
              }
            }
            $localLow = [IO.Path]::Combine([IO.Path]::GetDirectoryName([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)), 'LocalLow')
            if ([IO.Directory]::Exists($localLow)) {
              $lowSddl = [DistractionFirewall.LiveValidation.MandatoryIntegrityInspection]::GetLabelSddl($localLow)
              if ($lowSddl -notmatch '\(ML;') { throw 'LocalLow explicit mandatory label was not retrieved.' }
              try { Assert-AcceptableMandatoryIntegritySddl $lowSddl 'LocalLow negative control'; throw 'LocalLow unexpectedly passed.' }
              catch { if ($_.Exception.Message -ceq 'LocalLow unexpectedly passed.') { throw } }
            }
            'mandatory-integrity=passed'
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("mandatory-integrity=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Loader_environment_matching_is_case_insensitive_and_sanitization_restores_on_throw()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Start-Campaign.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            foreach ($name in @('Assert-Condition', 'Test-DangerousLoaderEnvironmentName', 'Get-DangerousLoaderEnvironmentFindings', 'Invoke-WithSanitizedElevationEnvironment')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              if ($null -eq $functionAst) { throw "Function not found: $name" }
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            $fixture = [ordered]@{
              Process = @{ 'cOr_Enable_Profiling' = '1' }
              User = @{ 'coreClr_Profiler_Path' = 'x'; 'DOTNET_CLI_TELEMETRY_OPTOUT' = '1' }
              Machine = @{ 'dotnet_startup_hooks' = 'x'; 'AppDomain_Manager_Assembly' = 'x' }
            }
            $findings = @(Get-DangerousLoaderEnvironmentFindings $fixture)
            if ($findings.Count -ne 4) { throw "Expected four dangerous findings, got $($findings.Count)." }
            if (@($findings | Where-Object { $_.PSObject.Properties.Name -contains 'value' }).Count -ne 0) { throw 'A loader value leaked into findings.' }
            if (Test-DangerousLoaderEnvironmentName 'DOTNET_CLI_TELEMETRY_OPTOUT') { throw 'A benign DOTNET variable was rejected.' }

            $systemDirectory = 'C:\trusted-system'
            $windowsDirectory = 'C:\trusted-windows'
            $trustedPowerShellHome = 'C:\trusted-powershell'
            $trustedPowerShellModuleRoot = 'C:\trusted-modules'
            $before = [ordered]@{
              PATH = $env:PATH
              PSModulePath = $env:PSModulePath
              PATHEXT = $env:PATHEXT
              PSExecutionPolicyPreference = $env:PSExecutionPolicyPreference
              SystemRoot = $env:SystemRoot
              windir = $env:windir
              ComSpec = $env:ComSpec
            }
            [Environment]::SetEnvironmentVariable('cOr_Test_Sentinel', 'restore-me', 'Process')
            $clean = [ordered]@{ Process = @{}; User = @{}; Machine = @{} }
            try {
              try {
                Invoke-WithSanitizedElevationEnvironment -EnvironmentByScope $clean -Operation {
                  if ($null -ne [Environment]::GetEnvironmentVariable('cOr_Test_Sentinel', 'Process')) { throw 'dangerous-variable-not-cleared' }
                  if ($env:PATH -cne 'C:\trusted-system;C:\trusted-windows;C:\trusted-powershell') { throw 'path-not-normalized' }
                  throw 'injected-operation-failure'
                }
                throw 'The injected operation unexpectedly returned.'
              }
              catch {
                if ($_.Exception.Message -cne 'injected-operation-failure') { throw }
              }
              foreach ($name in $before.Keys) {
                $actual = [Environment]::GetEnvironmentVariable($name, 'Process')
                $expected = $before[$name]
                if (($null -eq $expected -and $null -ne $actual) -or ($null -ne $expected -and $actual -cne [string]$expected)) { throw "Environment was not restored: $name" }
              }
              if ([Environment]::GetEnvironmentVariable('cOr_Test_Sentinel', 'Process') -cne 'restore-me') { throw 'Dangerous variable was not restored.' }
              'loader-environment=passed'
            }
            finally { [Environment]::SetEnvironmentVariable('cOr_Test_Sentinel', $null, 'Process') }
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("loader-environment=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void GitHub_cli_trust_does_not_follow_a_PATH_hijack()
    {
        var downloader = ReadLiveValidationFile("Get-BuildOnceCandidate.ps1");
        var generator = ReadLiveValidationFile("New-LiveValidationCampaign.ps1");

        foreach (var source in new[] { downloader, generator })
        {
            Assert.Contains("[Environment+SpecialFolder]::ProgramFiles", source, StringComparison.Ordinal);
            Assert.Contains("'GitHub CLI'", source, StringComparison.Ordinal);
            Assert.Contains("'gh.exe'", source, StringComparison.Ordinal);
            Assert.Contains("Assert-TrustedGitHubCliPathAcl", source, StringComparison.Ordinal);
            Assert.Contains("Get-AuthenticodeSignature -LiteralPath $cliPath", source, StringComparison.Ordinal);
            Assert.Contains("GitHub, Inc.", source, StringComparison.Ordinal);
            Assert.Contains("$env:GH_HOST = 'github.com'", source, StringComparison.Ordinal);
            Assert.Contains("$env:GH_ENTERPRISE_TOKEN = $null", source, StringComparison.Ordinal);
            Assert.Contains("$env:GH_CONFIG_DIR = $configDirectory", source, StringComparison.Ordinal);
            Assert.Contains("distraction-firewall-gh-", source, StringComparison.Ordinal);
            Assert.Contains("$env:XDG_CONFIG_HOME = $null", source, StringComparison.Ordinal);
            Assert.Contains("$env:GH_FORCE_TTY = $null", source, StringComparison.Ordinal);
            Assert.DoesNotContain("$env:GH_FORCE_TTY = '0'", source, StringComparison.Ordinal);
            Assert.Contains("$env:GH_PROMPT_DISABLED = '1'", source, StringComparison.Ordinal);
            Assert.Contains("$env:GH_NO_UPDATE_NOTIFIER = '1'", source, StringComparison.Ordinal);
            Assert.Contains("[IO.Directory]::Delete($isolatedConfigDirectory, $true)", source, StringComparison.Ordinal);
            Assert.Contains("[Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')", source, StringComparison.Ordinal);
            Assert.Contains("[Diagnostics.ProcessStartInfo]::new()", source, StringComparison.Ordinal);
            Assert.Contains("$startInfo.UseShellExecute = $false", source, StringComparison.Ordinal);
            Assert.Contains("$startInfo.RedirectStandardOutput = $true", source, StringComparison.Ordinal);
            Assert.Contains("$startInfo.RedirectStandardError = $true", source, StringComparison.Ordinal);
            Assert.Contains("$process.StandardOutput.ReadToEndAsync()", source, StringComparison.Ordinal);
            Assert.Contains("$process.StandardError.ReadToEndAsync()", source, StringComparison.Ordinal);
            Assert.Contains("$process.WaitForExit($TimeoutMilliseconds)", source, StringComparison.Ordinal);
            Assert.Contains("$process.Kill()", source, StringComparison.Ordinal);
            Assert.Contains("$process.WaitForExit(10000)", source, StringComparison.Ordinal);
            Assert.Contains("Protect-GitHubCliDiagnosticText", source, StringComparison.Ordinal);
            Assert.Contains("-SensitiveValue $Token -MaximumLength 4096", source, StringComparison.Ordinal);
            Assert.Contains("Invoke-CapturedNativeProcess -FilePath $TrustedGitHubCli.path -Arguments $Arguments", source, StringComparison.Ordinal);
            Assert.Contains("Invoke-CapturedNativeProcess -FilePath $cliPath -Arguments @('--version')", source, StringComparison.Ordinal);
            Assert.DoesNotContain("2>&1", source, StringComparison.Ordinal);
            Assert.DoesNotContain("& $TrustedGitHubCli.path", source, StringComparison.Ordinal);
            Assert.DoesNotContain("Get-Command 'gh", source, StringComparison.OrdinalIgnoreCase);

            var processBoundary = ExtractBetween(source, "function Invoke-CapturedNativeProcess", "function Resolve-TrustedGitHubCli");
            Assert.DoesNotContain("$Token", processBoundary, StringComparison.Ordinal);
        }

        Assert.Contains("'auth', 'token', '--hostname', 'github.com') -UseUserAuthenticationConfig", downloader, StringComparison.Ordinal);
        Assert.Contains("'api', '--hostname', 'github.com'", generator, StringComparison.Ordinal);
        Assert.Contains("-Token $trustedGitHubToken", generator, StringComparison.Ordinal);
        Assert.Contains("$attestationCall.diagnostic", generator, StringComparison.Ordinal);
        Assert.Contains("tooling =", generator, StringComparison.Ordinal);
        Assert.Contains("github_cli = $trustedGitHubCli", generator, StringComparison.Ordinal);
    }

    [Fact]
    public void Trusted_GitHub_CLI_capture_accepts_success_stderr_and_round_trips_Windows_arguments()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var fixtureRoot = Path.Combine(Path.GetTempPath(), $"df-gh-stderr-{Guid.NewGuid():N}");
        var fixtureScript = Path.Combine(fixtureRoot, "emit-success-stderr.ps1");
        Directory.CreateDirectory(fixtureRoot);
        File.WriteAllText(
            fixtureScript,
            """
            $ErrorActionPreference = 'Stop'
            if ($null -ne $env:GH_FORCE_TTY) {
              [Console]::Error.WriteLine('GH_FORCE_TTY leaked into the child process')
              exit 9
            }
            if ($args.Count -gt 0 -and $args[0] -ceq '__failure__') {
              [Console]::Out.WriteLine("failure stdout token=$env:GH_TOKEN " + ('o' * 8192))
              [Console]::Error.WriteLine("failure stderr token=$env:GH_TOKEN " + ('e' * 8192))
              exit 23
            }
            if ($args.Count -gt 0 -and $args[0] -ceq '__large__') {
              [Console]::Out.WriteLine('o' * 131072)
              [Console]::Error.WriteLine('e' * 131072)
              exit 0
            }
            foreach ($value in $args) {
              [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value)))
            }
            [Console]::Error.WriteLine('Loaded digest fixture')
            exit 0
            """,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        const string script = """
            $ErrorActionPreference = 'Stop'
            $expected = @(
              'plain',
              'value with spaces',
              'quote"inside',
              'C:\folder with spaces\',
              'two\\before"quote'
            )
            $nativePowerShell = [IO.Path]::Combine(
              [Environment]::GetFolderPath([Environment+SpecialFolder]::System),
              'WindowsPowerShell',
              'v1.0',
              'powershell.exe')
            $nativeArguments = @(
              '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
              '-File', $env:LIVE_VALIDATION_STDERR_FIXTURE
            ) + $expected

            foreach ($sourceName in @('Get-BuildOnceCandidate.ps1', 'New-LiveValidationCampaign.ps1')) {
              $sourcePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', $sourceName)
              $tokens = $null
              $errors = $null
              $ast = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$errors)
              if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
              foreach ($name in @(
                'Assert-Condition',
                'ConvertTo-WindowsCommandLineArgument',
                'ConvertFrom-CapturedProcessText',
                'Protect-GitHubCliDiagnosticText',
                'Invoke-CapturedNativeProcess',
                'Invoke-TrustedGitHubCli'
              )) {
                $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
                if ($null -eq $functionAst) { throw "Function not found in ${sourceName}: $name" }
                . ([ScriptBlock]::Create($functionAst.Extent.Text))
              }

              $trustedFixture = [pscustomobject]@{ path = $nativePowerShell }
              $call = Invoke-TrustedGitHubCli -TrustedGitHubCli $trustedFixture -Arguments $nativeArguments -Token 'fixture-token-not-for-output'
              if ($call.exit_code -ne 0) { throw "Captured process failed for ${sourceName}: $(@($call.error) -join ' ')" }
              if (@($call.error).Count -ne 1 -or [string]$call.error[0] -cne 'Loaded digest fixture') { throw "Success stderr was not captured separately for ${sourceName}." }
              if (@($call.output).Count -ne $expected.Count) { throw "Argument result count mismatch for ${sourceName}." }
              for ($index = 0; $index -lt $expected.Count; $index++) {
                $actual = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$call.output[$index]))
                if ($actual -cne $expected[$index]) { throw "Argument $index changed for ${sourceName}: '$actual'" }
              }
              if ($env:GH_FORCE_TTY -cne '80') { throw "GH_FORCE_TTY was not restored for ${sourceName}." }
              if ((@($call.output) + @($call.error) -join "`n").Contains('fixture-token-not-for-output')) { throw "Token leaked into captured output for ${sourceName}." }

              $failureCall = Invoke-TrustedGitHubCli -TrustedGitHubCli $trustedFixture -Arguments ($nativeArguments[0..6] + '__failure__') -Token 'fixture-token-not-for-output'
              if ($failureCall.exit_code -ne 23) { throw "Nonzero exit code changed for ${sourceName}: $($failureCall.exit_code)" }
              if ($failureCall.diagnostic.Length -gt 4096) { throw "Failure diagnostic was not bounded for ${sourceName}." }
              $failureText = @(@($failureCall.output) + @($failureCall.error) + @($failureCall.diagnostic)) -join "`n"
              if ($failureText.Contains('fixture-token-not-for-output')) { throw "Token leaked into failure diagnostics for ${sourceName}." }
              if (-not $failureText.Contains('[REDACTED]') -or -not $failureText.Contains('...[truncated]')) { throw "Failure diagnostic was not redacted and truncated for ${sourceName}." }
              if ($env:GH_FORCE_TTY -cne '80') { throw "GH_FORCE_TTY was not restored after failure for ${sourceName}." }

              $largeCall = Invoke-TrustedGitHubCli -TrustedGitHubCli $trustedFixture -Arguments ($nativeArguments[0..6] + '__large__') -Token 'fixture-token-not-for-output'
              if ($largeCall.exit_code -ne 0) { throw "Large dual-stream process failed for ${sourceName}." }
              if (([string]$largeCall.output[0]).Length -lt 131072 -or ([string]$largeCall.error[0]).Length -lt 131072) { throw "Large dual streams were not fully drained for ${sourceName}." }
              if ($env:GH_FORCE_TTY -cne '80') { throw "GH_FORCE_TTY was not restored after large output for ${sourceName}." }
            }
            'github-success-stderr=passed'
            """;

        try
        {
            var result = RunWindowsPowerShell(script, new Dictionary<string, string?>
            {
                ["LIVE_VALIDATION_STDERR_FIXTURE"] = fixtureScript,
                ["GH_FORCE_TTY"] = "80",
            });

            Assert.True(
                result.ExitCode == 0,
                $"Native Windows PowerShell stderr-capture fixture failed. stdout: {result.StandardOutput} stderr: {result.StandardError}");
            Assert.Contains("github-success-stderr=passed", result.StandardOutput, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(fixtureRoot))
            {
                Directory.Delete(fixtureRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void Elevated_phase_has_no_external_arguments_or_arbitrary_command_broker()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        var prefix = child[..Math.Min(child.Length, 300)];

        var normalizedPrefix = prefix.Replace("\r\n", "\n", StringComparison.Ordinal);
        Assert.Contains("[CmdletBinding()]\nparam()", normalizedPrefix, StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-Command", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ScriptBlock]::Create", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Win32_Product", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Start-Process -FilePath $env:ComSpec", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("& $env:ComSpec", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("schtasks.exe", child, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("$msiexec = [IO.Path]::Combine($systemDirectory, 'msiexec.exe')", child, StringComparison.Ordinal);
        Assert.Contains("$netsh = [IO.Path]::Combine($systemDirectory, 'netsh.exe')", child, StringComparison.Ordinal);
        Assert.Contains("Assert-TrustedSystemBinary $msiexec", child, StringComparison.Ordinal);
        Assert.Contains("Assert-TrustedSystemBinary $netsh", child, StringComparison.Ordinal);
        Assert.DoesNotContain("Join-Path $env:SystemRoot", child, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Join-Path $stagePayloadRoot 'candidate-setup.exe'", child, StringComparison.Ordinal);
        Assert.Contains("Assert-MsiRecordIdentity", child, StringComparison.Ordinal);
    }

    [Fact]
    public void Standard_user_parent_smokes_only_read_only_cli_and_noninvoking_UI_controls()
    {
        var parent = ReadLiveValidationFile("templates", "Start-Campaign.ps1.template");

        Assert.Contains("[ValidateSet('targets', 'status', 'diagnose')]", parent, StringComparison.Ordinal);
        Assert.Contains("$startInfo.Arguments = \"$Command --json\"", parent, StringComparison.Ordinal);
        Assert.Contains("$principal.IsInRole", parent, StringComparison.Ordinal);
        Assert.Contains("Campaign parent must remain non-elevated", parent, StringComparison.Ordinal);
        Assert.DoesNotContain("InvokePattern", parent, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("lease_controls_invoked = $false", parent, StringComparison.Ordinal);
        Assert.Contains("lease_start_invoked = $false", parent, StringComparison.Ordinal);

        string[] expectedLabels =
        [
            "YouTube", "期間を指定", "指定時刻まで", "任意の分数", "確認へ",
            "15分", "30分", "1時間", "2時間", "4時間", "8時間", "12時間",
        ];
        foreach (var label in expectedLabels)
        {
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(label));
            Assert.True(parent.Contains(label, StringComparison.Ordinal) || parent.Contains(encoded, StringComparison.Ordinal), $"UI smoke is missing '{label}'.");
        }
    }

    [Fact]
    public void Preparation_binds_exact_archive_inventory_api_metadata_and_attestations()
    {
        var generator = ReadLiveValidationFile("New-LiveValidationCampaign.ps1");

        Assert.Contains("exact nine-file inventory", generator, StringComparison.Ordinal);
        Assert.Contains("$expectedArchiveNames", generator, StringComparison.Ordinal);
        Assert.Contains("Count -eq 9", generator, StringComparison.Ordinal);
        Assert.Contains("candidate-subjects.sha256", generator, StringComparison.Ordinal);
        Assert.Contains("hosted-evidence.json", generator, StringComparison.Ordinal);
        Assert.Contains("provenance.bundle.json", generator, StringComparison.Ordinal);
        Assert.Contains("Invoke-TrustedGitHubCli $trustedGitHubCli", generator, StringComparison.Ordinal);
        Assert.Contains("-Token $trustedGitHubToken", generator, StringComparison.Ordinal);
        Assert.Contains("--deny-self-hosted-runners", generator, StringComparison.Ordinal);
        Assert.Contains("'--source-ref', 'refs/heads/main'", generator, StringComparison.Ordinal);
        Assert.Contains("head_repository.full_name", generator, StringComparison.Ordinal);
        Assert.Contains("workflow_dispatch", generator, StringComparison.Ordinal);
        Assert.Contains("artifactArchiveSizeBytes", generator, StringComparison.Ordinal);
        Assert.Contains("Raw artifact archive SHA-256", generator, StringComparison.Ordinal);
    }

    [Fact]
    public void Candidate_downloader_preserves_binary_bytes_and_does_not_forward_GitHub_token_to_blob_host()
    {
        var downloader = ReadLiveValidationFile("Get-BuildOnceCandidate.ps1");

        Assert.Contains("$handler.AllowAutoRedirect = $false", downloader, StringComparison.Ordinal);
        Assert.Contains("separate", downloader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("anonymous client", downloader, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, CountOccurrences(downloader, "DefaultRequestHeaders.Authorization"));
        Assert.Contains("[IO.FileMode]::CreateNew", downloader, StringComparison.Ordinal);
        Assert.Contains("$source.CopyTo($destination)", downloader, StringComparison.Ordinal);
        Assert.DoesNotContain("Out-File", downloader, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-WebRequest", downloader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("head_repository.full_name", downloader, StringComparison.Ordinal);
        Assert.Contains("sourceRepository =", downloader, StringComparison.Ordinal);
        Assert.Contains("github-api-receipt.json", downloader, StringComparison.Ordinal);
        Assert.Contains("GetFileName($entry.FullName) -ceq $entry.FullName", downloader, StringComparison.Ordinal);
    }

    [Fact]
    public void Candidate_downloader_strong_loads_System_Net_Http_from_the_native_GAC_before_typed_use()
    {
        var downloader = ReadLiveValidationFile("Get-BuildOnceCandidate.ps1");
        const string assemblyIdentity = "System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        var load = downloader.IndexOf("$null = Import-TrustedSystemNetHttpAssembly", StringComparison.Ordinal);
        var firstTypedUse = downloader.IndexOf("[Net.Http.", StringComparison.Ordinal);
        Assert.True(load >= 0 && firstTypedUse > load, "System.Net.Http must be loaded before the first typed use.");
        Assert.Contains(assemblyIdentity, downloader, StringComparison.Ordinal);
        Assert.Contains("[Reflection.Assembly]::Load($systemNetHttpAssemblyIdentity)", downloader, StringComparison.Ordinal);
        Assert.Contains("$systemNetHttpAssembly.GlobalAssemblyCache", downloader, StringComparison.Ordinal);
        Assert.Contains("$loadedSystemNetHttpPath.Equals($trustedSystemNetHttpPath", downloader, StringComparison.Ordinal);
        Assert.Contains("'GAC_MSIL'", downloader, StringComparison.Ordinal);
        Assert.DoesNotContain("Add-Type -AssemblyName System.Net.Http", downloader, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("[Reflection.Assembly]::LoadFrom", downloader, StringComparison.OrdinalIgnoreCase);

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var fixtureRoot = Path.Combine(Path.GetTempPath(), $"df-system-net-http-trap-{Guid.NewGuid():N}");
        var marker = Path.Combine(fixtureRoot, "fake-module-loaded.txt");
        Directory.CreateDirectory(Path.Combine(fixtureRoot, "System.Net.Http"));
        File.WriteAllText(Path.Combine(fixtureRoot, "System.Net.Http.dll"), "not a trusted assembly");
        File.WriteAllText(
            Path.Combine(fixtureRoot, "System.Net.Http", "System.Net.Http.psd1"),
            "@{ RootModule = 'System.Net.Http.psm1'; ModuleVersion = '4.0.0.0' }");
        File.WriteAllText(
            Path.Combine(fixtureRoot, "System.Net.Http", "System.Net.Http.psm1"),
            "[IO.File]::WriteAllText($env:LIVE_VALIDATION_ASSEMBLY_MARKER, 'loaded')");

        const string script = """
            $ErrorActionPreference = 'Stop'
            Microsoft.PowerShell.Management\Set-Location -LiteralPath $env:LIVE_VALIDATION_ASSEMBLY_TRAP
            $sourcePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'Get-BuildOnceCandidate.ps1')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            foreach ($name in @('Assert-Condition', 'Import-TrustedSystemNetHttpAssembly')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              if ($null -eq $functionAst) { throw "Function not found: $name" }
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            $nativeWindowsDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)).TrimEnd('\')
            $null = Import-TrustedSystemNetHttpAssembly
            $handler = [Net.Http.HttpClientHandler]::new()
            $handler.Dispose()
            $identity = 'System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
            $loaded = $null
            foreach ($candidate in [AppDomain]::CurrentDomain.GetAssemblies()) {
              if ($candidate.FullName -ceq $identity) { $loaded = $candidate; break }
            }
            if ($null -eq $loaded) { throw 'System.Net.Http was not loaded.' }
            $expectedPrefix = [IO.Path]::Combine($nativeWindowsDirectory, 'Microsoft.Net', 'assembly', 'GAC_MSIL', 'System.Net.Http') + '\'
            if (-not ([IO.Path]::GetFullPath($loaded.Location).StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase))) { throw "Untrusted assembly loaded: $($loaded.Location)" }
            if ([IO.File]::Exists($env:LIVE_VALIDATION_ASSEMBLY_MARKER)) { throw 'The fake System.Net.Http module executed.' }
            'system-net-http=passed'
            """;

        try
        {
            var result = RunWindowsPowerShell(script, new Dictionary<string, string?>
            {
                ["LIVE_VALIDATION_ASSEMBLY_TRAP"] = fixtureRoot,
                ["LIVE_VALIDATION_ASSEMBLY_MARKER"] = marker,
                ["PATH"] = fixtureRoot,
                ["PSModulePath"] = fixtureRoot,
            });

            Assert.True(
                result.ExitCode == 0,
                $"Native Windows PowerShell System.Net.Http probe failed. stdout: {result.StandardOutput} stderr: {result.StandardError}");
            Assert.Contains("system-net-http=passed", result.StandardOutput, StringComparison.Ordinal);
            Assert.False(File.Exists(marker), "The fake System.Net.Http module executed.");
        }
        finally
        {
            if (Directory.Exists(fixtureRoot))
            {
                Directory.Delete(fixtureRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void Recovery_cache_cleanup_is_exact_acl_checked_and_double_fingerprinted()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");

        Assert.Contains("Get-ProductState $cache.productCode", child, StringComparison.Ordinal);
        Assert.Contains("Test-DependencyProvider $cache.dependencyProviderKey", child, StringComparison.Ordinal);
        Assert.Contains("single-file layout", child, StringComparison.Ordinal);
        Assert.Contains("Assert-NoBroadWriteAcl $directory", child, StringComparison.Ordinal);
        Assert.Contains("Assert-NoBroadWriteAcl $files[0].FullName", child, StringComparison.Ordinal);
        Assert.Contains("immediate pre-removal recheck", child, StringComparison.Ordinal);
        Assert.Contains("Move-Item -LiteralPath $freshItem.FullName -Destination $quarantinePath", child, StringComparison.Ordinal);
        Assert.Contains("quarantined orphan package cache MSI", child, StringComparison.Ordinal);
        Assert.Contains("$trustedWriterSids = @('S-1-5-18', 'S-1-5-32-544', $trustedInstaller)", child, StringComparison.Ordinal);
        Assert.Contains("$ownerSid -in $trustedWriterSids", child, StringComparison.Ordinal);
        Assert.Contains("Assert-NoBroadWriteAcl $packageCacheRoot", child, StringComparison.Ordinal);
        Assert.Contains("[Security.AccessControl.AceFlags]::InheritOnly", child, StringComparison.Ordinal);
        Assert.Contains("if (-not (Test-Path -LiteralPath $directory))", child, StringComparison.Ordinal);
        Assert.Contains("orphan package cache path exists but is not a directory", child, StringComparison.Ordinal);
        Assert.DoesNotContain("Win32_Product", child, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DisplayName", child, StringComparison.OrdinalIgnoreCase);

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            foreach ($name in @('Assert-Condition', 'Get-ValidatedOrphanPackageCache')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            function Assert-NoBroadWriteAcl { }
            $fixtureRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('df-cache-file-' + [Guid]::NewGuid().ToString('N')))
            $programData = $fixtureRoot
            $packageCache = [IO.Path]::Combine($fixtureRoot, 'Package Cache')
            $null = [IO.Directory]::CreateDirectory($packageCache)
            $cacheLeaf = [IO.Path]::Combine($packageCache, 'expected-cache')
            [IO.File]::WriteAllText($cacheLeaf, 'not-a-directory')
            $cache = [pscustomobject]@{ directoryName = 'expected-cache'; payload = [pscustomobject]@{} }
            try {
              try { Get-ValidatedOrphanPackageCache $cache 'fixture'; throw 'File-shaped cache unexpectedly passed as absent.' }
              catch { if ($_.Exception.Message -ceq 'File-shaped cache unexpectedly passed as absent.') { throw } }
              'cache-file-shape=passed'
            }
            finally { [IO.Directory]::Delete($fixtureRoot, $true) }
            """;

        var result = RunWindowsPowerShell(script);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("cache-file-shape=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Acl_mask_accepts_read_execute_but_rejects_write_delete_and_acl_rights()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        var downloader = ReadLiveValidationFile("Get-BuildOnceCandidate.ps1");
        var generator = ReadLiveValidationFile("New-LiveValidationCampaign.ps1");
        foreach (var source in new[] { child, downloader, generator })
        {
            Assert.Contains("$dangerousRightsMask = [int64]0x500D0156", source, StringComparison.Ordinal);
            Assert.DoesNotContain("[Security.AccessControl.FileSystemRights]::FullControl -bor", source, StringComparison.Ordinal);
        }

        const long dangerousMask = 0x500D0156;
        const long readExecuteSynchronize = 0x001200A9;
        const long writeSynchronize = 0x00100116;
        const long delete = 0x00010000;
        const long changePermissions = 0x00040000;
        const long genericWrite = 0x40000000;
        Assert.Equal(0, readExecuteSynchronize & dangerousMask);
        Assert.NotEqual(0, writeSynchronize & dangerousMask);
        Assert.NotEqual(0, delete & dangerousMask);
        Assert.NotEqual(0, changePermissions & dangerousMask);
        Assert.NotEqual(0, genericWrite & dangerousMask);
    }

    [Fact]
    public void Trusted_system_binary_and_acl_checks_accept_the_native_PowerShell_and_reject_user_owned_paths()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Start-Campaign.ps1.template')
            $source = [IO.File]::ReadAllText($templatePath)
            $typeMatch = [regex]::Match($source, "Microsoft\.PowerShell\.Utility\\Add-Type -TypeDefinition @'\r?\n(?<source>.*?MandatoryIntegrityInspection.*?)\r?\n'@", [Text.RegularExpressions.RegexOptions]::Singleline)
            if (-not $typeMatch.Success) { throw 'Mandatory-integrity native source was not found.' }
            Add-Type -TypeDefinition $typeMatch.Groups['source'].Value
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            foreach ($name in @('Assert-Condition', 'Assert-AcceptableMandatoryIntegritySddl', 'Assert-PrivilegedPathAcl', 'Assert-TrustedSystemBinary')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            $windowsDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)).TrimEnd('\')
            $systemDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::System)).TrimEnd('\')
            $trustedPowerShellRoot = [IO.Path]::Combine($systemDirectory, 'WindowsPowerShell')
            $trustedPowerShellHome = [IO.Path]::Combine($trustedPowerShellRoot, 'v1.0')
            $trustedPowerShellModuleRoot = [IO.Path]::Combine($trustedPowerShellHome, 'Modules')
            $powershell = [IO.Path]::Combine($trustedPowerShellHome, 'powershell.exe')
            Assert-TrustedSystemBinary $powershell 'test native PowerShell'

            $untrusted = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('df-user-acl-' + [Guid]::NewGuid().ToString('N')))
            $null = [IO.Directory]::CreateDirectory($untrusted)
            try {
              try { Assert-PrivilegedPathAcl $untrusted 'test user directory'; throw 'User-owned directory unexpectedly passed.' }
              catch {
                if ($_.Exception.Message -ceq 'User-owned directory unexpectedly passed.') { throw }
              }
              'system-path-acl=passed'
            }
            finally { [IO.Directory]::Delete($untrusted, $true) }
            """;

        var result = RunWindowsPowerShell(script);

        Assert.True(
            result.ExitCode == 0,
            $"Trusted-system binary validation failed.{Environment.NewLine}{result.StandardError}{Environment.NewLine}{result.StandardOutput}");
        Assert.Contains("system-path-acl=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Reboot_pending_rename_and_machine_network_baselines_are_fail_closed()
    {
        var parent = ReadLiveValidationFile("templates", "Start-Campaign.ps1.template");
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");

        Assert.Contains("Component Based Servicing\\RebootPending", parent, StringComparison.Ordinal);
        Assert.Contains("WindowsUpdate\\Auto Update\\RebootRequired", parent, StringComparison.Ordinal);
        Assert.Contains("Installer\\InProgress", parent, StringComparison.Ordinal);
        Assert.Contains("UpdateExeVolatile", parent, StringComparison.Ordinal);
        Assert.Contains("ActiveComputerName", parent, StringComparison.Ordinal);
        Assert.Contains("PendingFileRenameOperations2", parent, StringComparison.Ordinal);
        Assert.Contains("PendingFileRenameOperations2", child, StringComparison.Ordinal);
        Assert.Contains("pair order/content", child, StringComparison.Ordinal);
        Assert.Contains("^DEL[0-9A-F]{4}\\.tmp$", child, StringComparison.Ordinal);
        Assert.Contains("burn_engine_sha256", child, StringComparison.Ordinal);
        Assert.Contains("Get-DnsClientSnapshot", child, StringComparison.Ordinal);
        Assert.Contains("Get-BrowserPolicySnapshot", child, StringComparison.Ordinal);
        Assert.Contains("changed DNS or browser machine-policy baseline", child, StringComparison.Ordinal);
    }

    [Fact]
    public void Service_and_final_residual_acceptance_cover_process_and_owned_OS_objects()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");

        Assert.Contains("ServiceType -ceq 'Own Process'", child, StringComparison.Ordinal);
        Assert.Contains("ProcessId -gt 0", child, StringComparison.Ordinal);
        Assert.Contains("Win32_Process", child, StringComparison.Ordinal);
        Assert.Contains("ExecutablePath", child, StringComparison.Ordinal);
        Assert.Contains("executable_sha256", child, StringComparison.Ordinal);
        Assert.Contains("Failure-action reset period is not one day", child, StringComparison.Ordinal);
        Assert.Contains("5000,5000,5000", child, StringComparison.Ordinal);
        Assert.Contains("Candidate Windows Installer LocalPackage remains", child, StringComparison.Ordinal);
        Assert.Contains("Candidate dependency provider remains", child, StringComparison.Ordinal);
        Assert.Contains("Candidate Package Cache directory remains", child, StringComparison.Ordinal);
        Assert.Contains("common Start Menu folder remains", child, StringComparison.Ordinal);
        Assert.Contains("Scheduled Task folder \\DistractionFirewall remains", child, StringComparison.Ordinal);
        Assert.Contains("Owned WFP provider/sublayer/filter residual remains", child, StringComparison.Ordinal);
    }

    [Fact]
    public void Candidate_cleanup_runs_even_when_the_Burn_install_attempt_fails_before_registration()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");

        Assert.Contains("$candidateInstallAttempted = $false", child, StringComparison.Ordinal);
        Assert.Contains("$candidateInstallAttempted = $true", child, StringComparison.Ordinal);
        Assert.Contains("if ($candidateInstallAttempted -or $installedCandidate", child, StringComparison.Ordinal);
        Assert.Contains("$uninstallEvidence = Invoke-CandidateUninstall", child, StringComparison.Ordinal);
        Assert.True(
            child.IndexOf("$candidateInstallAttempted = $true", StringComparison.Ordinal) <
            child.IndexOf("'candidate-burn-install'", StringComparison.Ordinal),
            "The attempt marker must be set before Burn is invoked.");
    }

    [Fact]
    public void Candidate_direct_product_and_cache_state_is_absent_before_the_first_Burn_invocation()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        var preflight = ExtractBetween(child, "function Assert-CandidatePackageStatePreflight", "trap {");
        Assert.Contains("Get-ProductState $record.product_code", preflight, StringComparison.Ordinal);
        Assert.Contains("-eq -1", preflight, StringComparison.Ordinal);
        Assert.Contains("Get-BundleRegistration", preflight, StringComparison.Ordinal);
        Assert.Contains("Test-DependencyProvider", preflight, StringComparison.Ordinal);
        Assert.Contains("Candidate Package Cache root is missing", preflight, StringComparison.Ordinal);
        Assert.Contains("Assert-NoBroadWriteAcl $packageCacheRoot", preflight, StringComparison.Ordinal);
        Assert.Contains("Candidate Package Cache directory already exists", preflight, StringComparison.Ordinal);
        Assert.True(
            child.LastIndexOf("Assert-CandidatePackageStatePreflight", StringComparison.Ordinal) <
            child.IndexOf("$candidateInstallAttempted = $true", StringComparison.Ordinal));

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = [IO.Path]::Combine($env:LIVE_VALIDATION_REPOSITORY_ROOT, 'eng', 'live-validation', 'templates', 'Invoke-ElevatedPhase.ps1.template')
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            foreach ($name in @('Assert-Condition', 'Assert-CandidatePackageStatePreflight')) {
              $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
              . ([ScriptBlock]::Create($functionAst.Extent.Text))
            }
            $app = [pscustomobject]@{ product_code = '{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}'; product_version = '0.1.0' }
            $runtime = [pscustomobject]@{ product_code = '{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}'; product_version = '0.1.0' }
            $campaign = [pscustomobject]@{
              candidate = [pscustomobject]@{ setup = [pscustomobject]@{ bundle_provider_key = '{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}' }; app_msi = $app; runtime_msi = $runtime }
              paths = [pscustomobject]@{ package_cache_root = 'C:\ProgramData\Package Cache' }
            }
            $programData = 'C:\ProgramData'
            function Get-BundleRegistration { if ($script:fixtureCase -ceq 'bundle-registration') { return @('registered') }; return @() }
            function Get-ProductState { param($ProductCode); if ($script:fixtureCase -ceq 'app-direct-state' -and $ProductCode -ceq $app.product_code) { return 5 }; if ($script:fixtureCase -ceq 'runtime-direct-state' -and $ProductCode -ceq $runtime.product_code) { return 1 }; return -1 }
            function Test-DependencyProvider { param($Key); return $script:fixtureCase -ceq 'dependency-provider' }
            function Test-Path {
              param([string]$LiteralPath, $PathType)
              $root = 'C:\ProgramData\Package Cache'
              if ($LiteralPath -ceq $root) {
                if ($script:fixtureCase -ceq 'root-missing') { return $false }
                if ($script:fixtureCase -ceq 'root-file' -and [string]$PathType -ceq 'Container') { return $false }
                return $true
              }
              return $script:fixtureCase -ceq 'cache-directory'
            }
            function Get-Item { return [pscustomobject]@{ Attributes = $(if ($script:fixtureCase -ceq 'root-reparse') { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Directory }) } }
            function Assert-NoBroadWriteAcl { if ($script:fixtureCase -ceq 'root-weak-acl') { throw 'root-weak-acl' } }
            foreach ($case in @('root-missing', 'root-file', 'root-reparse', 'root-weak-acl', 'bundle-registration', 'app-direct-state', 'runtime-direct-state', 'dependency-provider', 'cache-directory')) {
              $script:fixtureCase = $case
              try { Assert-CandidatePackageStatePreflight; throw "$case unexpectedly passed" }
              catch { if ($_.Exception.Message -ceq "$case unexpectedly passed") { throw } }
            }
            'candidate-direct-state=passed'
            """;

        var result = RunWindowsPowerShell(script);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("candidate-direct-state=passed", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Wfp_inventory_throw_path_deletes_raw_XML_and_never_copies_scratch_to_returned_evidence()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");
        Assert.Contains("$filterXml = Join-Path $stageScratchRoot", child, StringComparison.Ordinal);
        Assert.Contains("finally", ExtractBetween(child, "function Get-WfpOwnedState", "function Assert-NoOwnedSystemObjects"), StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $filterXml -Force", child, StringComparison.Ordinal);
        Assert.Contains("Get-ChildItem -LiteralPath $stageEvidenceRoot", child, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-ChildItem -LiteralPath $stageScratchRoot", child, StringComparison.Ordinal);

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string script = """
            $ErrorActionPreference = 'Stop'
            $templatePath = Join-Path $env:LIVE_VALIDATION_REPOSITORY_ROOT 'eng\live-validation\templates\Invoke-ElevatedPhase.ps1.template'
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw ($errors.Message -join '; ') }
            $functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-WfpOwnedState' }, $true)
            if ($null -eq $functionAst) { throw 'Get-WfpOwnedState was not found.' }
            $testableFunction = $functionAst.Extent.Text.Replace('Microsoft.PowerShell.Management\Start-Process', 'Start-Process')
            . ([ScriptBlock]::Create($testableFunction))
            $stageScratchRoot = Join-Path ([IO.Path]::GetTempPath()) ('df-wfp-throw-' + [Guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $stageScratchRoot
            function Assert-Condition { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
            function Start-Process {
              param([string]$FilePath, [object[]]$ArgumentList, [switch]$Wait, [switch]$PassThru, [string]$WindowStyle)
              $fileArgument = @($ArgumentList | Where-Object { ([string]$_).StartsWith('file=', [StringComparison]::Ordinal) })[0]
              [IO.File]::WriteAllText(([string]$fileArgument).Substring(5), '<raw-machine-wfp-inventory />')
              return [pscustomobject]@{ ExitCode = 0 }
            }
            function Select-String {
              param([string]$LiteralPath, [object[]]$Pattern, [switch]$SimpleMatch)
              throw 'injected Select-String failure'
            }
            try {
              try { Get-WfpOwnedState 'throw-path' | Out-Null; throw 'Injected failure was not observed.' }
              catch {
                if ($_.Exception.Message -cne 'injected Select-String failure') { throw }
              }
              if (Test-Path -LiteralPath (Join-Path $stageScratchRoot 'throw-path-wfp-filters.xml')) { throw 'Raw WFP XML survived the throw path.' }
              if (@(Get-ChildItem -LiteralPath $stageScratchRoot -Force).Count -ne 0) { throw 'Scratch directory is not empty.' }
              'wfp-throw-cleanup=passed'
            }
            finally {
              if (Test-Path -LiteralPath $stageScratchRoot) { Remove-Item -LiteralPath $stageScratchRoot -Force -Recurse }
            }
            """;

        var result = RunWindowsPowerShell(script);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("wfp-throw-cleanup=passed", result.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("raw-machine-wfp-inventory", result.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Cleanup_diagnostic_and_protected_stage_are_narrow_and_evidence_bearing()
    {
        var child = ReadLiveValidationFile("templates", "Invoke-ElevatedPhase.ps1.template");

        Assert.Contains("runtime_data_root 'cleanup-failure.json'", child, StringComparison.Ordinal);
        Assert.Contains("schema_version", child, StringComparison.Ordinal);
        Assert.Contains("runtime-installation-cleanup", child, StringComparison.Ordinal);
        Assert.Contains("failed-recovery-uninstall", child, StringComparison.Ordinal);
        Assert.Contains("failed-candidate-runtime-uninstall", child, StringComparison.Ordinal);
        Assert.Contains("[IO.Directory]::CreateDirectory($fullPath, $security)", child, StringComparison.Ordinal);
        Assert.Contains("DistractionFirewall-LiveValidation-", child, StringComparison.Ordinal);
        Assert.Contains("Protected staging teardown failed", child, StringComparison.Ordinal);
        Assert.Contains("protected_stage_teardown_error", child, StringComparison.Ordinal);
    }

    private static JsonSchema CandidateSchema() => CandidateSchemaValue.Value;

    private static JsonSchema GetSchema(string fileName) => fileName switch
    {
        "build-once-candidate-manifest.schema.json" => CandidateSchemaValue.Value,
        "provenance-envelope.schema.json" => ProvenanceSchemaValue.Value,
        "runtime-recovery-manifest.schema.json" => RecoverySchemaValue.Value,
        _ => throw new ArgumentOutOfRangeException(nameof(fileName), fileName, "Unknown live-validation schema."),
    };

    private static bool Evaluate(JsonSchema schema, string json)
    {
        using var document = JsonDocument.Parse(json);
        return schema.Evaluate(document.RootElement).IsValid;
    }

    private static JsonObject ReadFixtureObject(string fileName) =>
        JsonNode.Parse(File.ReadAllText(FixturePath(fileName)))?.AsObject() ??
        throw new InvalidDataException($"Fixture did not contain a JSON object: {fileName}");

    private static string SchemaPath(string fileName) => Path.Combine(LiveValidationRoot, "schemas", fileName);

    private static string FixturePath(string fileName) => Path.Combine(RepositoryRoot, "tests", "LiveValidation", "Fixtures", fileName);

    private static string ReadLiveValidationFile(params string[] segments) =>
        File.ReadAllText(segments.Aggregate(LiveValidationRoot, (current, segment) => Path.Combine(current, segment)));

    private static int CountOccurrences(string value, string fragment)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(fragment, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += fragment.Length;
        }

        return count;
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
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        var windowsDirectory = Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        var systemDirectory = Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.System));
        if (!systemDirectory.StartsWith(
                windowsDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The native Windows system directory escaped the Windows directory.");
        }

        var windowsPowerShellHome = Path.Combine(
            systemDirectory,
            "WindowsPowerShell",
            "v1.0");
        var nativeModuleRoot = Path.Combine(windowsPowerShellHome, "Modules");
        var executable = Path.Combine(windowsPowerShellHome, "powershell.exe");
        var moduleRootBase64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(nativeModuleRoot));
        var bootstrappedScript = $$"""
            $trustedPowerShellModuleRoot = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{{moduleRootBase64}}'))
            foreach ($moduleName in @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security')) {
                $moduleManifest = [IO.Path]::Combine($trustedPowerShellModuleRoot, $moduleName, "$moduleName.psd1")
                Microsoft.PowerShell.Core\Import-Module -Name $moduleManifest -Force -ErrorAction Stop
            }
            $PSModuleAutoLoadingPreference = 'None'
            {{script}}
            """;
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrappedScript));
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
        startInfo.ArgumentList.Add(encoded);
        startInfo.Environment["LIVE_VALIDATION_REPOSITORY_ROOT"] = RepositoryRoot;
        startInfo.Environment["PSModulePath"] = nativeModuleRoot;
        if (environment is not null)
        {
            foreach (var (name, value) in environment)
            {
                if (value is null)
                {
                    startInfo.Environment.Remove(name);
                }
                else
                {
                    startInfo.Environment[name] = value;
                }
            }
        }

        using var process = new Process { StartInfo = startInfo };
        Assert.True(process.Start(), "Windows PowerShell 5.1 did not start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Windows PowerShell 5.1 validation timed out.");
        }

        return new PowerShellResult(process.ExitCode, stdoutTask.GetAwaiter().GetResult(), stderrTask.GetAwaiter().GetResult());
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DistractionFirewall.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private sealed record PowerShellResult(int ExitCode, string StandardOutput, string StandardError);
}
