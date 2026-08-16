using System.Text.Json;
using System.Text.RegularExpressions;

namespace DistractionFirewall.ArchitectureTests;

public sealed class ReleaseWorkflowSecurityTests
{
    [Fact]
    public void Candidate_build_starts_only_from_exact_current_protected_main()
    {
        var workflow = ReadWorkflow("release-candidate.yml");
        var gate = ReadJob(workflow, "candidate-gate");

        Assert.Contains("workflow_dispatch:", workflow);
        Assert.DoesNotContain("\n  push:", workflow);
        Assert.Contains("DISPATCH_REF: ${{ github.ref }}", gate);
        Assert.Contains("$env:DISPATCH_REF -cne 'refs/heads/main'", gate);
        Assert.Contains("REQUESTED_SHA: ${{ inputs.source_commit }}", gate);
        Assert.Contains("$env:REQUESTED_SHA -cne $env:DISPATCH_SHA", gate);
        Assert.Contains("/branches/main", gate);
        Assert.Contains("-not [bool]$branch.protected", gate);
        Assert.Contains("$mainSha -cne $env:REQUESTED_SHA", gate);
        Assert.Contains("contents: read", gate);
        Assert.DoesNotContain("actions/checkout", gate);
    }

    [Fact]
    public void Every_candidate_job_has_a_verified_needs_path_to_candidate_gate()
    {
        var workflow = ReadWorkflow("release-candidate.yml");
        var jobNames = ReadJobNames(workflow);
        var needsByJob = jobNames.ToDictionary(
            jobName => jobName,
            jobName => ReadNeeds(ReadJob(workflow, jobName)),
            StringComparer.Ordinal);

        var requiredEdges = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["test"] = ["candidate-gate"],
            ["publish"] = ["test"],
            ["package"] = ["test", "publish"],
            ["installer-validation"] = ["test", "package"],
            ["supply-chain"] = ["test", "installer-validation"],
            ["seal-candidate"] = ["candidate-gate", "test", "supply-chain"],
        };

        foreach (var (jobName, requiredNeeds) in requiredEdges)
        {
            Assert.True(needsByJob.ContainsKey(jobName), $"Could not find candidate job '{jobName}'.");
            foreach (var requiredNeed in requiredNeeds)
            {
                Assert.Contains(requiredNeed, needsByJob[jobName]);
            }

            Assert.True(
                TransitivelyNeeds(jobName, "candidate-gate", needsByJob),
                $"Candidate job '{jobName}' has no needs path to candidate-gate.");
        }
    }

    [Fact]
    public void Candidate_is_sealed_once_with_manifest_evidence_and_provenance()
    {
        var workflow = ReadWorkflow("release-candidate.yml");
        var supplyChain = ReadJob(workflow, "supply-chain");
        var seal = ReadJob(workflow, "seal-candidate");

        Assert.Contains("distraction-firewall/build-once-candidate/v1", supplyChain);
        Assert.Contains("workflowPath = '.github/workflows/release-candidate.yml'", supplyChain);
        Assert.Contains("workflowRef = $env:WORKFLOW_REF", supplyChain);
        Assert.Contains("workflowRunAttempt = [int]$env:GITHUB_RUN_ATTEMPT", supplyChain);
        Assert.Contains("artifactId = $null", supplyChain);
        Assert.Contains("artifactDigestSha256 = $null", supplyChain);
        Assert.Contains("bundleProviderKey", supplyChain);
        Assert.Contains("productCode", supplyChain);
        Assert.Contains("packageCode", supplyChain);
        Assert.Contains("productVersion", supplyChain);
        Assert.Contains("authenticodeStatus", supplyChain);
        Assert.Contains("burnEngine", supplyChain);
        Assert.Contains("sizeBytes", supplyChain);
        Assert.Contains("outerPackageStatuses", supplyChain);
        Assert.Contains("candidate-subjects.sha256", supplyChain);
        Assert.Contains("hosted-candidate-validation/v1", supplyChain);
        Assert.Contains("The SPDX document is a distribution inventory skeleton", supplyChain);

        Assert.Contains("artifact-metadata: write", seal);
        Assert.Contains("attestations: write", seal);
        Assert.Contains("id-token: write", seal);
        Assert.Contains(
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            seal);
        Assert.Contains("subject-checksums:", seal);
        Assert.Contains("provenance.bundle.json", seal);
        Assert.Contains("overwrite: false", seal);
        Assert.Contains("retention-days: 90", seal);
        Assert.Contains("artifact-digest", seal);
        Assert.Contains("artifact-id", seal);
        Assert.Contains("manifest_sha256", seal);
        Assert.Contains("EXPECTED_WORKFLOW_REF: ${{ github.repository }}/.github/workflows/release-candidate.yml@refs/heads/main", seal);
        Assert.Contains("$manifest.source.workflowRef -cne $env:EXPECTED_WORKFLOW_REF", seal);
        Assert.Equal(
            1,
            Regex.Count(seal, @"uses:\s+actions/upload-artifact@"));
    }

    [Fact]
    public void Candidate_receipt_normalizes_upload_action_digest_to_rest_api_form()
    {
        var seal = ReadJob(ReadWorkflow("release-candidate.yml"), "seal-candidate");
        var rawDigest = new string('a', 64);

        Assert.Contains(
            "artifact_digest: ${{ steps.receipt.outputs.artifact_digest }}",
            seal);
        Assert.Contains(
            "ARTIFACT_DIGEST_HEX: ${{ steps.candidate_upload.outputs.artifact-digest }}",
            seal);
        Assert.Contains(
            "$env:ARTIFACT_DIGEST_HEX -cnotmatch '^[0-9a-f]{64}$'",
            seal);
        Assert.Contains(
            "$artifactDigest = \"sha256:$env:ARTIFACT_DIGEST_HEX\"",
            seal);
        Assert.Contains("\"artifact_digest=$artifactDigest\" >> $env:GITHUB_OUTPUT", seal);
        Assert.DoesNotContain(
            "artifact_digest: ${{ steps.candidate_upload.outputs.artifact-digest }}",
            seal);

        Assert.Matches("^[0-9a-f]{64}$", rawDigest);
        Assert.DoesNotMatch("^[0-9a-f]{64}$", $"sha256:{rawDigest}");
        Assert.Matches("^sha256:[0-9a-f]{64}$", $"sha256:{rawDigest}");
    }

    [Fact]
    public void Candidate_signing_secrets_are_directly_guarded_by_the_signing_environment()
    {
        var workflow = ReadWorkflow("release-candidate.yml");
        var package = ReadJob(workflow, "package");
        var workflowWithoutPackage = workflow.Replace(package, string.Empty, StringComparison.Ordinal);

        Assert.Contains(
            "environment:\n      name: ${{ vars.WINDOWS_SIGNING_CONFIGURED == 'true' && 'release-signing' || '' }}",
            package);
        Assert.Contains("if: ${{ vars.WINDOWS_SIGNING_CONFIGURED == 'true' }}", package);
        Assert.Contains("secrets.WINDOWS_SIGNING_PFX_BASE64", package);
        Assert.Contains("secrets.WINDOWS_SIGNING_PFX_PASSWORD", package);
        Assert.DoesNotContain("secrets.WINDOWS_SIGNING_PFX_BASE64", workflowWithoutPackage);
        Assert.DoesNotContain("secrets.WINDOWS_SIGNING_PFX_PASSWORD", workflowWithoutPackage);
        Assert.DoesNotContain("environment: release-signing", workflow);
    }

    [Fact]
    public void Promotion_gate_binds_tag_main_candidate_api_metadata_and_local_smoke()
    {
        var workflow = ReadWorkflow("release.yml");
        var gate = ReadJob(workflow, "promotion-approval");

        Assert.Contains("push:", workflow);
        Assert.Contains("tags:", workflow);
        Assert.DoesNotContain("workflow_dispatch:", workflow);
        Assert.Contains("environment: windows-11-live-smoke-approval", gate);
        Assert.Contains("actions: read", gate);
        Assert.Contains("contents: read", gate);
        Assert.Contains("WINDOWS_11_LIVE_SMOKE_APPROVED_SHA", gate);
        Assert.Contains("WINDOWS_11_LIVE_SMOKE_APPROVED_TAG", gate);
        Assert.Contains("RELEASE_CANDIDATE_RUN_ID", gate);
        Assert.Contains("RELEASE_CANDIDATE_ARTIFACT_ID", gate);
        Assert.Contains("RELEASE_CANDIDATE_ARTIFACT_DIGEST", gate);
        Assert.Contains("RELEASE_CANDIDATE_MANIFEST_SHA256", gate);
        Assert.Contains("WINDOWS_11_LIVE_SMOKE_ARTIFACT_ID", gate);
        Assert.Contains("WINDOWS_11_LIVE_SMOKE_ARTIFACT_DIGEST", gate);
        Assert.Contains("WINDOWS_11_LIVE_SMOKE_MANIFEST_SHA256", gate);
        Assert.Contains("WINDOWS_11_LIVE_SMOKE_EVIDENCE_SHA256", gate);
        Assert.Contains("$SMOKE_ARTIFACT_ID", gate);
        Assert.Contains("$CANDIDATE_ARTIFACT_ID", gate);
        Assert.Contains("/branches/main", gate);
        Assert.Contains(".protected", gate);
        Assert.Contains("/git/ref/tags/$RELEASE_TAG", gate);
        Assert.Contains("$tag_type", gate);
        Assert.Contains("!= tag", gate);
        Assert.Contains("/actions/runs/$CANDIDATE_RUN_ID", gate);
        Assert.Contains(".github/workflows/release-candidate.yml", gate);
        Assert.Contains(".event", gate);
        Assert.Contains("workflow_dispatch", gate);
        Assert.Contains(".head_sha", gate);
        Assert.Contains(".conclusion", gate);
        Assert.Contains("/actions/artifacts/$CANDIDATE_ARTIFACT_ID", gate);
        Assert.Contains(".workflow_run.id", gate);
        Assert.Contains(".digest", gate);
        Assert.Contains(
            "approval_run_attempt: ${{ steps.gate.outputs.approval_run_attempt }}",
            gate);
        Assert.Contains("WORKFLOW_RUN_ATTEMPT: ${{ github.run_attempt }}", gate);
        Assert.Contains("approval_run_attempt=$WORKFLOW_RUN_ATTEMPT", gate);
        Assert.DoesNotContain("actions/checkout", gate);
    }

    [Fact]
    public void Promotion_downloads_by_artifact_id_and_drafts_without_rebuilding()
    {
        var workflow = ReadWorkflow("release.yml");
        var draft = ReadJob(workflow, "draft-release");

        Assert.Equal(["promotion-approval"], ReadNeeds(draft));
        Assert.Contains("/actions/artifacts/$ARTIFACT_ID/zip", draft);
        Assert.Contains("sha256sum candidate.zip", draft);
        Assert.Contains("candidate-manifest.json", draft);
        Assert.Contains("$REPOSITORY/.github/workflows/release-candidate.yml@refs/heads/main", draft);
        Assert.Contains(".source.workflowRef == $workflowRef", draft);
        Assert.Contains("candidate-subjects.sha256", draft);
        Assert.Contains("provenance.bundle.json", draft);
        Assert.Contains("gh attestation verify", draft);
        Assert.Contains("--source-digest", draft);
        Assert.Contains("$RELEASE_SHA", draft);
        Assert.Contains("--deny-self-hosted-runners", draft);
        Assert.Contains("windows11-smoke-promotion/v1", draft);
        Assert.Contains(
            "APPROVAL_RUN_ATTEMPT: ${{ needs.promotion-approval.outputs.approval_run_attempt }}",
            draft);
        Assert.Contains(
            "$APPROVAL_RUN_ATTEMPT\" != \"$WORKFLOW_RUN_ATTEMPT",
            draft);
        Assert.Contains("use Re-run all jobs and approve again", draft);
        Assert.Contains("workflowActor: $actor", draft);
        Assert.DoesNotContain("approvedBy", workflow);
        Assert.Contains("artifact-metadata: write", draft);
        Assert.Contains("attestations: write", draft);
        Assert.Contains("id-token: write", draft);
        Assert.Contains(
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            draft);
        Assert.Contains("subject-path:", draft);
        Assert.Contains("windows11-smoke-promotion.provenance.bundle.json", draft);
        Assert.Contains("expected_names=(", draft);
        Assert.Contains("distraction-firewall-app-$VERSION-win-x64.msi", draft);
        Assert.Contains("distraction-firewall-runtime-$VERSION-win-x64.msi", draft);
        Assert.Contains("distraction-firewall-setup-$VERSION-win-x64.exe", draft);
        Assert.Contains("distraction-firewall-$VERSION.provenance.bundle.json", draft);
        Assert.Contains("gh release create", draft);
        Assert.Contains("gh release view \"$RELEASE_TAG\" --repo \"$REPOSITORY\"", draft);
        Assert.Contains("--repo \"$REPOSITORY\"", draft);
        Assert.Contains("--draft", draft);
        Assert.Contains("--target \"$RELEASE_SHA\"", draft);
        Assert.Contains("--verify-tag", draft);
        Assert.Contains(".prerelease", draft);
        Assert.Contains(".tag_name", draft);
        Assert.Contains(".target_commitish", draft);
        Assert.Contains("Distraction Firewall $VERSION", draft);
        Assert.Contains("does not start a restriction lease", draft);
        Assert.Contains("does not claim a live YouTube network-enforcement E2E result", draft);
        Assert.DoesNotContain("--clobber", draft);
        Assert.DoesNotContain("actions/checkout", workflow);
        Assert.DoesNotContain("dotnet publish", workflow);
        Assert.DoesNotContain("./eng/package.ps1", workflow);
        Assert.DoesNotContain("--draft=false", workflow);
    }

    [Fact]
    public void Publication_is_a_separate_reviewed_no_build_operation()
    {
        var workflow = ReadWorkflow("publish-release.yml");
        var publish = ReadJob(workflow, "publish");

        Assert.Contains("workflow_dispatch:", workflow);
        Assert.DoesNotContain("\n  push:", workflow);
        Assert.Contains("github.ref == 'refs/heads/main'", publish);
        Assert.Contains("environment: release-publication", publish);
        Assert.Contains("PUBLISH-REVIEWED-DRAFT", publish);
        Assert.Contains("/branches/main", publish);
        Assert.Contains("/git/ref/tags/$RELEASE_TAG", publish);
        Assert.Contains("'.draft'", publish);
        Assert.Contains("'.prerelease'", publish);
        Assert.Contains("'.tag_name'", publish);
        Assert.Contains("'.target_commitish'", publish);
        Assert.Contains("Distraction Firewall $version", publish);
        Assert.Contains("gh release download", publish);
        Assert.Contains("expected_names=(", publish);
        Assert.Equal(
            [
                "distraction-firewall-$version.candidate-manifest.json",
                "distraction-firewall-$version.candidate-subjects.sha256",
                "distraction-firewall-$version.hosted-evidence.json",
                "distraction-firewall-$version.provenance.bundle.json",
                "distraction-firewall-$version.sha256",
                "distraction-firewall-$version.spdx.json",
                "distraction-firewall-$version.windows11-smoke-promotion.json",
                "distraction-firewall-$version.windows11-smoke-promotion.provenance.bundle.json",
                "distraction-firewall-app-$version-win-x64.msi",
                "distraction-firewall-runtime-$version-win-x64.msi",
                "distraction-firewall-setup-$version-win-x64.exe",
            ],
            ReadBashArray(publish, "expected_names"));
        Assert.Contains("windows11-smoke-promotion.json", publish);
        Assert.Contains("windows11-smoke-promotion.provenance.bundle.json", publish);
        Assert.Contains("/actions/artifacts/$artifact_id", publish);
        Assert.Contains("/actions/artifacts/$artifact_id/zip", publish);
        Assert.Contains("sha256sum original-candidate.zip", publish);
        Assert.Contains("cmp --silent", publish);
        Assert.Contains("expected_candidate_names=(", publish);
        Assert.Contains("expected_subject_names=(", publish);
        Assert.Contains("subject_names=()", publish);
        Assert.Contains(".value.sizeBytes", publish);
        Assert.Contains("hosted-candidate-validation/v1", publish);
        Assert.Contains(".candidateManifestSha256 == $manifestSha", publish);
        Assert.Contains(".workflowRunAttempt == $runAttempt", publish);
        Assert.Contains("/actions/runs/$candidate_run_id", publish);
        Assert.Contains(".github/workflows/release-candidate.yml", publish);
        Assert.Contains("gh attestation verify", publish);
        Assert.Contains("--signer-workflow \"$REPOSITORY/.github/workflows/release.yml\"", publish);
        Assert.Contains("--source-digest \"$RELEASE_COMMIT\"", publish);
        Assert.Contains("--source-ref \"refs/tags/$RELEASE_TAG\"", publish);
        Assert.Contains("--deny-self-hosted-runners", publish);
        Assert.Contains("\"workflowActor\"", publish);
        Assert.Contains("verified-release-assets.tsv", publish);
        Assert.Contains("final-release-assets.tsv", publish);
        Assert.Contains("publish-boundary", publish);
        Assert.Contains("Draft asset changed before the publication boundary", publish);
        Assert.Contains("Reviewed draft asset API identity does not match verified bytes", publish);
        Assert.Contains(
            "Publication-boundary asset API identity does not match redownloaded bytes",
            publish);
        Assert.Contains("diff -u verified-release-assets.tsv final-release-assets.tsv", publish);
        Assert.Equal(
            2,
            Regex.Count(
                publish,
                @"^\s{10}verify_protected_main_and_annotated_tag\s*$",
                RegexOptions.Multiline));
        var finalAssetCheck = publish.IndexOf(
            "Publication-boundary asset API identity does not match redownloaded bytes",
            StringComparison.Ordinal);
        var finalRefCheck = publish.LastIndexOf(
            "verify_protected_main_and_annotated_tag",
            StringComparison.Ordinal);
        var publishMutation = publish.IndexOf("gh release edit", StringComparison.Ordinal);
        Assert.True(
            publish.IndexOf("final_release_json=", StringComparison.Ordinal) <
            publishMutation,
            "Final Release/asset identity revalidation must occur before publication.");
        Assert.True(
            finalAssetCheck < finalRefCheck && finalRefCheck < publishMutation,
            "Final asset bytes, protected main, and annotated tag must be revalidated immediately before publication.");
        Assert.Contains("gh release edit", publish);
        Assert.Contains("--draft=false", publish);
        Assert.Equal(1, Regex.Count(publish, @"\bgh release edit\b"));
        Assert.EndsWith(
            "gh release edit \"$RELEASE_TAG\" --repo \"$REPOSITORY\" --draft=false",
            publish.TrimEnd(),
            StringComparison.Ordinal);
        Assert.DoesNotContain("actions/checkout", workflow);
        Assert.DoesNotContain("dotnet publish", workflow);
        Assert.DoesNotContain("./eng/package.ps1", workflow);
    }

    [Fact]
    public void Release_jobs_use_only_reviewed_permissions_and_fixed_environments()
    {
        var candidate = ReadWorkflow("release-candidate.yml");
        var promotion = ReadWorkflow("release.yml");
        var publication = ReadWorkflow("publish-release.yml");

        Assert.Equal(
            ["artifact-metadata: write", "attestations: write", "contents: read", "id-token: write"],
            ReadJobPermissions(ReadJob(candidate, "seal-candidate")));
        Assert.Equal(
            ["actions: read", "contents: read"],
            ReadJobPermissions(ReadJob(promotion, "promotion-approval")));
        Assert.Equal(
            ["actions: read", "artifact-metadata: write", "attestations: write", "contents: write", "id-token: write"],
            ReadJobPermissions(ReadJob(promotion, "draft-release")));
        Assert.Equal(
            ["actions: read", "attestations: read", "contents: write"],
            ReadJobPermissions(ReadJob(publication, "publish")));

        Assert.Contains("environment: windows-11-live-smoke-approval", ReadJob(promotion, "promotion-approval"));
        Assert.Contains("environment: release-publication", ReadJob(publication, "publish"));
        Assert.DoesNotContain("actions: write", candidate + promotion + publication);
        Assert.DoesNotContain("packages: write", candidate + promotion + publication);
    }

    [Fact]
    public void Release_runbook_requires_external_environment_tag_and_immutability_preflight()
    {
        var runbook = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "docs", "04-ci-cd-release.md"));

        Assert.Contains(
            "environments/windows-11-live-smoke-approval",
            runbook);
        Assert.Contains("environments/release-publication", runbook);
        Assert.Contains("deployment-branch-policies", runbook);
        Assert.Contains("rulesets?includes_parents=true", runbook);
        Assert.Contains("immutable-releases", runbook);
        Assert.Contains("can_admins_bypass=false", runbook);
        Assert.Contains("Immutable Releasesは `enabled=true`", runbook);
        Assert.Contains("外部設定freeze", runbook);
        Assert.Contains("`release-tag-v-creation`", runbook);
        Assert.Contains("`release-tag-v-immutability`", runbook);
        Assert.Contains("\"actor_type\": \"User\"", runbook);
        Assert.Contains("\"bypass_actors\": []", runbook);
        Assert.Contains("\"type\": \"update\"", runbook);
        Assert.Contains("\"type\": \"deletion\"", runbook);
        Assert.Contains("\"type\": \"non_fast_forward\"", runbook);
        Assert.Contains("policyの `type` を返さず", runbook);
        Assert.Contains("GitHub UI", runbook);
        Assert.Contains("`v0.1.0-alpha.1` Releaseには遡及しない", runbook);
        Assert.Contains("unsigned `v0.1.0-alpha.2`", runbook);
        Assert.Contains("Re-run failed jobs", runbook);
        Assert.Contains("Re-run all jobs", runbook);
        Assert.Contains("`workflowActor`", runbook);
        Assert.Contains("Environment reviewerではありません", runbook);
        Assert.Contains("既知blocker", runbook);
    }

    [Fact]
    public void Existing_required_pull_request_checks_remain_stable()
    {
        var ci = ReadWorkflow("ci.yml");
        var dependencyReview = ReadWorkflow("dependency-review.yml");

        Assert.Contains("pull_request:", ci);
        Assert.Contains("push:", ci);
        Assert.Contains("- main", ci);
        Assert.Contains("name: CI / build and test", ci);
        Assert.Contains("name: CI / gate", ci);
        Assert.Contains("if: ${{ always() }}", ReadJob(ci, "gate"));
        Assert.Contains("pull_request:", dependencyReview);
        Assert.Contains("name: Security / dependency review", dependencyReview);
        Assert.Contains("fail-on-severity: high", dependencyReview);
    }

    [Fact]
    public void Every_external_action_reference_is_pinned_to_a_full_commit_sha()
    {
        foreach (var workflowPath in Directory.EnumerateFiles(
                     Path.Combine(FindRepositoryRoot(), ".github", "workflows"),
                     "*.yml"))
        {
            var workflow = File.ReadAllText(workflowPath);
            var references = Regex.Matches(
                workflow,
                @"^\s*uses:\s*[^@\s]+@(?<reference>[^\s#]+)",
                RegexOptions.Multiline);
            foreach (Match reference in references)
            {
                Assert.Matches(
                    "^[0-9a-f]{40}$",
                    reference.Groups["reference"].Value);
            }
        }
    }

    [Fact]
    public void Version_contract_is_strict_and_consistent_across_candidate_promotion_and_schema()
    {
        var candidate = ReadWorkflow("release-candidate.yml");
        var promotion = ReadWorkflow("release.yml");
        var publication = ReadWorkflow("publish-release.yml");
        var candidatePattern = Regex.Match(
            candidate,
            @"\$strictVersionPattern = '(?<pattern>[^']+)'").Groups["pattern"].Value;
        var promotionPattern = Regex.Match(
            promotion,
            @"strict_tag_pattern='(?<pattern>[^']+)'").Groups["pattern"].Value;
        var publicationPattern = Regex.Match(
            publication,
            @"strict_tag_pattern='(?<pattern>[^']+)'").Groups["pattern"].Value;
        var schemaPath = Path.Combine(
            FindRepositoryRoot(),
            "eng",
            "live-validation",
            "schemas",
            "build-once-candidate-manifest.schema.json");
        using var schema = JsonDocument.Parse(File.ReadAllText(schemaPath));
        var schemaPattern = schema.RootElement
            .GetProperty("properties")
            .GetProperty("version")
            .GetProperty("pattern")
            .GetString();

        Assert.NotEmpty(candidatePattern);
        Assert.NotEmpty(promotionPattern);
        Assert.Equal(promotionPattern, publicationPattern);
        Assert.NotNull(schemaPattern);
        Assert.Contains("$versionMatch = [regex]::Match($requestedVersion, $strictVersionPattern)", candidate);
        Assert.Contains("$versionMatch.Index -ne 0", candidate);
        Assert.Contains("$versionMatch.Length -ne $requestedVersion.Length", candidate);

        string[] accepted = ["0.1.0", "1.2.3", "1.2.3-alpha", "1.2.3-alpha.1", "1.2.3-0"];
        string[] rejected =
        [
            "01.2.3", "1.02.3", "1.2.03", "1.2", "1.2.3-01",
            "1.2.3-alpha.01", "1.2.3-alpha..1", "1.2.3-alpha_1", "1.2.3+build",
            "1٢.3.4", "1.2.3-1٢", "1.2.3\r", "1.2.3\n", "1.2.3\r\n",
        ];
        foreach (var version in accepted)
        {
            Assert.True(IsFullMatch(candidatePattern, version));
            Assert.True(IsFullMatch(schemaPattern!, version));
            Assert.True(IsFullMatch(promotionPattern, $"v{version}"));
            Assert.True(IsFullMatch(publicationPattern, $"v{version}"));
        }

        foreach (var version in rejected)
        {
            Assert.False(IsFullMatch(candidatePattern, version));
            Assert.False(IsFullMatch(schemaPattern!, version));
            Assert.False(IsFullMatch(promotionPattern, $"v{version}"));
            Assert.False(IsFullMatch(publicationPattern, $"v{version}"));
        }

        Assert.False(IsFullMatch(candidatePattern, "v1.2.3"));
        Assert.False(IsFullMatch(schemaPattern!, "v1.2.3"));
        Assert.False(IsFullMatch(promotionPattern, "1.2.3"));
        Assert.False(IsFullMatch(publicationPattern, "1.2.3"));
    }

    private static string[] ReadJobNames(string workflow)
    {
        var lines = workflow.Split('\n');
        var jobsStart = Array.FindIndex(
            lines,
            line => string.Equals(line, "jobs:", StringComparison.Ordinal));
        Assert.True(jobsStart >= 0, "Could not find the workflow jobs mapping.");

        return lines[(jobsStart + 1)..]
            .Where(
                line => line.StartsWith("  ", StringComparison.Ordinal) &&
                        !line.StartsWith("    ", StringComparison.Ordinal) &&
                        line.EndsWith(':'))
            .Select(line => line[2..^1])
            .ToArray();
    }

    private static string[] ReadNeeds(string job)
    {
        var lines = job.Split('\n');
        var needsLineIndex = Array.FindIndex(
            lines,
            line => line.StartsWith("    needs:", StringComparison.Ordinal));
        if (needsLineIndex < 0)
        {
            return [];
        }

        var inlineNeed = lines[needsLineIndex]["    needs:".Length..].Trim();
        if (inlineNeed.Length > 0)
        {
            return [inlineNeed];
        }

        return lines[(needsLineIndex + 1)..]
            .TakeWhile(
                line => string.IsNullOrWhiteSpace(line) ||
                        line.StartsWith("      ", StringComparison.Ordinal))
            .Where(line => line.StartsWith("      - ", StringComparison.Ordinal))
            .Select(line => line[8..].Trim())
            .ToArray();
    }

    private static string[] ReadBashArray(string script, string variableName)
    {
        var match = Regex.Match(
            script,
            $@"^\s{{10}}{Regex.Escape(variableName)}=\(\n(?<body>.*?)^\s{{10}}\)$",
            RegexOptions.Multiline | RegexOptions.Singleline);
        Assert.True(match.Success, $"Could not find Bash array '{variableName}'.");

        return Regex.Matches(
                match.Groups["body"].Value,
                "^\\s{12}\\\"(?<value>[^\\\"]+)\\\"$",
                RegexOptions.Multiline)
            .Select(item => item.Groups["value"].Value)
            .ToArray();
    }

    private static bool IsFullMatch(string pattern, string value)
    {
        var match = Regex.Match(value, pattern, RegexOptions.CultureInvariant);
        return match.Success && match.Index == 0 && match.Length == value.Length;
    }

    private static string[] ReadJobPermissions(string job)
    {
        var lines = job.Split('\n');
        var permissionsLineIndex = Array.FindIndex(
            lines,
            line => string.Equals(line, "    permissions:", StringComparison.Ordinal));
        Assert.True(permissionsLineIndex >= 0, "Could not find the job permissions mapping.");

        return lines[(permissionsLineIndex + 1)..]
            .TakeWhile(
                line => string.IsNullOrWhiteSpace(line) ||
                        line.StartsWith("      ", StringComparison.Ordinal))
            .Where(
                line => line.StartsWith("      ", StringComparison.Ordinal) &&
                        !line.StartsWith("        ", StringComparison.Ordinal) &&
                        line.Contains(':'))
            .Select(line => line.Trim())
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToArray();
    }

    private static bool TransitivelyNeeds(
        string jobName,
        string requiredJobName,
        Dictionary<string, string[]> needsByJob)
    {
        var pending = new Stack<string>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        pending.Push(jobName);

        while (pending.TryPop(out var currentJobName))
        {
            if (!visited.Add(currentJobName) || !needsByJob.TryGetValue(currentJobName, out var needs))
            {
                continue;
            }

            foreach (var need in needs)
            {
                if (string.Equals(need, requiredJobName, StringComparison.Ordinal))
                {
                    return true;
                }

                pending.Push(need);
            }
        }

        return false;
    }

    private static string ReadWorkflow(string fileName)
    {
        return File.ReadAllText(Path.Combine(FindRepositoryRoot(), ".github", "workflows", fileName))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    private static string ReadJob(string workflow, string jobName)
    {
        var lines = workflow.Split('\n');
        var start = Array.FindIndex(
            lines,
            line => string.Equals(line, $"  {jobName}:", StringComparison.Ordinal));
        Assert.True(start >= 0, $"Could not find workflow job '{jobName}'.");

        var end = lines.Length;
        for (var index = start + 1; index < lines.Length; index++)
        {
            var line = lines[index];
            if (line.StartsWith("  ", StringComparison.Ordinal) &&
                !line.StartsWith("    ", StringComparison.Ordinal) &&
                line.EndsWith(':'))
            {
                end = index;
                break;
            }
        }

        return string.Join('\n', lines[start..end]);
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
}
