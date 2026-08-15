namespace DistractionFirewall.ArchitectureTests;

public sealed class ReleaseWorkflowSecurityTests
{
    [Fact]
    public void Tag_pipeline_requires_exact_environment_approval_before_checkout_or_build()
    {
        var workflow = ReadReleaseWorkflow();
        var approvalJob = ReadJob(workflow, "live-smoke-approval");

        Assert.Contains("if: ${{ github.event_name == 'push' }}", approvalJob);
        Assert.Contains("runs-on: ubuntu-24.04", approvalJob);
        Assert.Contains("environment: windows-11-live-smoke-approval", approvalJob);
        Assert.Contains("contents: read", approvalJob);
        Assert.Contains("APPROVED_SHA: ${{ vars.WINDOWS_11_LIVE_SMOKE_APPROVED_SHA }}", approvalJob);
        Assert.Contains("APPROVED_TAG: ${{ vars.WINDOWS_11_LIVE_SMOKE_APPROVED_TAG }}", approvalJob);
        Assert.Contains("$env:APPROVED_SHA -cnotmatch '^[0-9a-f]{40}$'", approvalJob);
        Assert.Contains("$env:APPROVED_SHA -cne $env:RELEASE_SHA", approvalJob);
        Assert.Contains("$env:APPROVED_TAG -cne $env:RELEASE_TAG", approvalJob);
        Assert.Contains("/branches/main", approvalJob);
        Assert.Contains("-not [bool]$branch.protected", approvalJob);
        Assert.Contains("$mainSha -cne $env:RELEASE_SHA", approvalJob);
        Assert.Contains("approved_sha=$($env:RELEASE_SHA)", approvalJob);
        Assert.Contains("approved_tag=$($env:RELEASE_TAG)", approvalJob);
        Assert.DoesNotContain("actions/checkout", approvalJob);
        Assert.DoesNotContain("contents: write", approvalJob);
        Assert.False(workflow.Contains("variables: write", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Every_tag_pipeline_job_has_a_verified_needs_path_to_live_smoke_approval()
    {
        var workflow = ReadReleaseWorkflow();
        var jobNames = ReadJobNames(workflow);
        var needsByJob = jobNames.ToDictionary(
            jobName => jobName,
            jobName => ReadNeeds(ReadJob(workflow, jobName)),
            StringComparer.Ordinal);

        var requiredEdges = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["test"] = ["live-smoke-approval"],
            ["publish"] = ["test"],
            ["package"] = ["test", "publish"],
            ["installer-validation"] = ["test", "package"],
            ["supply-chain"] = ["test", "installer-validation"],
            ["draft-release"] = ["live-smoke-approval", "test", "supply-chain"],
        };

        foreach (var (jobName, requiredNeeds) in requiredEdges)
        {
            Assert.True(needsByJob.ContainsKey(jobName), $"Could not find tag pipeline job '{jobName}'.");
            foreach (var requiredNeed in requiredNeeds)
            {
                Assert.Contains(requiredNeed, needsByJob[jobName]);
            }

            Assert.True(
                TransitivelyNeeds(jobName, "live-smoke-approval", needsByJob),
                $"Tag pipeline job '{jobName}' has no needs path to live-smoke-approval.");
        }

        var nonTagJobs = new HashSet<string>(
            ["live-smoke-approval", "windows11-smoke"],
            StringComparer.Ordinal);
        foreach (var jobName in jobNames.Where(jobName => !nonTagJobs.Contains(jobName)))
        {
            Assert.True(
                TransitivelyNeeds(jobName, "live-smoke-approval", needsByJob),
                $"Release job '{jobName}' must be classified as manual or transitively gated by live-smoke-approval.");
        }
    }

    [Fact]
    public void Draft_job_revalidates_live_smoke_approval_outputs()
    {
        var workflow = ReadReleaseWorkflow();
        var draftJob = ReadJob(workflow, "draft-release");

        Assert.Contains(
            "APPROVED_SHA: ${{ needs.live-smoke-approval.outputs.approved_sha }}",
            draftJob);
        Assert.Contains(
            "APPROVED_TAG: ${{ needs.live-smoke-approval.outputs.approved_tag }}",
            draftJob);
        Assert.Contains("\"$APPROVED_SHA\" != \"$RELEASE_SHA\"", draftJob);
        Assert.Contains("\"$APPROVED_TAG\" != \"$RELEASE_TAG\"", draftJob);
        Assert.Contains("maintainer-attested live Windows 11 source smoke", draftJob);
        Assert.Contains("attached release artifacts", draftJob);
        Assert.Contains("must not be published", draftJob);
    }

    [Fact]
    public void Destructive_self_hosted_smoke_remains_manual_and_unavailable_to_pull_requests()
    {
        var workflow = ReadReleaseWorkflow();
        var smokeJob = ReadJob(workflow, "windows11-smoke");

        Assert.Contains("github.event_name == 'workflow_dispatch'", smokeJob);
        Assert.Contains("github.ref == 'refs/heads/main'", smokeJob);
        Assert.Contains("runs-on: [self-hosted, Windows, X64, windows-11]", smokeJob);
        Assert.DoesNotContain("pull_request", smokeJob);
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

    private static string ReadReleaseWorkflow()
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(root, ".github/workflows/release.yml"))
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
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DistractionFirewall.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
