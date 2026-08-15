namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class LiveRegistryPolicyTests
{
    [Fact(Skip = "Requires an isolated disposable Windows 11 x64 VM; writes and restores HKLM browser machine policies.")]
    public void LiveChromeEdgeFirefoxPolicyApplyRefreshAndRestore()
    {
        throw new NotSupportedException("This gate is intentionally VM-only.");
    }
}
