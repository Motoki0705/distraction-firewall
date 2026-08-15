namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class DnsLiveIntegrationTests
{
    [Fact(Skip = "Requires an isolated disposable Windows 11 x64 VM, SYSTEM task provisioning, the signed DNS filter, and static IPv4/IPv6 adapters.")]
    public void LiveStaticDualStackReadySeedApplyAndCasRestore()
    {
        throw new NotSupportedException("This destructive live DNS gate is intentionally VM-only.");
    }

    [Fact(Skip = "Requires an isolated Windows 11 VM to prove per-family DHCP classification, loopback mutation, empty-nameserver reset, and resolver-cache refresh.")]
    public void LiveDhcpOriginSnapshotApplyAndExactResetGate()
    {
        throw new NotSupportedException("DHCP DNS restoration has not passed the VM-only gate.");
    }

    [Fact(Skip = "Requires an isolated Windows 11 VM with scripted VPN/tunnel adapter hot-plug while a lease is active.")]
    public void LiveVpnAndNewAdapterReconcileUpdatesUpstreamsAndRestores()
    {
        throw new NotSupportedException("This network hot-plug gate is intentionally VM-only.");
    }

    [Fact(Skip = "Requires an isolated Windows 11 VM to suspend/resume and verify the lease token sentinel on IPv4/IPv6 before DNS remains redirected.")]
    public void LiveSleepResumeTaskRecoveryAndLeaseSentinel()
    {
        throw new NotSupportedException("This power-transition gate is intentionally VM-only.");
    }

    [Fact(Skip = "Requires an isolated VM to prove owned Task Stop(0) completion, process exit, task-chain CAS restore, and immediate port 53 reuse without stopping foreign tasks.")]
    public void LiveOwnedFilterStopConfirmationAndPortReuse()
    {
        throw new NotSupportedException("This process/task ownership gate is intentionally VM-only.");
    }

    [Fact(Skip = "Requires controlled authoritative DNS to prove exact-host/CNAME resolution and TTL-bounded address-only observation persistence against snapshotted upstreams.")]
    public void LiveCnameTtlObservationSeedContainsNoQueryNames()
    {
        throw new NotSupportedException("This controlled-DNS privacy gate is intentionally VM-only.");
    }
}
