using System.Net;
using System.Runtime.InteropServices;
using DistractionFirewall.Enforcement.Windows.Wfp;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class WfpInteropAndPolicyTests
{
    [Fact]
    public void WfpExceptionPreservesNativeErrorCodeAsHResult()
    {
        const uint errorCode = 0x80320005;

        var exception = new WfpException("test-operation", errorCode);

        Assert.Equal(errorCode, exception.ErrorCode);
        Assert.Equal(unchecked((int)errorCode), exception.HResult);
    }

    [Fact]
    public void NativeLayoutsMatchWindowsX64Abi()
    {
        Assert.Equal(8, nint.Size);
        Assert.Equal(16, Marshal.SizeOf<FwpDisplayData0>());
        Assert.Equal(16, Marshal.SizeOf<FwpByteBlob>());
        Assert.Equal(16, Marshal.SizeOf<FwpValue0>());
        Assert.Equal(16, Marshal.SizeOf<FwpConditionValue0>());
        Assert.Equal(8, Marshal.SizeOf<FwpV4AddressAndMask>());
        Assert.Equal(17, Marshal.SizeOf<FwpV6AddressAndMask>());
        Assert.Equal(40, Marshal.SizeOf<FwpmFilterCondition0>());
        Assert.Equal(20, Marshal.SizeOf<FwpAction0>());
        Assert.Equal(64, Marshal.SizeOf<FwpmProvider0>());
        Assert.Equal(72, Marshal.SizeOf<FwpmSubLayer0>());
        Assert.Equal(192, Marshal.SizeOf<FwpmFilter0>());
        Assert.Equal(0, typeof(FwpmFilter0).StructLayoutAttribute!.Pack);
        Assert.Equal(0, typeof(FwpmFilterCondition0).StructLayoutAttribute!.Pack);

        Assert.Equal(8, Marshal.OffsetOf<FwpConditionValue0>(nameof(FwpConditionValue0.Value)).ToInt32());
        Assert.Equal(24, Marshal.OffsetOf<FwpmFilterCondition0>(nameof(FwpmFilterCondition0.ConditionValue)).ToInt32());
        Assert.Equal(40, Marshal.OffsetOf<FwpmProvider0>(nameof(FwpmProvider0.ProviderData)).ToInt32());
        Assert.Equal(120, Marshal.OffsetOf<FwpmFilter0>(nameof(FwpmFilter0.FilterCondition)).ToInt32());
        Assert.Equal(128, Marshal.OffsetOf<FwpmFilter0>(nameof(FwpmFilter0.Action)).ToInt32());
        Assert.Equal(176, Marshal.OffsetOf<FwpmFilter0>(nameof(FwpmFilter0.EffectiveWeight)).ToInt32());
    }

    [Theory]
    [InlineData("203.0.113.9")]
    [InlineData("2001:db8::9")]
    public void EachAddressCreatesAleAndOutboundTransportFilters(string addressText)
    {
        var leaseId = Guid.Parse("8a3d329f-4638-4f1d-876f-a9c122c76d6e");
        var first = WfpFilterSpec.CreateForAddress(leaseId, IPAddress.Parse(addressText));
        var second = WfpFilterSpec.CreateForAddress(leaseId, IPAddress.Parse(addressText));

        Assert.Equal(2, first.Count);
        Assert.Equal(2, first.Select(filter => filter.LayerKey).Distinct().Count());
        Assert.Equal(first.Select(filter => filter.FilterKey), second.Select(filter => filter.FilterKey));
        Assert.All(first, filter => Assert.Equal(addressText, filter.ParseAddress().ToString()));

        if (IPAddress.Parse(addressText).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            Assert.Contains(first, filter => filter.LayerKey == WfpProductConstants.AleAuthConnectV4);
            Assert.Contains(first, filter => filter.LayerKey == WfpProductConstants.OutboundTransportV4);
        }
        else
        {
            Assert.Contains(first, filter => filter.LayerKey == WfpProductConstants.AleAuthConnectV6);
            Assert.Contains(first, filter => filter.LayerKey == WfpProductConstants.OutboundTransportV6);
        }
    }

    [Fact]
    public void AddFailureAlwaysAbortsExplicitTransaction()
    {
        var native = new FakeWfpNativeSessionFactory { ThrowOnAddFilter = true };
        var store = new WfpPolicyStore(native);
        var filters = WfpFilterSpec.CreateForAddress(
            Guid.NewGuid(),
            IPAddress.Parse("203.0.113.10"));

        Assert.Throws<InvalidOperationException>(() => store.EnsurePersistentFilters(filters));

        Assert.Equal(1, native.BeginCount);
        Assert.Equal(0, native.CommitCount);
        Assert.Equal(1, native.AbortCount);
    }

    [Fact]
    public void SuccessfulApplyCommitsOneTransaction()
    {
        var native = new FakeWfpNativeSessionFactory();
        var store = new WfpPolicyStore(native);
        var filters = WfpFilterSpec.CreateForAddress(
            Guid.NewGuid(),
            IPAddress.Parse("203.0.113.10"));

        store.EnsurePersistentFilters(filters);

        Assert.Equal(WfpObjectMatch.Matching, native.Provider);
        Assert.Equal(WfpObjectMatch.Matching, native.SubLayer);
        Assert.Equal(2, native.Filters.Count);
        Assert.Equal(1, native.CommitCount);
        Assert.Equal(0, native.AbortCount);
    }

    [Fact]
    public void RestoreRefusesForeignKnownGuidAndAbortsWithoutDeletion()
    {
        var native = new FakeWfpNativeSessionFactory();
        var store = new WfpPolicyStore(native);
        var filters = WfpFilterSpec.CreateForAddress(
            Guid.NewGuid(),
            IPAddress.Parse("203.0.113.10"));
        native.Filters[filters[0].FilterKey] = WfpObjectMatch.Foreign;
        native.Filters[filters[1].FilterKey] = WfpObjectMatch.Matching;

        Assert.Throws<InvalidOperationException>(() => store.RestoreKnownFilters(filters));

        Assert.Equal(0, native.DeleteCount);
        Assert.Equal(1, native.AbortCount);
        Assert.Equal(0, native.CommitCount);
    }

    [Fact]
    public void ReconcileAddsAndRemovesFiltersInOneTransaction()
    {
        var native = new FakeWfpNativeSessionFactory
        {
            Provider = WfpObjectMatch.Matching,
            SubLayer = WfpObjectMatch.Matching,
        };
        var store = new WfpPolicyStore(native);
        var leaseId = Guid.NewGuid();
        var expired = WfpFilterSpec.CreateForAddress(
            leaseId,
            IPAddress.Parse("203.0.113.10"));
        var current = WfpFilterSpec.CreateForAddress(
            leaseId,
            IPAddress.Parse("2001:db8::10"));
        foreach (var filter in expired)
        {
            native.Filters[filter.FilterKey] = WfpObjectMatch.Matching;
        }

        store.ReconcilePersistentFilters(current, expired);

        Assert.All(expired, filter => Assert.DoesNotContain(filter.FilterKey, native.Filters.Keys));
        Assert.All(current, filter => Assert.Equal(WfpObjectMatch.Matching, native.Filters[filter.FilterKey]));
        Assert.Equal(1, native.BeginCount);
        Assert.Equal(1, native.CommitCount);
        Assert.Equal(0, native.AbortCount);
    }

    [Fact]
    public void ReconcileDeleteFailureAbortsAddAndRemoveTogether()
    {
        var native = new FakeWfpNativeSessionFactory
        {
            Provider = WfpObjectMatch.Matching,
            SubLayer = WfpObjectMatch.Matching,
            ThrowOnDeleteFilter = true,
        };
        var store = new WfpPolicyStore(native);
        var leaseId = Guid.NewGuid();
        var expired = WfpFilterSpec.CreateForAddress(
            leaseId,
            IPAddress.Parse("203.0.113.10"));
        var current = WfpFilterSpec.CreateForAddress(
            leaseId,
            IPAddress.Parse("2001:db8::10"));
        foreach (var filter in expired)
        {
            native.Filters[filter.FilterKey] = WfpObjectMatch.Matching;
        }

        Assert.Throws<InvalidOperationException>(() =>
            store.ReconcilePersistentFilters(current, expired));

        Assert.All(expired, filter => Assert.Equal(WfpObjectMatch.Matching, native.Filters[filter.FilterKey]));
        Assert.All(current, filter => Assert.DoesNotContain(filter.FilterKey, native.Filters.Keys));
        Assert.Equal(0, native.CommitCount);
        Assert.Equal(1, native.AbortCount);
    }

    [Fact]
    public void ReconcileForeignRemovalAbortsBeforeAddingAnything()
    {
        var native = new FakeWfpNativeSessionFactory
        {
            Provider = WfpObjectMatch.Matching,
            SubLayer = WfpObjectMatch.Matching,
        };
        var store = new WfpPolicyStore(native);
        var leaseId = Guid.NewGuid();
        var expired = WfpFilterSpec.CreateForAddress(
            leaseId,
            IPAddress.Parse("203.0.113.10"));
        var current = WfpFilterSpec.CreateForAddress(
            leaseId,
            IPAddress.Parse("2001:db8::10"));
        native.Filters[expired[0].FilterKey] = WfpObjectMatch.Foreign;
        native.Filters[expired[1].FilterKey] = WfpObjectMatch.Matching;

        Assert.Throws<InvalidOperationException>(() =>
            store.ReconcilePersistentFilters(current, expired));

        Assert.All(current, filter => Assert.DoesNotContain(filter.FilterKey, native.Filters.Keys));
        Assert.Equal(0, native.CommitCount);
        Assert.Equal(1, native.AbortCount);
    }

    [Fact]
    public void InstallationCleanupTreatsMissingInfrastructureAsIdempotentWithoutEnumeratingFilters()
    {
        var native = new FakeWfpNativeSessionFactory();
        var store = new WfpPolicyStore(native);

        store.RemovePersistentInfrastructure();

        Assert.Equal(WfpObjectMatch.Missing, native.Provider);
        Assert.Equal(WfpObjectMatch.Missing, native.SubLayer);
        Assert.Empty(native.InfrastructureDeletionOrder);
        Assert.Equal(0, native.CountFilterReferencesCount);
        Assert.Equal(1, native.BeginCount);
        Assert.Equal(1, native.CommitCount);
        Assert.Equal(0, native.AbortCount);
    }

    [Fact]
    public void InstallationCleanupDeletesEmptyMatchingSublayerThenProviderInOneTransaction()
    {
        var native = new FakeWfpNativeSessionFactory
        {
            Provider = WfpObjectMatch.Matching,
            SubLayer = WfpObjectMatch.Matching,
        };
        var store = new WfpPolicyStore(native);

        store.RemovePersistentInfrastructure();

        Assert.Equal(WfpObjectMatch.Missing, native.Provider);
        Assert.Equal(WfpObjectMatch.Missing, native.SubLayer);
        Assert.Equal(["sublayer", "provider"], native.InfrastructureDeletionOrder);
        Assert.Equal(1, native.CountFilterReferencesCount);
        Assert.Equal(1, native.BeginCount);
        Assert.Equal(1, native.CommitCount);
        Assert.Equal(0, native.AbortCount);
    }

    [Theory]
    [InlineData(false, true, "sublayer")]
    [InlineData(true, false, "provider")]
    public void InstallationCleanupInspectsFiltersBeforeDeletingMixedInfrastructure(
        bool providerPresent,
        bool subLayerPresent,
        string expectedDeletion)
    {
        var native = new FakeWfpNativeSessionFactory
        {
            Provider = providerPresent ? WfpObjectMatch.Matching : WfpObjectMatch.Missing,
            SubLayer = subLayerPresent ? WfpObjectMatch.Matching : WfpObjectMatch.Missing,
        };

        new WfpPolicyStore(native).RemovePersistentInfrastructure();

        Assert.Equal([expectedDeletion], native.InfrastructureDeletionOrder);
        Assert.Equal(1, native.CountFilterReferencesCount);
        Assert.Equal(1, native.CommitCount);
        Assert.Equal(0, native.AbortCount);
    }

    [Fact]
    public void InstallationCleanupRefusesReferencedInfrastructureWithoutDeletion()
    {
        var referenced = new FakeWfpNativeSessionFactory
        {
            Provider = WfpObjectMatch.Matching,
            SubLayer = WfpObjectMatch.Matching,
            AdditionalProductFilterReferences = 1,
        };

        Assert.Throws<InvalidOperationException>(() =>
            new WfpPolicyStore(referenced).RemovePersistentInfrastructure());

        Assert.Empty(referenced.InfrastructureDeletionOrder);
        Assert.Equal(1, referenced.CountFilterReferencesCount);
        Assert.Equal(1, referenced.AbortCount);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void InstallationCleanupRefusesForeignInfrastructureBeforeEnumeratingFilters(
        bool providerForeign,
        bool subLayerForeign)
    {
        var foreign = new FakeWfpNativeSessionFactory
        {
            Provider = providerForeign ? WfpObjectMatch.Foreign : WfpObjectMatch.Matching,
            SubLayer = subLayerForeign ? WfpObjectMatch.Foreign : WfpObjectMatch.Matching,
        };

        Assert.Throws<InvalidOperationException>(() =>
            new WfpPolicyStore(foreign).RemovePersistentInfrastructure());

        Assert.Empty(foreign.InfrastructureDeletionOrder);
        Assert.Equal(0, foreign.CountFilterReferencesCount);
        Assert.Equal(1, foreign.AbortCount);
    }

    [Fact]
    public void InstallationCleanupDeleteFailureRollsBackBothInfrastructureObjects()
    {
        var native = new FakeWfpNativeSessionFactory
        {
            Provider = WfpObjectMatch.Matching,
            SubLayer = WfpObjectMatch.Matching,
            ThrowOnDeleteProvider = true,
        };
        var store = new WfpPolicyStore(native);

        Assert.Throws<InvalidOperationException>(() => store.RemovePersistentInfrastructure());

        Assert.Equal(WfpObjectMatch.Matching, native.Provider);
        Assert.Equal(WfpObjectMatch.Matching, native.SubLayer);
        Assert.Equal(["sublayer"], native.InfrastructureDeletionOrder);
        Assert.Equal(1, native.DeleteSubLayerCount);
        Assert.Equal(0, native.DeleteProviderCount);
        Assert.Equal(0, native.CommitCount);
        Assert.Equal(1, native.AbortCount);
    }

    [Fact(Skip = "Requires an isolated disposable Windows 11 x64 VM; mutates persistent BFE policy and validates live TCP/QUIC flow interruption.")]
    public void LivePersistentWfpApplyRebootFlowInterruptionAndRestore()
    {
        throw new NotSupportedException("This gate is intentionally VM-only.");
    }
}
