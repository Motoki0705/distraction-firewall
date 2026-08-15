using System.Text.Json;
using DistractionFirewall.Core.Enforcement;

namespace DistractionFirewall.Enforcement.Windows;

internal interface IWindowsPrimaryBlockingAdapter
{
}

internal interface IWindowsPendingVerificationAdapter
{
    bool IsPending(EnforcementArtifact artifact, EnforcementVerification verification);
}

internal interface IWindowsIncrementalArtifactAdapter
{
    EnforcementArtifact MergeReconciledArtifact(
        EnforcementArtifact existingArtifact,
        EnforcementArtifact reconciledArtifact);

    EnforcementArtifact? CreateRollbackArtifact(
        EnforcementArtifact existingArtifact,
        EnforcementArtifact reconciledArtifact);
}

public sealed class WindowsEnforcementAdapter : IEnforcementReconciliationAdapter, IDisposable
{
    private readonly IReadOnlyList<IEnforcementAdapter> _components;
    private readonly IDisposable _ownedLifetime;
    private bool _disposed;

    internal WindowsEnforcementAdapter(
        IReadOnlyList<IEnforcementAdapter> components,
        IDisposable ownedLifetime)
    {
        _components = components ?? throw new ArgumentNullException(nameof(components));
        _ownedLifetime = ownedLifetime ?? throw new ArgumentNullException(nameof(ownedLifetime));
        if (_components.Count == 0
            || _components.Select(component => component.AdapterId).Distinct(StringComparer.Ordinal).Count()
                != _components.Count)
        {
            throw new ArgumentException("Windows enforcement components must be non-empty and unique.", nameof(components));
        }
    }

    public string AdapterId => "windows-live";

    public async Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var health = new List<EnforcementHealth>(_components.Count);
        foreach (var component in _components)
        {
            health.Add(await component.CheckHealthAsync(cancellationToken).ConfigureAwait(false));
        }

        return new EnforcementHealth(
            AdapterId,
            health.All(item => item.Available),
            health.All(item => item.Healthy),
            string.Join(" | ", health.Select(item => item.AdapterId + ": " + item.Summary)));
    }

    public async Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);
        var applied = new List<(IEnforcementAdapter Adapter, EnforcementArtifact Artifact)>();
        try
        {
            foreach (var component in _components)
            {
                var artifact = await component.ApplyAsync(context, cancellationToken).ConfigureAwait(false);
                applied.Add((component, artifact));
            }
        }
        catch
        {
            foreach (var item in applied.AsEnumerable().Reverse())
            {
                try
                {
                    _ = await item.Adapter.RestoreAsync(context, item.Artifact, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    System.Diagnostics.Trace.TraceError(
                        "Composite rollback for {0} failed: {1}",
                        item.Adapter.AdapterId,
                        exception.Message);
                }
            }

            throw;
        }

        return CreateCompositeArtifact(applied.Select(item => (item.Adapter, item.Artifact)));
    }

    public async Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ValidateArtifact(artifact);
        var results = new List<ComponentVerification>(_components.Count);
        foreach (var component in _components)
        {
            var componentArtifact = ReadComponentArtifact(artifact, component.AdapterId);
            var verification = await component.VerifyAsync(context, componentArtifact, cancellationToken)
                .ConfigureAwait(false);
            results.Add(new ComponentVerification(component, componentArtifact, verification));
        }

        var targetBlocked = EvaluateTargetBlocked(results);
        return new EnforcementVerification(
            AdapterId,
            targetBlocked,
            results.All(result => result.Verification.GeneralConnectivityAvailable),
            string.Join(" | ", results.Select(result =>
                result.Verification.AdapterId + ": " + result.Verification.Summary)));
    }

    public async Task<EnforcementArtifact> ReconcileAsync(
        EnforcementContext context,
        EnforcementArtifact existingArtifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(existingArtifact);

        var reconciled = new List<(IEnforcementAdapter Adapter, EnforcementArtifact Artifact)>(_components.Count);
        var rollback = new List<(IEnforcementAdapter Adapter, EnforcementArtifact Artifact)>();
        try
        {
            foreach (var component in _components)
            {
                var existingComponent = ReadComponentArtifact(existingArtifact, component.AdapterId);
                var verification = await component.VerifyAsync(
                    context,
                    existingComponent,
                    cancellationToken).ConfigureAwait(false);
                if ((verification.TargetBlocked && verification.GeneralConnectivityAvailable)
                    || IsPending(component, existingComponent, verification))
                {
                    reconciled.Add((component, existingComponent));
                    continue;
                }

                var replacement = component is IEnforcementReconciliationAdapter reconciliationAdapter
                    ? await reconciliationAdapter.ReconcileAsync(
                        context,
                        existingComponent,
                        cancellationToken).ConfigureAwait(false)
                    : await component.ApplyAsync(context, cancellationToken).ConfigureAwait(false);
                ValidateComponentArtifact(component, replacement);
                var merged = component is IWindowsIncrementalArtifactAdapter incremental
                    ? incremental.MergeReconciledArtifact(existingComponent, replacement)
                    : MergeOwnedArtifacts(existingComponent, replacement);
                ValidateComponentArtifact(component, merged);
                var rollbackArtifact = component is IWindowsIncrementalArtifactAdapter deltaAdapter
                    ? deltaAdapter.CreateRollbackArtifact(existingComponent, merged)
                    : CreateGenericRollbackArtifact(existingComponent, merged);
                if (rollbackArtifact is not null)
                {
                    rollback.Add((component, rollbackArtifact));
                }

                reconciled.Add((component, merged));
            }

            var result = CreateCompositeArtifact(reconciled);
            var finalVerification = await VerifyAsync(context, result, cancellationToken).ConfigureAwait(false);
            if (!finalVerification.TargetBlocked || !finalVerification.GeneralConnectivityAvailable)
            {
                throw new InvalidOperationException(
                    "Windows composite reconciliation verification failed: " + finalVerification.Summary);
            }

            return result;
        }
        catch
        {
            foreach (var item in rollback.AsEnumerable().Reverse())
            {
                try
                {
                    _ = await item.Adapter.RestoreAsync(context, item.Artifact, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    System.Diagnostics.Trace.TraceError(
                        "Composite incremental rollback for {0} failed: {1}",
                        item.Adapter.AdapterId,
                        exception.Message);
                }
            }

            throw;
        }
    }

    public async Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ValidateArtifact(artifact);
        var results = new List<RestoreResult>(_components.Count);
        foreach (var component in _components.Reverse())
        {
            var componentArtifact = ReadComponentArtifact(artifact, component.AdapterId);
            results.Add(await component.RestoreAsync(context, componentArtifact, cancellationToken)
                .ConfigureAwait(false));
        }

        return new RestoreResult(
            AdapterId,
            results.All(result => result.Restored),
            results.Any(result => result.Retryable),
            string.Join(" | ", results.Select(result => result.AdapterId + ": " + result.Summary)));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _ownedLifetime.Dispose();
        _disposed = true;
    }

    private static EnforcementArtifact ReadComponentArtifact(
        EnforcementArtifact artifact,
        string componentAdapterId)
    {
        if (!artifact.Properties.TryGetValue("component." + componentAdapterId, out var serialized))
        {
            throw new InvalidDataException($"Composite artifact is missing component '{componentAdapterId}'.");
        }

        var component = JsonSerializer.Deserialize<EnforcementArtifact>(serialized)
            ?? throw new InvalidDataException($"Composite artifact component '{componentAdapterId}' is invalid.");
        if (!string.Equals(component.AdapterId, componentAdapterId, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Composite artifact component '{componentAdapterId}' was substituted.");
        }

        return component;
    }

    private EnforcementArtifact CreateCompositeArtifact(
        IEnumerable<(IEnforcementAdapter Adapter, EnforcementArtifact Artifact)> components)
    {
        var materialized = components.ToArray();
        foreach (var item in materialized)
        {
            ValidateComponentArtifact(item.Adapter, item.Artifact);
        }

        var properties = materialized.ToDictionary(
            item => "component." + item.Adapter.AdapterId,
            item => JsonSerializer.Serialize(item.Artifact),
            StringComparer.Ordinal);
        var ownedResourceIds = materialized
            .SelectMany(item => item.Artifact.OwnedResourceIds.Select(
                resourceId => item.Adapter.AdapterId + ":" + resourceId))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return new EnforcementArtifact(AdapterId, SchemaVersion: 1, ownedResourceIds, properties);
    }

    private static EnforcementArtifact MergeOwnedArtifacts(
        EnforcementArtifact existing,
        EnforcementArtifact replacement)
    {
        var properties = new Dictionary<string, string>(existing.Properties, StringComparer.Ordinal);
        foreach (var property in replacement.Properties)
        {
            properties[property.Key] = property.Value;
        }

        return replacement with
        {
            OwnedResourceIds = existing.OwnedResourceIds
                .Concat(replacement.OwnedResourceIds)
                .Distinct(StringComparer.Ordinal)
                .ToArray(),
            Properties = properties,
        };
    }

    private static EnforcementArtifact? CreateGenericRollbackArtifact(
        EnforcementArtifact existing,
        EnforcementArtifact reconciled)
    {
        var existingIds = existing.OwnedResourceIds.ToHashSet(StringComparer.Ordinal);
        var newIds = reconciled.OwnedResourceIds.Where(id => !existingIds.Contains(id)).ToArray();
        return newIds.Length == 0 ? null : reconciled with { OwnedResourceIds = newIds };
    }

    private static bool EvaluateTargetBlocked(IReadOnlyList<ComponentVerification> results)
    {
        var nonPending = results.Where(result => !IsPending(
            result.Adapter,
            result.Artifact,
            result.Verification)).ToArray();
        var primary = nonPending
            .Where(result => result.Adapter is IWindowsPrimaryBlockingAdapter)
            .ToArray();
        if (primary.Length == 0)
        {
            primary = nonPending;
        }

        return primary.Length > 0
            && primary.All(result => result.Verification.TargetBlocked)
            && nonPending.All(result => result.Verification.TargetBlocked);
    }

    private static bool IsPending(
        IEnforcementAdapter adapter,
        EnforcementArtifact artifact,
        EnforcementVerification verification)
    {
        return adapter is IWindowsPendingVerificationAdapter pending
            && pending.IsPending(artifact, verification);
    }

    private static void ValidateComponentArtifact(
        IEnforcementAdapter component,
        EnforcementArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!string.Equals(component.AdapterId, artifact.AdapterId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Component '{component.AdapterId}' returned artifact owner '{artifact.AdapterId}'.");
        }
    }

    private void ValidateArtifact(EnforcementArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!string.Equals(artifact.AdapterId, AdapterId, StringComparison.Ordinal)
            || artifact.SchemaVersion != 1)
        {
            throw new ArgumentException("The enforcement artifact does not belong to this adapter.", nameof(artifact));
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed record ComponentVerification(
        IEnforcementAdapter Adapter,
        EnforcementArtifact Artifact,
        EnforcementVerification Verification);
}
