using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Browser;

internal sealed record BrowserPolicyScalar(
    string KeyPath,
    string ValueName,
    OwnedResourceState DesiredState);

internal sealed record BrowserPolicyDefinition(
    string Name,
    string UrlBlocklistKey,
    string UrlAllowlistKey,
    IReadOnlyList<BrowserPolicyScalar> Scalars);

internal sealed record PlannedBrowserMutation(
    string ResourceId,
    OwnedResourceState DesiredState);

public sealed class BrowserPolicyEnforcementAdapter : IEnforcementAdapter, IWindowsPrimaryBlockingAdapter
{
    private const int MaximumUrlPolicyEntries = 1000;

    private static readonly IReadOnlyList<BrowserPolicyDefinition> Browsers =
    [
        new BrowserPolicyDefinition(
            "Chrome",
            @"SOFTWARE\Policies\Google\Chrome\URLBlocklist",
            @"SOFTWARE\Policies\Google\Chrome\URLAllowlist",
            [
                new BrowserPolicyScalar(
                    @"SOFTWARE\Policies\Google\Chrome",
                    "DnsOverHttpsMode",
                    RegistryPolicyValueCodec.String("off")),
                new BrowserPolicyScalar(
                    @"SOFTWARE\Policies\Google\Chrome",
                    "QuicAllowed",
                    RegistryPolicyValueCodec.DWord(0)),
            ]),
        new BrowserPolicyDefinition(
            "Edge",
            @"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist",
            @"SOFTWARE\Policies\Microsoft\Edge\URLAllowlist",
            [
                new BrowserPolicyScalar(
                    @"SOFTWARE\Policies\Microsoft\Edge",
                    "DnsOverHttpsMode",
                    RegistryPolicyValueCodec.String("off")),
                new BrowserPolicyScalar(
                    @"SOFTWARE\Policies\Microsoft\Edge",
                    "QuicAllowed",
                    RegistryPolicyValueCodec.DWord(0)),
            ]),
        new BrowserPolicyDefinition(
            "Firefox",
            @"SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block",
            @"SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Exceptions",
            [
                new BrowserPolicyScalar(
                    @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
                    "Enabled",
                    RegistryPolicyValueCodec.DWord(0)),
                new BrowserPolicyScalar(
                    @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
                    "Locked",
                    RegistryPolicyValueCodec.DWord(1)),
            ]),
    ];

    private readonly IRegistryPolicyStore _registry;
    private readonly OwnedMutationCoordinator _coordinator;
    private readonly WindowsMutationGate _mutationGate;

    internal BrowserPolicyEnforcementAdapter(
        IRegistryPolicyStore registry,
        OwnedMutationCoordinator coordinator,
        WindowsMutationGate mutationGate)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
    }

    public string AdapterId => "windows-browser-policy";

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var available = OperatingSystem.IsWindows() && _mutationGate.IsEnabled;
        return Task.FromResult(new EnforcementHealth(
            AdapterId,
            available,
            available && _registry.View == Microsoft.Win32.RegistryView.Registry64,
            available
                ? "HKLM policy adapter is enabled with the shared Registry64 policy view."
                : "Live Windows mutation was not explicitly enabled."));
    }

    public async Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        _mutationGate.Demand();

        var patterns = GetPatterns(context);
        var plan = await BuildPlanAsync(patterns, cancellationToken).ConfigureAwait(false);
        var ownedRecordIds = new List<string>();
        var alreadySatisfied = 0;

        try
        {
            foreach (var mutation in plan)
            {
                var result = await _coordinator.ApplyAsync(
                    _registry,
                    AdapterId,
                    context.LeaseId,
                    mutation.ResourceId,
                    mutation.DesiredState,
                    failIfPresent: true,
                    cancellationToken).ConfigureAwait(false);
                if (result.Owned && result.RecordId is not null)
                {
                    ownedRecordIds.Add(result.RecordId);
                }

                if (result.AlreadySatisfied)
                {
                    alreadySatisfied++;
                }
            }
        }
        catch
        {
            await RestoreRecordsBestEffortAsync(ownedRecordIds, cancellationToken).ConfigureAwait(false);
            throw;
        }

        return new EnforcementArtifact(
            AdapterId,
            SchemaVersion: 1,
            ownedRecordIds,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["pattern_count"] = patterns.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["owned_value_count"] = ownedRecordIds.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["preexisting_value_count"] = alreadySatisfied.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["registry_view"] = _registry.View.ToString(),
            });
    }

    public async Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);

        try
        {
            var plan = await BuildPlanAsync(GetPatterns(context), cancellationToken).ConfigureAwait(false);
            return new EnforcementVerification(
                AdapterId,
                TargetBlocked: plan.Count == 0,
                GeneralConnectivityAvailable: true,
                plan.Count == 0
                    ? "All browser machine-policy values are present and no matching exception was found."
                    : $"{plan.Count} browser policy values are missing.");
        }
        catch (OwnershipConflictException exception)
        {
            return new EnforcementVerification(
                AdapterId,
                TargetBlocked: false,
                GeneralConnectivityAvailable: true,
                exception.Message);
        }
    }

    public async Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);
        _mutationGate.Demand();

        var conflicts = 0;
        var failures = 0;
        foreach (var recordId in artifact.OwnedResourceIds.Reverse())
        {
            try
            {
                var result = await _coordinator.RestoreAsync(_registry, recordId, cancellationToken)
                    .ConfigureAwait(false);
                conflicts += result.Conflict ? 1 : 0;
                failures += result.Restored ? 0 : 1;
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                failures++;
            }
        }

        return new RestoreResult(
            AdapterId,
            Restored: failures == 0,
            Retryable: failures > 0,
            failures == 0
                ? "All owned browser policy values were restored by compare-and-swap."
                : $"Restore retained {failures} values, including {conflicts} ownership conflicts.");
    }

    private async Task<IReadOnlyList<PlannedBrowserMutation>> BuildPlanAsync(
        IReadOnlyList<string> patterns,
        CancellationToken cancellationToken)
    {
        var plan = new List<PlannedBrowserMutation>();
        foreach (var browser in Browsers)
        {
            await EnsureNoAllowlistConflictAsync(browser, patterns, cancellationToken).ConfigureAwait(false);

            var blockValues = await _registry.ReadKeyValuesAsync(browser.UrlBlocklistKey, cancellationToken)
                .ConfigureAwait(false);
            var reservedNames = new HashSet<string>(blockValues.Keys, StringComparer.Ordinal);
            foreach (var pattern in patterns)
            {
                var desired = RegistryPolicyValueCodec.String(pattern);
                if (blockValues.Values.Any(value => _registry.StatesEqual(value, desired)))
                {
                    continue;
                }

                var valueName = Enumerable.Range(1, MaximumUrlPolicyEntries)
                    .Select(number => number.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    .FirstOrDefault(candidate => reservedNames.Add(candidate));
                if (valueName is null)
                {
                    throw new InvalidOperationException(
                        $"{browser.Name} URLBlocklist has no free entry in the supported 1..{MaximumUrlPolicyEntries} range.");
                }

                plan.Add(new PlannedBrowserMutation(
                    new RegistryPolicyValueId(browser.UrlBlocklistKey, valueName).ToString(),
                    desired));
            }

            foreach (var scalar in browser.Scalars)
            {
                var resourceId = new RegistryPolicyValueId(scalar.KeyPath, scalar.ValueName).ToString();
                var current = await _registry.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
                if (_registry.StatesEqual(current, scalar.DesiredState))
                {
                    continue;
                }

                if (current.Exists)
                {
                    throw new OwnershipConflictException(
                        resourceId,
                        $"{browser.Name} scalar policy '{scalar.ValueName}' has a conflicting preexisting value.");
                }

                plan.Add(new PlannedBrowserMutation(resourceId, scalar.DesiredState));
            }
        }

        return plan;
    }

    private async Task EnsureNoAllowlistConflictAsync(
        BrowserPolicyDefinition browser,
        IReadOnlyList<string> patterns,
        CancellationToken cancellationToken)
    {
        var exceptions = await _registry.ReadKeyValuesAsync(browser.UrlAllowlistKey, cancellationToken)
            .ConfigureAwait(false);
        foreach (var exception in exceptions)
        {
            if (!string.Equals(
                    exception.Value.ContentType,
                    RegistryPolicyValueCodec.StringContentType,
                    StringComparison.Ordinal))
            {
                continue;
            }

            var allowPattern = RegistryPolicyValueCodec.DecodeString(exception.Value);
            if (patterns.Any(blockPattern => PolicyPatternCouldCover(allowPattern, blockPattern)))
            {
                throw new OwnershipConflictException(
                    new RegistryPolicyValueId(browser.UrlAllowlistKey, exception.Key).ToString(),
                    $"{browser.Name} has a preexisting allowlist/exception that can override a target block.");
            }
        }
    }

    private static bool PolicyPatternCouldCover(string allowPattern, string blockPattern)
    {
        if (string.Equals(allowPattern, blockPattern, StringComparison.OrdinalIgnoreCase)
            || string.Equals(allowPattern, "<all_urls>", StringComparison.OrdinalIgnoreCase)
            || string.Equals(allowPattern, "*", StringComparison.Ordinal))
        {
            return true;
        }

        var allowHost = ExtractHost(allowPattern);
        var blockHost = ExtractHost(blockPattern);
        if (allowHost is null || blockHost is null)
        {
            return false;
        }

        if (allowHost == "*")
        {
            return true;
        }

        allowHost = allowHost.TrimStart('[', ']', '*', '.');
        blockHost = blockHost.TrimStart('[', ']', '*', '.');
        return blockHost.Equals(allowHost, StringComparison.OrdinalIgnoreCase)
            || blockHost.EndsWith('.' + allowHost, StringComparison.OrdinalIgnoreCase);
    }

    private static string? ExtractHost(string pattern)
    {
        var schemeSeparator = pattern.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0)
        {
            return null;
        }

        var hostStart = schemeSeparator + 3;
        var pathStart = pattern.IndexOf('/', hostStart);
        return pathStart < 0 ? pattern[hostStart..] : pattern[hostStart..pathStart];
    }

    private static string[] GetPatterns(EnforcementContext context)
    {
        return context.Targets
            .SelectMany(target => target.BrowserUrlPatterns)
            .Where(pattern => !string.IsNullOrWhiteSpace(pattern))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private async Task RestoreRecordsBestEffortAsync(
        IEnumerable<string> recordIds,
        CancellationToken cancellationToken)
    {
        foreach (var recordId in recordIds.Reverse())
        {
            try
            {
                await _coordinator.RestoreAsync(_registry, recordId, cancellationToken).ConfigureAwait(false);
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                // The durable record remains available to the recovery worker.
            }
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
}
