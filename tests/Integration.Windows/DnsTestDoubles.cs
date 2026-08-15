using DistractionFirewall.Enforcement.Windows.Dns;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;

namespace DistractionFirewall.Integration.Windows.Tests;

internal sealed class FakeDnsSettingsStore : IWindowsDnsSettingsStore, IPostWriteVerificationStore
{
    private readonly Dictionary<string, OwnedResourceState> _states = new(StringComparer.Ordinal);
    private readonly HashSet<string> _active = new(StringComparer.Ordinal);
    private readonly IList<string> _events;

    public FakeDnsSettingsStore(IList<string>? events = null)
    {
        _events = events ?? new List<string>();
    }

    public int MutationCount { get; private set; }

    public int EnumerationCount { get; private set; }

    public Action<int>? BeforeEnumeration { get; set; }

    public Func<DnsInterfaceSettingsState, DnsInterfaceSettingsState>? TransformReplacement { get; set; }

    public bool CheckAvailable(out string summary)
    {
        summary = "fake DNS store available";
        return true;
    }

    public ValueTask<IReadOnlyList<DnsInterfaceSettingsState>> EnumerateActiveAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnumerationCount++;
        BeforeEnumeration?.Invoke(EnumerationCount);
        _events.Add("dns:enumerate");
        var result = _active
            .Order(StringComparer.Ordinal)
            .Select(resourceId => DnsSettingsStateCodec.Decode(_states[resourceId]))
            .ToArray();
        return ValueTask.FromResult<IReadOnlyList<DnsInterfaceSettingsState>>(result);
    }

    public ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            _states.TryGetValue(resourceId, out var state) ? state : OwnedResourceState.Missing);
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return DnsSettingsStateCodec.Equivalent(left, right);
    }

    public bool ReplacementWasApplied(
        OwnedResourceState actual,
        OwnedResourceState replacement)
    {
        if (!actual.Exists || !replacement.Exists)
        {
            return StatesEqual(actual, replacement);
        }

        var expected = DnsSettingsStateCodec.Decode(replacement);
        if (expected.Origin != DnsConfigurationOrigin.Dhcp)
        {
            return StatesEqual(actual, replacement);
        }

        var current = DnsSettingsStateCodec.Decode(actual);
        return current.InterfaceId == expected.InterfaceId
            && current.AddressFamily == expected.AddressFamily
            && current.Origin == DnsConfigurationOrigin.Dhcp
            && current.NameServers.Count > 0;
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        if (!expected.Exists || !replacement.Exists)
        {
            throw new InvalidOperationException("Fake DNS mutations require an existing interface family.");
        }

        _ = DnsSettingsMutationPlan.Create(
            DnsSettingsStateCodec.Decode(expected),
            DnsSettingsStateCodec.Decode(replacement));

        MutationCount++;
        _events.Add("dns:write:" + resourceId);
        var replacementState = DnsSettingsStateCodec.Decode(replacement);
        SetRaw(
            resourceId,
            DnsSettingsStateCodec.Encode(
                TransformReplacement?.Invoke(replacementState) ?? replacementState));
        return true;
    }

    public string Seed(DnsInterfaceSettingsState state, bool active = true)
    {
        var resourceId = new DnsInterfaceResourceId(state.InterfaceId, state.AddressFamily).ToString();
        SetRaw(resourceId, DnsSettingsStateCodec.Encode(state));
        SetActive(resourceId, active);
        return resourceId;
    }

    public void SetExternal(string resourceId, DnsInterfaceSettingsState state)
    {
        SetRaw(resourceId, DnsSettingsStateCodec.Encode(state));
    }

    public DnsInterfaceSettingsState ReadState(string resourceId)
    {
        return DnsSettingsStateCodec.Decode(_states[resourceId]);
    }

    public void SetActive(string resourceId, bool active)
    {
        if (active)
        {
            _active.Add(resourceId);
        }
        else
        {
            _active.Remove(resourceId);
        }
    }

    private void SetRaw(string resourceId, OwnedResourceState state)
    {
        if (state.Exists)
        {
            _states[resourceId] = state;
        }
        else
        {
            _states.Remove(resourceId);
            _active.Remove(resourceId);
        }
    }
}

internal sealed class FakeDnsFilterLauncher : IDnsFilterLauncher
{
    private readonly IList<string> _events;

    public FakeDnsFilterLauncher(IList<string>? events = null)
    {
        _events = events ?? new List<string>();
    }

    public int StartCount { get; private set; }

    public bool ThrowOnStart { get; set; }

    public string? OwnershipRecordId { get; set; }

    public List<DnsFilterLaunchRequest> Requests { get; } = [];

    public bool CheckAvailable(out string summary)
    {
        summary = "fake DNS filter launcher available";
        return true;
    }

    public Task<DnsFilterLaunchResult> EnsureStartedAsync(
        DnsFilterLaunchRequest request,
        string? expectedCurrentOwnershipRecordId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        StartCount++;
        Requests.Add(request);
        _events.Add("launcher:start");
        if (ThrowOnStart)
        {
            throw new InvalidOperationException("injected launcher failure");
        }

        return Task.FromResult(new DnsFilterLaunchResult(
            "task:\\DistractionFirewall\\DnsFilter-" + request.LeaseId.ToString("N"),
            OwnershipRecordId));
    }

    public Task<OwnedRestoreResult?> RestoreTaskAsync(
        string? ownershipRecordId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _events.Add("launcher:restore");
        return Task.FromResult<OwnedRestoreResult?>(ownershipRecordId is null
            ? null
            : new OwnedRestoreResult(true, false, "fake task restored"));
    }
}

internal sealed class FakeDnsFilterReadyProbe : IDnsFilterReadyProbe
{
    private readonly IList<string> _events;

    public FakeDnsFilterReadyProbe(IList<string>? events = null)
    {
        _events = events ?? new List<string>();
    }

    public bool ThrowTimeout { get; set; }

    public int CallCount { get; private set; }

    public List<DnsFilterReadinessRequest> Requests { get; } = [];

    public Task WaitUntilReadyAsync(
        DnsFilterReadinessRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CallCount++;
        Requests.Add(request);
        _events.Add("probe:ready");
        return ThrowTimeout
            ? Task.FromException(new TimeoutException("injected readiness timeout"))
            : Task.CompletedTask;
    }
}

internal sealed class FakeDnsFilterTaskStore : IDnsFilterTaskStore
{
    private readonly Dictionary<string, OwnedResourceState> _states = new(StringComparer.Ordinal);

    public int MutationCount { get; private set; }

    public List<string> Runs { get; } = [];

    public List<string> Restarts { get; } = [];

    public List<string> Stops { get; } = [];

    public int? ThrowOnRestartCall { get; set; }

    public bool CheckAvailable(out string summary)
    {
        summary = "fake DNS task store available";
        return true;
    }

    public ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            _states.TryGetValue(resourceId, out var state) ? state : OwnedResourceState.Missing);
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right) =>
        TaskStateCodec.Equivalent(left, right);

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        MutationCount++;
        Seed(resourceId, replacement);
        return true;
    }

    public void Run(string resourceId)
    {
        Runs.Add(resourceId);
    }

    public Task RestartAsync(string resourceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Restarts.Add(resourceId);
        if (ThrowOnRestartCall == Restarts.Count)
        {
            throw new InvalidOperationException("injected DNS task restart failure");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(string resourceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Stops.Add(resourceId);
        return Task.CompletedTask;
    }

    public void Seed(string resourceId, OwnedResourceState state)
    {
        if (state.Exists)
        {
            _states[resourceId] = state;
        }
        else
        {
            _states.Remove(resourceId);
        }
    }
}

internal sealed class FakeDnsObservationSeeder : IWindowsDnsUpstreamObservationSeeder
{
    private readonly IList<string> _events;

    public FakeDnsObservationSeeder(IList<string>? events = null)
    {
        _events = events ?? new List<string>();
    }

    public bool ThrowOnSeed { get; set; }

    public Action<WindowsDnsObservationSeedRequest>? OnSeed { get; set; }

    public List<WindowsDnsObservationSeedRequest> Requests { get; } = [];

    public Task SeedAsync(
        WindowsDnsObservationSeedRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Requests.Add(request);
        _events.Add("seed:upstream");
        OnSeed?.Invoke(request);
        return ThrowOnSeed
            ? Task.FromException(new IOException("injected observation seed failure"))
            : Task.CompletedTask;
    }
}
