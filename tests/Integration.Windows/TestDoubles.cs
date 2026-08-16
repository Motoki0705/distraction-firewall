using System.Net;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows.Browser;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Tasks;
using DistractionFirewall.Enforcement.Windows.Wfp;
using Microsoft.Win32;

namespace DistractionFirewall.Integration.Windows.Tests;

internal sealed class FakeCompareExchangeStore : ICompareExchangeResourceStore
{
    private readonly Dictionary<string, OwnedResourceState> _states = new(StringComparer.Ordinal);

    public int MutationCount { get; private set; }

    public ValueTask<OwnedResourceState> ReadAsync(string resourceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            _states.TryGetValue(resourceId, out var state) ? state : OwnedResourceState.Missing);
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return OwnedResourceState.ExactEquals(left, right);
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(resourceId, cancellationToken);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        MutationCount++;
        Set(resourceId, replacement);
        return true;
    }

    public void Set(string resourceId, OwnedResourceState state)
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

internal sealed class FakeRegistryPolicyStore : IRegistryPolicyStore
{
    private readonly Dictionary<string, OwnedResourceState> _states = new(StringComparer.Ordinal);

    public RegistryView View => RegistryView.Registry64;

    public int MutationCount { get; private set; }

    public ValueTask<OwnedResourceState> ReadAsync(string resourceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            _states.TryGetValue(resourceId, out var state) ? state : OwnedResourceState.Missing);
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return OwnedResourceState.ExactEquals(left, right);
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(resourceId, cancellationToken);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        MutationCount++;
        Seed(resourceId, replacement);
        return true;
    }

    public ValueTask<IReadOnlyDictionary<string, OwnedResourceState>> ReadKeyValuesAsync(
        string keyPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new Dictionary<string, OwnedResourceState>(StringComparer.Ordinal);
        foreach (var item in _states)
        {
            var id = RegistryPolicyValueId.Parse(item.Key);
            if (string.Equals(id.KeyPath, keyPath, StringComparison.Ordinal))
            {
                result[id.ValueName] = item.Value;
            }
        }

        return ValueTask.FromResult<IReadOnlyDictionary<string, OwnedResourceState>>(result);
    }

    public void Seed(string keyPath, string valueName, OwnedResourceState state)
    {
        Seed(new RegistryPolicyValueId(keyPath, valueName).ToString(), state);
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

    public OwnedResourceState Read(string keyPath, string valueName)
    {
        var id = new RegistryPolicyValueId(keyPath, valueName).ToString();
        return _states.TryGetValue(id, out var state) ? state : OwnedResourceState.Missing;
    }
}

internal sealed class FakeTaskSchedulerStore : ITaskSchedulerStore
{
    private readonly Dictionary<string, OwnedResourceState> _states = new(StringComparer.Ordinal);

    public int MutationCount { get; private set; }

    public List<string> Runs { get; } = [];

    public bool CheckAvailable(out string summary)
    {
        summary = "fake scheduler available";
        return true;
    }

    public ValueTask<OwnedResourceState> ReadAsync(string resourceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            _states.TryGetValue(resourceId, out var state) ? state : OwnedResourceState.Missing);
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return TaskStateCodec.Equivalent(left, right);
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(resourceId, cancellationToken);
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

internal sealed class FakeWfpNativeSessionFactory : IWfpNativeSessionFactory
{
    public WfpObjectMatch Provider { get; set; } = WfpObjectMatch.Missing;

    public WfpObjectMatch SubLayer { get; set; } = WfpObjectMatch.Missing;

    public Dictionary<Guid, WfpObjectMatch> Filters { get; } = [];

    public bool ThrowOnAddFilter { get; set; }

    public bool ThrowOnDeleteFilter { get; set; }

    public bool ThrowOnDeleteProvider { get; set; }

    public bool ThrowOnDeleteSubLayer { get; set; }

    public int AdditionalProductFilterReferences { get; set; }

    public int BeginCount { get; set; }

    public int CommitCount { get; set; }

    public int AbortCount { get; set; }

    public int DeleteCount { get; set; }

    public int DeleteProviderCount { get; set; }

    public int DeleteSubLayerCount { get; set; }

    public int CountFilterReferencesCount { get; set; }

    public List<string> InfrastructureDeletionOrder { get; } = [];

    public IWfpNativeSession Open()
    {
        return new FakeWfpNativeSession(this);
    }

    private sealed class FakeWfpNativeSession : IWfpNativeSession
    {
        private readonly FakeWfpNativeSessionFactory _owner;
        private WfpObjectMatch? _providerBeforeTransaction;
        private WfpObjectMatch? _subLayerBeforeTransaction;
        private Dictionary<Guid, WfpObjectMatch>? _filtersBeforeTransaction;

        public FakeWfpNativeSession(FakeWfpNativeSessionFactory owner)
        {
            _owner = owner;
        }

        public void BeginTransaction()
        {
            _owner.BeginCount++;
            _providerBeforeTransaction = _owner.Provider;
            _subLayerBeforeTransaction = _owner.SubLayer;
            _filtersBeforeTransaction = new Dictionary<Guid, WfpObjectMatch>(_owner.Filters);
        }

        public void CommitTransaction()
        {
            _owner.CommitCount++;
            ClearSnapshot();
        }

        public void AbortTransaction()
        {
            _owner.AbortCount++;
            if (_providerBeforeTransaction is not null
                && _subLayerBeforeTransaction is not null
                && _filtersBeforeTransaction is not null)
            {
                _owner.Provider = _providerBeforeTransaction.Value;
                _owner.SubLayer = _subLayerBeforeTransaction.Value;
                _owner.Filters.Clear();
                foreach (var item in _filtersBeforeTransaction)
                {
                    _owner.Filters[item.Key] = item.Value;
                }
            }

            ClearSnapshot();
        }

        public WfpObjectMatch InspectProvider() => _owner.Provider;

        public void AddProvider() => _owner.Provider = WfpObjectMatch.Matching;

        public void DeleteProvider()
        {
            if (_owner.ThrowOnDeleteProvider)
            {
                throw new InvalidOperationException("injected infrastructure delete failure");
            }

            _owner.DeleteProviderCount++;
            _owner.InfrastructureDeletionOrder.Add("provider");
            _owner.Provider = WfpObjectMatch.Missing;
        }

        public WfpObjectMatch InspectSubLayer() => _owner.SubLayer;

        public void AddSubLayer() => _owner.SubLayer = WfpObjectMatch.Matching;

        public void DeleteSubLayer()
        {
            if (_owner.ThrowOnDeleteSubLayer)
            {
                throw new InvalidOperationException("injected infrastructure delete failure");
            }

            _owner.DeleteSubLayerCount++;
            _owner.InfrastructureDeletionOrder.Add("sublayer");
            _owner.SubLayer = WfpObjectMatch.Missing;
        }

        public int CountFiltersReferencingProductObjects()
        {
            _owner.CountFilterReferencesCount++;
            return checked(_owner.Filters.Count + _owner.AdditionalProductFilterReferences);
        }

        public WfpObjectMatch InspectFilter(WfpFilterSpec spec)
        {
            return _owner.Filters.TryGetValue(spec.FilterKey, out var match) ? match : WfpObjectMatch.Missing;
        }

        public void AddFilter(WfpFilterSpec spec)
        {
            if (_owner.ThrowOnAddFilter)
            {
                throw new InvalidOperationException("injected add failure");
            }

            _owner.Filters[spec.FilterKey] = WfpObjectMatch.Matching;
        }

        public void DeleteFilter(Guid filterKey)
        {
            if (_owner.ThrowOnDeleteFilter)
            {
                throw new InvalidOperationException("injected delete failure");
            }

            _owner.DeleteCount++;
            _owner.Filters.Remove(filterKey);
        }

        public void Dispose()
        {
        }

        private void ClearSnapshot()
        {
            _providerBeforeTransaction = null;
            _subLayerBeforeTransaction = null;
            _filtersBeforeTransaction = null;
        }
    }
}

internal sealed class FakeWfpPolicyStore : IWfpPolicyStore
{
    private readonly Dictionary<Guid, WfpFilterSpec> _filters = [];

    public IReadOnlyCollection<WfpFilterSpec> Filters => _filters.Values;

    public bool ThrowOnReconcileAfterAdd { get; set; }

    public bool CheckAvailable(out string summary)
    {
        summary = "fake WFP available";
        return true;
    }

    public void EnsurePersistentFilters(IReadOnlyList<WfpFilterSpec> filters)
    {
        foreach (var filter in filters)
        {
            _filters[filter.FilterKey] = filter;
        }
    }

    public void ReconcilePersistentFilters(
        IReadOnlyList<WfpFilterSpec> filtersToAdd,
        IReadOnlyList<WfpFilterSpec> filtersToRemove)
    {
        var before = new Dictionary<Guid, WfpFilterSpec>(_filters);
        try
        {
            foreach (var filter in filtersToAdd)
            {
                _filters[filter.FilterKey] = filter;
            }

            if (ThrowOnReconcileAfterAdd)
            {
                throw new InvalidOperationException("injected reconcile failure");
            }

            foreach (var filter in filtersToRemove)
            {
                _filters.Remove(filter.FilterKey);
            }
        }
        catch
        {
            _filters.Clear();
            foreach (var filter in before)
            {
                _filters[filter.Key] = filter.Value;
            }

            throw;
        }
    }

    public bool VerifyPersistentFilters(IReadOnlyList<WfpFilterSpec> filters, out string summary)
    {
        var verified = filters.All(filter => _filters.ContainsKey(filter.FilterKey));
        summary = verified ? "verified" : "missing";
        return verified;
    }

    public void RestoreKnownFilters(IReadOnlyList<WfpFilterSpec> filters)
    {
        foreach (var filter in filters)
        {
            _filters.Remove(filter.FilterKey);
        }
    }
}

internal sealed class FixedAddressSource : IWindowsObservedAddressSource
{
    private readonly IPAddress[] _addresses;

    public FixedAddressSource(params string[] addresses)
    {
        _addresses = addresses.Select(IPAddress.Parse).ToArray();
    }

    public ValueTask<IReadOnlyCollection<IPAddress>> GetObservedAddressesAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlyCollection<IPAddress>>(_addresses);
    }
}

internal sealed class MutableAddressSource : IWindowsObservedAddressSource
{
    private IPAddress[] _addresses = [];

    public MutableAddressSource(params string[] addresses)
    {
        Set(addresses);
    }

    public void Set(params string[] addresses)
    {
        _addresses = addresses.Select(IPAddress.Parse).ToArray();
    }

    public ValueTask<IReadOnlyCollection<IPAddress>> GetObservedAddressesAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlyCollection<IPAddress>>(_addresses);
    }
}
