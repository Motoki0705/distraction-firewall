namespace DistractionFirewall.Enforcement.Windows.Wfp;

internal interface IWfpPolicyStore
{
    bool CheckAvailable(out string summary);

    void EnsurePersistentFilters(IReadOnlyList<WfpFilterSpec> filters);

    void ReconcilePersistentFilters(
        IReadOnlyList<WfpFilterSpec> filtersToAdd,
        IReadOnlyList<WfpFilterSpec> filtersToRemove);

    bool VerifyPersistentFilters(IReadOnlyList<WfpFilterSpec> filters, out string summary);

    void RestoreKnownFilters(IReadOnlyList<WfpFilterSpec> filters);
}

internal sealed class WfpPolicyStore : IWfpPolicyStore
{
    private readonly IWfpNativeSessionFactory _sessionFactory;

    public WfpPolicyStore(IWfpNativeSessionFactory sessionFactory)
    {
        _sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));
    }

    public bool CheckAvailable(out string summary)
    {
        try
        {
            using var session = _sessionFactory.Open();
            summary = "WFP Base Filtering Engine management session is available.";
            return true;
        }
        catch (Exception exception) when (exception is WfpException or PlatformNotSupportedException)
        {
            summary = exception.Message;
            return false;
        }
    }

    public void EnsurePersistentFilters(IReadOnlyList<WfpFilterSpec> filters)
    {
        ArgumentNullException.ThrowIfNull(filters);
        using var session = _sessionFactory.Open();
        ExecuteTransaction(
            session,
            () =>
            {
                EnsureProvider(session);
                EnsureSubLayer(session);
                foreach (var filter in filters)
                {
                    switch (session.InspectFilter(filter))
                    {
                        case WfpObjectMatch.Missing:
                            session.AddFilter(filter);
                            break;
                        case WfpObjectMatch.Matching:
                            break;
                        case WfpObjectMatch.Foreign:
                            throw new InvalidOperationException(
                                $"WFP filter GUID {filter.FilterKey:D} is occupied by a foreign or altered object.");
                        default:
                            throw new InvalidOperationException("Unknown WFP filter inspection result.");
                    }
                }
            });
    }

    public void ReconcilePersistentFilters(
        IReadOnlyList<WfpFilterSpec> filtersToAdd,
        IReadOnlyList<WfpFilterSpec> filtersToRemove)
    {
        ArgumentNullException.ThrowIfNull(filtersToAdd);
        ArgumentNullException.ThrowIfNull(filtersToRemove);
        var additions = filtersToAdd.ToArray();
        var removals = filtersToRemove.ToArray();
        var duplicateAddition = additions
            .GroupBy(filter => filter.FilterKey)
            .FirstOrDefault(group => group.Count() > 1);
        var duplicateRemoval = removals
            .GroupBy(filter => filter.FilterKey)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateAddition is not null || duplicateRemoval is not null)
        {
            throw new ArgumentException("WFP reconciliation contains a duplicate filter key.");
        }

        var removalKeys = removals.Select(filter => filter.FilterKey).ToHashSet();
        if (additions.Any(filter => removalKeys.Contains(filter.FilterKey)))
        {
            throw new ArgumentException("A WFP filter cannot be added and removed in the same reconciliation.");
        }

        using var session = _sessionFactory.Open();
        ExecuteTransaction(
            session,
            () =>
            {
                EnsureProvider(session);
                EnsureSubLayer(session);

                var additionsToCreate = new List<WfpFilterSpec>(additions.Length);
                foreach (var filter in additions)
                {
                    switch (session.InspectFilter(filter))
                    {
                        case WfpObjectMatch.Missing:
                            additionsToCreate.Add(filter);
                            break;
                        case WfpObjectMatch.Matching:
                            break;
                        case WfpObjectMatch.Foreign:
                            throw new InvalidOperationException(
                                $"WFP filter GUID {filter.FilterKey:D} is occupied by a foreign or altered object.");
                        default:
                            throw new InvalidOperationException("Unknown WFP filter inspection result.");
                    }
                }

                var removalsToDelete = new List<WfpFilterSpec>(removals.Length);
                foreach (var filter in removals)
                {
                    switch (session.InspectFilter(filter))
                    {
                        case WfpObjectMatch.Missing:
                            break;
                        case WfpObjectMatch.Matching:
                            removalsToDelete.Add(filter);
                            break;
                        case WfpObjectMatch.Foreign:
                            throw new InvalidOperationException(
                                $"Refusing to delete altered or foreign WFP filter {filter.FilterKey:D}.");
                        default:
                            throw new InvalidOperationException("Unknown WFP filter inspection result.");
                    }
                }

                foreach (var filter in additionsToCreate)
                {
                    session.AddFilter(filter);
                }

                foreach (var filter in removalsToDelete)
                {
                    session.DeleteFilter(filter.FilterKey);
                }
            });
    }

    public bool VerifyPersistentFilters(IReadOnlyList<WfpFilterSpec> filters, out string summary)
    {
        ArgumentNullException.ThrowIfNull(filters);
        using var session = _sessionFactory.Open();
        if (session.InspectProvider() != WfpObjectMatch.Matching
            || session.InspectSubLayer() != WfpObjectMatch.Matching)
        {
            summary = "The persistent WFP provider or sublayer is absent or has foreign ownership metadata.";
            return false;
        }

        foreach (var filter in filters)
        {
            if (session.InspectFilter(filter) != WfpObjectMatch.Matching)
            {
                summary = $"WFP filter {filter.FilterKey:D} is absent or altered.";
                return false;
            }
        }

        summary = $"Verified {filters.Count} persistent exact-address WFP filters.";
        return true;
    }

    public void RestoreKnownFilters(IReadOnlyList<WfpFilterSpec> filters)
    {
        ArgumentNullException.ThrowIfNull(filters);
        using var session = _sessionFactory.Open();
        ExecuteTransaction(
            session,
            () =>
            {
                foreach (var filter in filters)
                {
                    var inspection = session.InspectFilter(filter);
                    if (inspection == WfpObjectMatch.Foreign)
                    {
                        throw new InvalidOperationException(
                            $"Refusing to delete altered or foreign WFP filter {filter.FilterKey:D}.");
                    }
                }

                foreach (var filter in filters)
                {
                    if (session.InspectFilter(filter) == WfpObjectMatch.Matching)
                    {
                        session.DeleteFilter(filter.FilterKey);
                    }
                }
            });
    }

    internal void ValidatePersistentInfrastructureCanBeRemoved()
    {
        using var session = _sessionFactory.Open();
        ExecuteTransaction(session, () => ValidatePersistentInfrastructureCanBeRemoved(session));
    }

    internal void RemovePersistentInfrastructure()
    {
        using var session = _sessionFactory.Open();
        ExecuteTransaction(
            session,
            () =>
            {
                ValidatePersistentInfrastructureCanBeRemoved(session);
                if (session.InspectSubLayer() == WfpObjectMatch.Matching)
                {
                    session.DeleteSubLayer();
                }

                if (session.InspectProvider() == WfpObjectMatch.Matching)
                {
                    session.DeleteProvider();
                }

                if (session.InspectSubLayer() != WfpObjectMatch.Missing
                    || session.InspectProvider() != WfpObjectMatch.Missing)
                {
                    throw new InvalidOperationException(
                        "WFP provider or sublayer remained after installation cleanup.");
                }
            });
    }

    private static void EnsureProvider(IWfpNativeSession session)
    {
        switch (session.InspectProvider())
        {
            case WfpObjectMatch.Missing:
                session.AddProvider();
                break;
            case WfpObjectMatch.Matching:
                break;
            case WfpObjectMatch.Foreign:
                throw new InvalidOperationException("The product WFP provider GUID is occupied by a foreign object.");
            default:
                throw new InvalidOperationException("Unknown WFP provider inspection result.");
        }
    }

    private static void ValidatePersistentInfrastructureCanBeRemoved(IWfpNativeSession session)
    {
        var provider = session.InspectProvider();
        var subLayer = session.InspectSubLayer();
        if (provider == WfpObjectMatch.Foreign || subLayer == WfpObjectMatch.Foreign)
        {
            throw new InvalidOperationException(
                "WFP installation cleanup refused foreign or altered provider/sublayer metadata.");
        }

        var filters = session.CountFiltersReferencingProductObjects();
        if (filters != 0)
        {
            throw new InvalidOperationException(
                $"WFP installation cleanup requires zero filters referencing product objects; found {filters}.");
        }
    }

    private static void EnsureSubLayer(IWfpNativeSession session)
    {
        switch (session.InspectSubLayer())
        {
            case WfpObjectMatch.Missing:
                session.AddSubLayer();
                break;
            case WfpObjectMatch.Matching:
                break;
            case WfpObjectMatch.Foreign:
                throw new InvalidOperationException("The product WFP sublayer GUID is occupied by a foreign object.");
            default:
                throw new InvalidOperationException("Unknown WFP sublayer inspection result.");
        }
    }

    private static void ExecuteTransaction(IWfpNativeSession session, Action action)
    {
        session.BeginTransaction();
        var transactionActive = true;
        try
        {
            action();
            session.CommitTransaction();
            transactionActive = false;
        }
        catch
        {
            if (transactionActive)
            {
                try
                {
                    session.AbortTransaction();
                }
                catch (Exception abortException)
                {
                    System.Diagnostics.Trace.TraceError(
                        "WFP transaction abort also failed: {0}",
                        abortException.Message);
                }
            }

            throw;
        }
    }
}
