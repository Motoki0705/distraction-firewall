using System.Reflection;
using System.Windows.Input;
using DistractionFirewall.App.Services;
using DistractionFirewall.App.ViewModels;
using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace DistractionFirewall.UiTests;

public sealed class MainViewModelTests
{
    [Fact]
    public async Task Initialize_projects_the_runtime_target_collection_for_rendering()
    {
        var client = new FakeActivationClient
        {
            CatalogResponse = new GetTargetCatalogResponse(
                ProtocolConstants.CurrentVersion,
                [
                    CreateDescriptor("video", "Video service", "Video coverage"),
                    CreateDescriptor("social", "Social service", "Social coverage"),
                ]),
        };
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);

        Assert.True(viewModel.IsSetupPage);
        Assert.Collection(
            viewModel.Targets,
            target =>
            {
                Assert.Equal("video", target.Target.StableId);
                Assert.Equal("Video service", target.Target.DisplayName);
                Assert.Equal("Video coverage", target.Target.Description);
                Assert.False(target.IsSelected);
            },
            target =>
            {
                Assert.Equal("social", target.Target.StableId);
                Assert.Equal("Social service", target.Target.DisplayName);
                Assert.Equal("Social coverage", target.Target.Description);
                Assert.False(target.IsSelected);
            });
        Assert.False(viewModel.PrepareCommand.CanExecute(null));
    }

    [Theory]
    [InlineData("1", 1)]
    [InlineData("720", 720)]
    public async Task Custom_duration_accepts_one_and_seven_hundred_twenty_minute_boundaries(
        string text,
        int expectedMinutes)
    {
        var client = new FakeActivationClient();
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);
        SelectFirstTargetAndCustomDuration(viewModel, text);

        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() => viewModel.IsConfirmationPage).ConfigureAwait(true);

        var request = Assert.Single(client.PrepareRequests);
        Assert.Equal(LeaseEndMode.Duration, request.End.Mode);
        Assert.Equal(expectedMinutes, request.End.DurationMinutes);
        Assert.Null(request.End.UntilUtc);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("721")]
    [InlineData("not-a-number")]
    public async Task Custom_duration_rejects_invalid_values_without_calling_runtime(string text)
    {
        var client = new FakeActivationClient();
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);
        SelectFirstTargetAndCustomDuration(viewModel, text);

        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() =>
            viewModel.ErrorMessage.Length > 0 && viewModel.PrepareCommand.CanExecute(null)).ConfigureAwait(true);

        Assert.Empty(client.PrepareRequests);
        Assert.True(viewModel.IsSetupPage);
    }

    [Fact]
    public async Task Until_mode_sends_local_wall_time_zone_and_resolved_utc_deadline()
    {
        var client = new FakeActivationClient();
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);
        var date = DateTime.Today.AddDays(2);
        var local = DateTime.SpecifyKind(date.Date.AddHours(12).AddMinutes(34), DateTimeKind.Unspecified);
        var expectedUtc = new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local)).ToUniversalTime();
        viewModel.Targets[0].IsSelected = true;
        viewModel.UseUntil = true;
        viewModel.UntilDate = date;
        viewModel.UntilTime = "12:34";

        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() => viewModel.IsConfirmationPage).ConfigureAwait(true);

        var end = Assert.Single(client.PrepareRequests).End;
        Assert.Equal(LeaseEndMode.Until, end.Mode);
        Assert.Null(end.DurationMinutes);
        Assert.Equal(expectedUtc, end.UntilUtc);
        Assert.Equal(TimeZoneInfo.Local.Id, end.InputTimeZoneId);
        Assert.Equal(local, end.InputLocalTime);
        Assert.Equal(DateTimeKind.Unspecified, end.InputLocalTime?.Kind);
    }

    [Fact]
    public async Task Until_mode_rejects_a_nonexistent_dst_wall_time()
    {
        using var localZone = new LocalTimeZoneScope(CreateQaDstZone());
        var client = new FakeActivationClient();
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);
        viewModel.Targets[0].IsSelected = true;
        viewModel.UseUntil = true;
        viewModel.UntilDate = new DateTime(2030, 3, 8);
        viewModel.UntilTime = "02:30";

        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() =>
            viewModel.ErrorMessage.Length > 0 && viewModel.PrepareCommand.CanExecute(null)).ConfigureAwait(true);

        Assert.Contains("存在しません", viewModel.ErrorMessage, StringComparison.Ordinal);
        Assert.Empty(client.PrepareRequests);
        Assert.True(viewModel.IsSetupPage);
    }

    [Fact]
    public async Task Until_mode_requires_an_offset_for_ambiguous_dst_time_then_submits_the_choice()
    {
        using var localZone = new LocalTimeZoneScope(CreateQaDstZone());
        var client = new FakeActivationClient();
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);
        var local = new DateTime(2030, 11, 1, 1, 30, 0, DateTimeKind.Unspecified);
        viewModel.Targets[0].IsSelected = true;
        viewModel.UseUntil = true;
        viewModel.UntilDate = local.Date;
        viewModel.UntilTime = "01:30";

        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() =>
            viewModel.ErrorMessage.Length > 0 && viewModel.PrepareCommand.CanExecute(null)).ConfigureAwait(true);

        Assert.Contains("2回存在", viewModel.ErrorMessage, StringComparison.Ordinal);
        Assert.True(viewModel.HasAmbiguousOffsets);
        Assert.Equal(2, viewModel.AmbiguousOffsets.Count);
        Assert.Empty(client.PrepareRequests);

        var selectedOffset = viewModel.AmbiguousOffsets[0];
        viewModel.SelectedAmbiguousOffset = selectedOffset;
        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() => viewModel.IsConfirmationPage).ConfigureAwait(true);

        var end = Assert.Single(client.PrepareRequests).End;
        Assert.Equal(new DateTimeOffset(local, selectedOffset.Offset).ToUniversalTime(), end.UntilUtc);
        Assert.Equal("QA-DST-Zone", end.InputTimeZoneId);
    }

    [Fact]
    public async Task Prepare_confirmation_acknowledgement_commit_transitions_to_active()
    {
        var preparationId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var leaseId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var target = CreateSnapshot("youtube", "YouTube");
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
        var client = new FakeActivationClient
        {
            PrepareResponse = new PrepareLeaseResponse(
                ProtocolConstants.CurrentVersion,
                preparationId,
                "qa-nonce",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddMinutes(5),
                expiresAt,
                TimeSpan.FromHours(1),
                [target],
                "sha256:qa-rule",
                [new LeaseWarning("collateral", "May affect related media hosts.")]),
            CommitResponse = new CommitLeaseResponse(
                ProtocolConstants.CurrentVersion,
                leaseId,
                LeaseState.Active,
                DateTimeOffset.UtcNow,
                expiresAt,
                [target],
                LeaseHealth.Healthy),
        };
        using var viewModel = await CreateInitializedViewModelAsync(client).ConfigureAwait(true);
        viewModel.Targets[0].IsSelected = true;

        viewModel.PrepareCommand.Execute(null);
        await WaitUntilAsync(() => viewModel.IsConfirmationPage).ConfigureAwait(true);

        Assert.Equal("YouTube", viewModel.ConfirmationTargets);
        Assert.Single(viewModel.PreparationWarnings);
        Assert.False(viewModel.CommitCommand.CanExecute(null));
        viewModel.CommitCommand.Execute(null);
        Assert.Empty(client.CommitRequests);

        viewModel.Acknowledged = true;
        Assert.True(viewModel.CommitCommand.CanExecute(null));
        viewModel.CommitCommand.Execute(null);
        await WaitUntilAsync(() => viewModel.IsActivePage).ConfigureAwait(true);

        var commit = Assert.Single(client.CommitRequests);
        Assert.Equal(preparationId, commit.PreparationId);
        Assert.Equal("qa-nonce", commit.Nonce);
        Assert.Equal(leaseId.ToString("D"), viewModel.ActiveLeaseId);
        Assert.Equal("YouTube", viewModel.ActiveTargets);
        Assert.Equal("YouTubeを制限中", viewModel.ActiveHeading);
        Assert.Equal(LeaseHealth.Healthy, viewModel.ActiveHealth);
        Assert.False(viewModel.IsConfirmationPage);
    }

    [Fact]
    public async Task Runtime_connection_failure_displays_unavailable_without_assuming_idle()
    {
        var client = new FakeActivationClient
        {
            StatusException = new RpcClientException(
                LeaseErrorCode.BackendUnavailable,
                "qa runtime unavailable",
                retryable: true),
        };
        using var viewModel = new MainViewModel(client);

        await viewModel.InitializeAsync().ConfigureAwait(true);

        Assert.True(viewModel.IsUnavailablePage);
        Assert.False(viewModel.IsSetupPage);
        Assert.Contains("Lease Runtimeへ接続できません", viewModel.ErrorMessage, StringComparison.Ordinal);
        Assert.Contains("qa runtime unavailable", viewModel.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(0, client.TargetCatalogCallCount);
    }

    [Fact]
    public async Task Initialize_restores_an_active_lease_without_loading_setup_catalog()
    {
        var leaseId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var expiresAt = DateTimeOffset.UtcNow.AddHours(2);
        var client = new FakeActivationClient
        {
            StatusResponse = new LeaseStatusResponse(
                ProtocolConstants.CurrentVersion,
                LeaseState.Active,
                leaseId,
                DateTimeOffset.UtcNow.AddMinutes(-5),
                expiresAt,
                [CreateSnapshot("news", "News")],
                LeaseHealth.Degraded,
                AppInstallState.Removed,
                RuntimeInstallIntent.Keep,
                RuntimeInstallState.Installed,
                Sequence: 9),
        };
        using var viewModel = new MainViewModel(client);

        await viewModel.InitializeAsync().ConfigureAwait(true);

        Assert.True(viewModel.IsActivePage);
        Assert.Equal(leaseId.ToString("D"), viewModel.ActiveLeaseId);
        Assert.Equal("News", viewModel.ActiveTargets);
        Assert.Equal("Newsを制限中", viewModel.ActiveHeading);
        Assert.Equal(LeaseHealth.Degraded, viewModel.ActiveHealth);
        Assert.NotEmpty(viewModel.RemainingText);
        Assert.Equal(0, client.TargetCatalogCallCount);
    }

    [Fact]
    public void Public_ui_and_activation_client_expose_no_cancel_shorten_extend_or_change_operation()
    {
        var commandNames = typeof(MainViewModel)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(property => typeof(ICommand).IsAssignableFrom(property.PropertyType))
            .Select(property => property.Name);
        var publicPropertyNames = typeof(MainViewModel)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Select(property => property.Name);
        var activationOperationNames = typeof(IActivationClient)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Select(method => method.Name);
        var exposedNames = commandNames
            .Concat(publicPropertyNames)
            .Concat(activationOperationNames)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var forbidden = new[] { "cancel", "shorten", "extend", "change" };

        var violations = exposedNames
            .Where(name => forbidden.Any(term => name.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        Assert.Empty(violations);
    }

    private static async Task<MainViewModel> CreateInitializedViewModelAsync(FakeActivationClient client)
    {
        var viewModel = new MainViewModel(client);
        await viewModel.InitializeAsync().ConfigureAwait(true);
        return viewModel;
    }

    private static void SelectFirstTargetAndCustomDuration(MainViewModel viewModel, string minutes)
    {
        viewModel.Targets[0].IsSelected = true;
        viewModel.SelectedDuration = viewModel.DurationChoices.Single(choice => choice.Minutes is null);
        viewModel.CustomMinutes = minutes;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline)
            {
                throw new TimeoutException("The asynchronous ViewModel command did not reach its expected state.");
            }

            await Task.Delay(10).ConfigureAwait(true);
        }
    }

    private static TimeZoneInfo CreateQaDstZone()
    {
        var daylightStart = TimeZoneInfo.TransitionTime.CreateFixedDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            month: 3,
            day: 8);
        var daylightEnd = TimeZoneInfo.TransitionTime.CreateFixedDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            month: 11,
            day: 1);
        var rule = TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(
            new DateTime(2020, 1, 1),
            new DateTime(2099, 12, 31),
            TimeSpan.FromHours(1),
            daylightStart,
            daylightEnd);
        return TimeZoneInfo.CreateCustomTimeZone(
            "QA-DST-Zone",
            TimeSpan.FromHours(-5),
            "QA DST Zone",
            "QA Standard Time",
            "QA Daylight Time",
            [rule]);
    }

    private static TargetDescriptor CreateDescriptor(string stableId, string displayName, string description) => new(
        stableId,
        displayName,
        description,
        "1.0.0",
        ["Browser", "DNS"],
        ["Related media hosts"]);

    private static TargetSnapshotDto CreateSnapshot(string stableId, string displayName) => new(
        stableId,
        displayName,
        "1.0.0",
        "sha256:qa-target");

    private static LeaseStatusResponse CreateIdleStatus() => new(
        ProtocolConstants.CurrentVersion,
        LeaseState.Idle,
        LeaseId: null,
        ActivatedAtUtc: null,
        ExpiresAtUtc: null,
        Targets: [],
        LeaseHealth.Unknown,
        AppInstallState.Installed,
        RuntimeInstallIntent.Keep,
        RuntimeInstallState.Installed,
        Sequence: 0);

    private sealed class FakeActivationClient : IActivationClient
    {
        public GetTargetCatalogResponse CatalogResponse { get; set; } = new(
            ProtocolConstants.CurrentVersion,
            [CreateDescriptor("youtube", "YouTube", "YouTube and related media endpoints")]);

        public LeaseStatusResponse StatusResponse { get; set; } = CreateIdleStatus();

        public Exception? StatusException { get; set; }

        public PrepareLeaseResponse? PrepareResponse { get; set; }

        public CommitLeaseResponse? CommitResponse { get; set; }

        public int TargetCatalogCallCount { get; private set; }

        public List<PrepareLeaseRequest> PrepareRequests { get; } = [];

        public List<CommitLeaseRequest> CommitRequests { get; } = [];

        public Task<GetTargetCatalogResponse> GetTargetsAsync(CancellationToken cancellationToken)
        {
            TargetCatalogCallCount++;
            return Task.FromResult(CatalogResponse);
        }

        public Task<LeaseStatusResponse> GetStatusAsync(CancellationToken cancellationToken) =>
            StatusException is null
                ? Task.FromResult(StatusResponse)
                : Task.FromException<LeaseStatusResponse>(StatusException);

        public Task<PrepareLeaseResponse> PrepareAsync(
            PrepareLeaseRequest request,
            CancellationToken cancellationToken)
        {
            PrepareRequests.Add(request);
            if (PrepareResponse is not null)
            {
                return Task.FromResult(PrepareResponse);
            }

            var now = DateTimeOffset.UtcNow;
            var expiresAt = request.End.UntilUtc
                ?? now.AddMinutes(request.End.DurationMinutes ?? 60);
            var targets = CatalogResponse.Targets
                .Where(target => request.TargetIds.Contains(target.StableId, StringComparer.Ordinal))
                .Select(target => CreateSnapshot(target.StableId, target.DisplayName))
                .ToArray();
            return Task.FromResult(new PrepareLeaseResponse(
                ProtocolConstants.CurrentVersion,
                Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                "default-qa-nonce",
                now,
                now.AddMinutes(5),
                expiresAt,
                expiresAt - now,
                targets,
                "sha256:default-qa-rule",
                Warnings: []));
        }

        public Task<CommitLeaseResponse> CommitAsync(
            CommitLeaseRequest request,
            CancellationToken cancellationToken)
        {
            CommitRequests.Add(request);
            return Task.FromResult(CommitResponse ?? new CommitLeaseResponse(
                ProtocolConstants.CurrentVersion,
                Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                LeaseState.Active,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddHours(1),
                [CreateSnapshot("youtube", "YouTube")],
                LeaseHealth.Healthy));
        }

        public Task<DiagnosticsResponse> GetDiagnosticsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new DiagnosticsResponse(
                ProtocolConstants.CurrentVersion,
                DateTimeOffset.UtcNow,
                Checks: []));
    }

    private sealed class LocalTimeZoneScope : IDisposable
    {
        public LocalTimeZoneScope(TimeZoneInfo localTimeZone)
        {
            var cachedDataField = typeof(TimeZoneInfo).GetField(
                "s_cachedData",
                BindingFlags.Static | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("TimeZoneInfo cached data field was not found.");
            var cachedData = cachedDataField.GetValue(null)
                ?? throw new InvalidOperationException("TimeZoneInfo cached data was null.");
            var localTimeZoneField = cachedData.GetType().GetField(
                "_localTimeZone",
                BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("TimeZoneInfo local cache field was not found.");
            localTimeZoneField.SetValue(cachedData, localTimeZone);
            if (!ReferenceEquals(TimeZoneInfo.Local, localTimeZone))
            {
                throw new InvalidOperationException("The QA local time zone could not be installed in the process cache.");
            }
        }

        public void Dispose()
        {
            TimeZoneInfo.ClearCachedData();
        }
    }
}
