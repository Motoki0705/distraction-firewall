using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Threading;
using DistractionFirewall.App.Services;
using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.App.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly IActivationClient _client;
    private readonly DispatcherTimer _countdownTimer;
    private AppPage _currentPage = AppPage.Loading;
    private bool _useDuration = true;
    private DurationChoice? _selectedDuration;
    private string _customMinutes = "60";
    private DateTime? _untilDate = DateTime.Today;
    private string _untilTime = "18:00";
    private OffsetChoice? _selectedAmbiguousOffset;
    private bool _acknowledged;
    private string _errorMessage = string.Empty;
    private string _diagnosticSummary = string.Empty;
    private PrepareLeaseResponse? _prepared;
    private Guid? _activeLeaseId;
    private DateTimeOffset? _activeExpiresAtUtc;
    private LeaseHealth _activeHealth;
    private string _activeTargets = string.Empty;
    private string _remainingText = string.Empty;
    private bool _disposed;

    public MainViewModel(IActivationClient client)
    {
        _client = client;
        DurationChoices =
        [
            new("15分", 15),
            new("30分", 30),
            new("1時間", 60),
            new("2時間", 120),
            new("4時間", 240),
            new("8時間", 480),
            new("12時間", 720),
            new("任意の分数", null),
        ];
        _selectedDuration = DurationChoices[2];
        PrepareCommand = new AsyncCommand(PrepareAsync, CanPrepare, ShowError);
        CommitCommand = new AsyncCommand(CommitAsync, () => Acknowledged && _prepared is not null, ShowError);
        BackCommand = new RelayCommand(BackToSetup);
        RetryCommand = new AsyncCommand(InitializeAsync, onError: ShowError);
        DiagnoseCommand = new AsyncCommand(DiagnoseAsync, onError: ShowError);

        _countdownTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(30),
        };
        _countdownTimer.Tick += CountdownTimerOnTick;
    }

    public ObservableCollection<TargetChoiceViewModel> Targets { get; } = [];

    public IReadOnlyList<DurationChoice> DurationChoices { get; }

    public ObservableCollection<OffsetChoice> AmbiguousOffsets { get; } = [];

    public ObservableCollection<LeaseWarning> PreparationWarnings { get; } = [];

    public AsyncCommand PrepareCommand { get; }

    public AsyncCommand CommitCommand { get; }

    public RelayCommand BackCommand { get; }

    public AsyncCommand RetryCommand { get; }

    public AsyncCommand DiagnoseCommand { get; }

    public bool IsLoadingPage => CurrentPage == AppPage.Loading;

    public bool IsSetupPage => CurrentPage == AppPage.Setup;

    public bool IsConfirmationPage => CurrentPage == AppPage.Confirmation;

    public bool IsActivePage => CurrentPage == AppPage.Active;

    public bool IsUnavailablePage => CurrentPage == AppPage.Unavailable;

    public bool UseDuration
    {
        get => _useDuration;
        set
        {
            if (SetProperty(ref _useDuration, value))
            {
                OnPropertyChanged(nameof(UseUntil));
                PrepareCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool UseUntil
    {
        get => !UseDuration;
        set
        {
            if (value)
            {
                UseDuration = false;
            }
        }
    }

    public DurationChoice? SelectedDuration
    {
        get => _selectedDuration;
        set
        {
            if (SetProperty(ref _selectedDuration, value))
            {
                OnPropertyChanged(nameof(IsCustomDuration));
                PrepareCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsCustomDuration => SelectedDuration?.Minutes is null;

    public string CustomMinutes
    {
        get => _customMinutes;
        set
        {
            if (SetProperty(ref _customMinutes, value))
            {
                PrepareCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public DateTime? UntilDate
    {
        get => _untilDate;
        set => SetProperty(ref _untilDate, value);
    }

    public string UntilTime
    {
        get => _untilTime;
        set => SetProperty(ref _untilTime, value);
    }

    public OffsetChoice? SelectedAmbiguousOffset
    {
        get => _selectedAmbiguousOffset;
        set => SetProperty(ref _selectedAmbiguousOffset, value);
    }

    public bool HasAmbiguousOffsets => AmbiguousOffsets.Count > 0;

    public bool Acknowledged
    {
        get => _acknowledged;
        set
        {
            if (SetProperty(ref _acknowledged, value))
            {
                CommitCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public string DiagnosticSummary
    {
        get => _diagnosticSummary;
        private set => SetProperty(ref _diagnosticSummary, value);
    }

    public string ConfirmationTargets => _prepared is null
        ? string.Empty
        : string.Join(", ", _prepared.Targets.Select(target => target.DisplayName));

    public string ConfirmationDeadline => _prepared is null
        ? string.Empty
        : _prepared.ResolvedExpiresAtUtc.ToLocalTime().ToString("yyyy年M月d日 HH:mm zzz", CultureInfo.CurrentCulture);

    public string ActiveTargets
    {
        get => _activeTargets;
        private set
        {
            if (SetProperty(ref _activeTargets, value))
            {
                OnPropertyChanged(nameof(ActiveHeading));
            }
        }
    }

    public string ActiveHeading => string.IsNullOrWhiteSpace(ActiveTargets)
        ? "対象を制限中"
        : $"{ActiveTargets}を制限中";

    public string ActiveDeadline => _activeExpiresAtUtc?.ToLocalTime()
        .ToString("yyyy年M月d日 HH:mm zzz", CultureInfo.CurrentCulture) ?? string.Empty;

    public string ActiveLeaseId => _activeLeaseId?.ToString("D", CultureInfo.InvariantCulture) ?? string.Empty;

    public LeaseHealth ActiveHealth
    {
        get => _activeHealth;
        private set => SetProperty(ref _activeHealth, value);
    }

    public string RemainingText
    {
        get => _remainingText;
        private set => SetProperty(ref _remainingText, value);
    }

    private AppPage CurrentPage
    {
        get => _currentPage;
        set
        {
            if (!SetProperty(ref _currentPage, value))
            {
                return;
            }

            OnPropertyChanged(nameof(IsLoadingPage));
            OnPropertyChanged(nameof(IsSetupPage));
            OnPropertyChanged(nameof(IsConfirmationPage));
            OnPropertyChanged(nameof(IsActivePage));
            OnPropertyChanged(nameof(IsUnavailablePage));
        }
    }

    public async Task InitializeAsync()
    {
        ErrorMessage = string.Empty;
        CurrentPage = AppPage.Loading;
        try
        {
            var status = await _client.GetStatusAsync(CancellationToken.None).ConfigureAwait(true);
            if (status.State is LeaseState.Active or LeaseState.Releasing)
            {
                ShowActive(status);
                return;
            }

            var catalog = await _client.GetTargetsAsync(CancellationToken.None).ConfigureAwait(true);
            Targets.Clear();
            foreach (var target in catalog.Targets)
            {
                Targets.Add(new TargetChoiceViewModel(target, OnTargetSelectionChanged));
            }

            CurrentPage = AppPage.Setup;
            PrepareCommand.RaiseCanExecuteChanged();
        }
        catch (Exception exception)
        {
            ShowError(exception);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _countdownTimer.Stop();
        _countdownTimer.Tick -= CountdownTimerOnTick;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private bool CanPrepare() => Targets.Any(target => target.IsSelected);

    private async Task PrepareAsync()
    {
        ErrorMessage = string.Empty;
        var selectedTargets = Targets
            .Where(target => target.IsSelected)
            .Select(target => target.Target.StableId)
            .ToArray();
        var end = BuildEndRequest();
        var request = new PrepareLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            selectedTargets,
            end);
        _prepared = await _client.PrepareAsync(request, CancellationToken.None).ConfigureAwait(true);
        Acknowledged = false;
        PreparationWarnings.Clear();
        foreach (var warning in _prepared.Warnings)
        {
            PreparationWarnings.Add(warning);
        }

        OnPropertyChanged(nameof(ConfirmationTargets));
        OnPropertyChanged(nameof(ConfirmationDeadline));
        CurrentPage = AppPage.Confirmation;
        CommitCommand.RaiseCanExecuteChanged();
    }

    private async Task CommitAsync()
    {
        if (_prepared is null || !Acknowledged)
        {
            return;
        }

        ErrorMessage = string.Empty;
        var request = new CommitLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            _prepared.PreparationId,
            _prepared.Nonce);
        var active = await _client.CommitAsync(request, CancellationToken.None).ConfigureAwait(true);
        ShowActive(new LeaseStatusResponse(
            active.ProtocolVersion,
            active.State,
            active.LeaseId,
            active.ActivatedAtUtc,
            active.ExpiresAtUtc,
            active.Targets,
            active.Health,
            AppInstallState.Installed,
            RuntimeInstallIntent.Keep,
            RuntimeInstallState.Installed,
            Sequence: 0));
    }

    private async Task DiagnoseAsync()
    {
        var response = await _client.GetDiagnosticsAsync(CancellationToken.None).ConfigureAwait(true);
        DiagnosticSummary = string.Join(
            Environment.NewLine,
            response.Checks.Select(check => $"{(check.IsHealthy ? "OK" : "要確認")}: {check.DisplayName} — {check.Summary}"));
    }

    private LeaseEndRequest BuildEndRequest()
    {
        if (UseDuration)
        {
            int minutes;
            if (SelectedDuration?.Minutes is int presetMinutes)
            {
                minutes = presetMinutes;
            }
            else if (!int.TryParse(CustomMinutes, NumberStyles.None, CultureInfo.CurrentCulture, out minutes))
            {
                throw new FormatException("任意の分数には1〜720の整数を入力してください。");
            }

            if (minutes is < 1 or > 720)
            {
                throw new FormatException("期間は1分以上、12時間以下にしてください。");
            }

            return new LeaseEndRequest(LeaseEndMode.Duration, minutes, null);
        }

        if (UntilDate is null ||
            !TimeSpan.TryParseExact(UntilTime, @"hh\:mm", CultureInfo.InvariantCulture, out var time))
        {
            throw new FormatException("終了日と24時間表記の時刻（HH:mm）を入力してください。");
        }

        var local = DateTime.SpecifyKind(UntilDate.Value.Date + time, DateTimeKind.Unspecified);
        var zone = TimeZoneInfo.Local;
        if (zone.IsInvalidTime(local))
        {
            throw new FormatException("この時刻は夏時間の切替で存在しません。別の時刻を選んでください。");
        }

        TimeSpan offset;
        if (zone.IsAmbiguousTime(local))
        {
            var offsets = zone.GetAmbiguousTimeOffsets(local).Order().ToArray();
            if (AmbiguousOffsets.Count == 0)
            {
                foreach (var candidate in offsets)
                {
                    var sign = candidate < TimeSpan.Zero ? "-" : "+";
                    AmbiguousOffsets.Add(new OffsetChoice(
                        "UTC" + sign + candidate.Duration().ToString(@"hh\:mm", CultureInfo.InvariantCulture),
                        candidate));
                }

                OnPropertyChanged(nameof(HasAmbiguousOffsets));
            }

            offset = SelectedAmbiguousOffset?.Offset
                ?? throw new FormatException("この時刻は2回存在します。UTC offsetを選んでください。");
        }
        else
        {
            AmbiguousOffsets.Clear();
            SelectedAmbiguousOffset = null;
            OnPropertyChanged(nameof(HasAmbiguousOffsets));
            offset = zone.GetUtcOffset(local);
        }

        var until = new DateTimeOffset(local, offset).ToUniversalTime();
        return new LeaseEndRequest(LeaseEndMode.Until, null, until, zone.Id, local);
    }

    private void ShowActive(LeaseStatusResponse status)
    {
        _prepared = null;
        _activeLeaseId = status.LeaseId;
        _activeExpiresAtUtc = status.ExpiresAtUtc;
        ActiveTargets = string.Join(", ", status.Targets.Select(target => target.DisplayName));
        ActiveHealth = status.Health;
        OnPropertyChanged(nameof(ActiveDeadline));
        OnPropertyChanged(nameof(ActiveLeaseId));
        UpdateRemaining();
        CurrentPage = AppPage.Active;
        _countdownTimer.Start();
    }

    private void BackToSetup()
    {
        _prepared = null;
        Acknowledged = false;
        CurrentPage = AppPage.Setup;
    }

    private void OnTargetSelectionChanged() => PrepareCommand.RaiseCanExecuteChanged();

    private void ShowError(Exception exception)
    {
        ErrorMessage = exception is RpcClientException
            ? "Lease Runtimeへ接続できません。サービスの状態を確認してください。\n" + exception.Message
            : exception.Message;
        if (CurrentPage == AppPage.Loading)
        {
            CurrentPage = AppPage.Unavailable;
        }
    }

    private async void CountdownTimerOnTick(object? sender, EventArgs eventArgs)
    {
        UpdateRemaining();
        if (_activeExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            _countdownTimer.Stop();
            try
            {
                await InitializeAsync().ConfigureAwait(true);
            }
            catch (Exception exception)
            {
                ShowError(exception);
            }
        }
    }

    private void UpdateRemaining()
    {
        if (_activeExpiresAtUtc is null)
        {
            RemainingText = string.Empty;
            return;
        }

        var remaining = _activeExpiresAtUtc.Value - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            RemainingText = "解除処理を確認中";
            return;
        }

        RemainingText = remaining.TotalHours >= 1
            ? $"{(int)remaining.TotalHours}時間 {remaining.Minutes}分"
            : $"{Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes))}分";
    }

    private enum AppPage
    {
        Loading,
        Setup,
        Confirmation,
        Active,
        Unavailable,
    }
}
