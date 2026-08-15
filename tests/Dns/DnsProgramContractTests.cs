using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;
using DistractionFirewall.DnsFilter.Runtime;

namespace DistractionFirewall.DnsFilter.Tests;

public sealed class DnsFilterOptionsTests
{
    private static readonly DateTimeOffset ReferenceTime =
        new(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public void Production_contract_parses_all_fixed_arguments_and_repeatable_upstreams()
    {
        var options = DnsFilterOptions.Parse(
            CreateValidArguments(ReferenceTime.AddHours(2)),
            new FrozenTimeProvider(ReferenceTime));

        Assert.Equal(Guid.Parse("3a778ca3-8be5-409a-943f-f674a0bac777"), options.LeaseId);
        Assert.Equal(ReferenceTime.AddHours(2), options.LeaseExpiresUtc);
        Assert.Equal(Path.GetFullPath(TargetPath), options.TargetSnapshotPath);
        Assert.Equal(Path.GetFullPath(ObservationPath), options.ObservationStorePath);
        Assert.Equal(Enumerable.Range(0, 32).Select(value => (byte)value), options.ReadyToken.ToArray());
        Assert.Collection(
            options.Upstreams,
            endpoint => Assert.Equal(new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53), endpoint),
            endpoint => Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::53"), 53), endpoint));
    }

    [Theory]
    [InlineData(0.999, false)]
    [InlineData(1, true)]
    [InlineData(43200, true)]
    [InlineData(43200.001, false)]
    public void Deadline_must_be_between_one_second_and_twelve_hours_from_parse_time(
        double seconds,
        bool accepted)
    {
        var args = CreateValidArguments(ReferenceTime.AddSeconds(seconds));
        if (accepted)
        {
            var options = DnsFilterOptions.Parse(args, new FrozenTimeProvider(ReferenceTime));
            Assert.Equal(ReferenceTime.AddSeconds(seconds), options.LeaseExpiresUtc);
        }
        else
        {
            Assert.Throws<ArgumentException>(() =>
                DnsFilterOptions.Parse(args, new FrozenTimeProvider(ReferenceTime)));
        }
    }

    [Fact]
    public void Past_deadline_is_rejected_before_the_filter_can_bind_a_port()
    {
        Assert.Throws<ArgumentException>(() => DnsFilterOptions.Parse(
            CreateValidArguments(ReferenceTime.AddTicks(-1)),
            new FrozenTimeProvider(ReferenceTime)));
    }

    [Fact]
    public void Deadline_requires_exact_round_trip_format_with_zero_offset()
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1));
        ReplaceValue(args, "--lease-expires-utc", "2030-01-02T04:04:05.0000000+01:00");

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args, new FrozenTimeProvider(ReferenceTime)));
    }

    [Theory]
    [InlineData("--listen-port")]
    [InlineData("--targets")]
    [InlineData("--unknown")]
    public void Unknown_or_legacy_options_are_rejected_in_production_mode(string option)
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1)).ToList();
        args.Add(option);
        args.Add("value");

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args.ToArray(), new FrozenTimeProvider(ReferenceTime)));
    }

    [Fact]
    public void Singleton_options_cannot_be_repeated()
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1)).ToList();
        args.Add("--lease-id");
        args.Add("3a778ca3-8be5-409a-943f-f674a0bac777");

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args.ToArray(), new FrozenTimeProvider(ReferenceTime)));
    }

    [Theory]
    [InlineData("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")]
    [InlineData("abcdef")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public void Ready_token_requires_exactly_32_bytes_of_lower_case_hex(string token)
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1));
        ReplaceValue(args, "--ready-token", token);

        var exception = Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args, new FrozenTimeProvider(ReferenceTime)));
        Assert.DoesNotContain(token, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("dns.example")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("224.0.0.53")]
    [InlineData("ff02::53")]
    public void Upstream_requires_a_non_loopback_unicast_literal(string upstream)
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1));
        ReplaceValue(args, "--upstream", upstream);

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args, new FrozenTimeProvider(ReferenceTime)));
    }

    [Fact]
    public void Duplicate_upstreams_are_rejected()
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1)).ToList();
        args.Add("--upstream");
        args.Add("192.0.2.53");

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args.ToArray(), new FrozenTimeProvider(ReferenceTime)));
    }

    [Theory]
    [InlineData("relative.json")]
    [InlineData("%ProgramData%\\targets.json")]
    [InlineData("C:\\ProgramData\\bad\nname.json")]
    public void Data_paths_must_be_literal_and_fully_qualified(string path)
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1));
        ReplaceValue(args, "--target-snapshot", path);

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args, new FrozenTimeProvider(ReferenceTime)));
    }

    [Fact]
    public void Every_required_option_must_be_present()
    {
        var args = CreateValidArguments(ReferenceTime.AddHours(1)).ToList();
        var index = args.IndexOf("--observation-store");
        args.RemoveRange(index, 2);

        Assert.Throws<ArgumentException>(() =>
            DnsFilterOptions.Parse(args.ToArray(), new FrozenTimeProvider(ReferenceTime)));
    }

    private static string TargetPath =>
        Path.Combine(Path.GetTempPath(), "distraction-firewall", "targets.json");

    private static string ObservationPath =>
        Path.Combine(Path.GetTempPath(), "distraction-firewall", "observed-addresses.json");

    internal static string[] CreateValidArguments(DateTimeOffset expiration) =>
    [
        "dns-filter",
        "--lease-id",
        "3a778ca3-8be5-409a-943f-f674a0bac777",
        "--lease-expires-utc",
        expiration.ToString("O", CultureInfo.InvariantCulture),
        "--target-snapshot",
        TargetPath,
        "--observation-store",
        ObservationPath,
        "--ready-token",
        string.Concat(Enumerable.Range(0, 32).Select(value => value.ToString("x2", CultureInfo.InvariantCulture))),
        "--upstream",
        "192.0.2.53",
        "--upstream",
        "2001:db8::53",
    ];

    private static void ReplaceValue(string[] args, string option, string replacement)
    {
        var optionIndex = Array.IndexOf(args, option);
        Assert.True(optionIndex >= 0);
        args[optionIndex + 1] = replacement;
    }

    private sealed class FrozenTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}

public sealed class DnsReadyProbeContractTests
{
    [Fact]
    public async Task Exact_txt_sentinel_returns_token_derived_authoritative_answer_without_upstream_or_observation()
    {
        var token = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var upstream = new CountingUpstreamClient(CreateResponseHeader());
        var observer = new CountingObserver();
        var processor = CreateProcessor(upstream, observer, token);
        var query = CreateQuery(DnsReadyProbeProtocol.QuestionName, DnsReadyProbeProtocol.QuestionType);

        var response = await processor.ProcessAsync(query, CancellationToken.None).ConfigureAwait(true);

        Assert.Equal(0, upstream.CallCount);
        Assert.Equal(0, observer.CallCount);
        Assert.Equal(BinaryPrimitives.ReadUInt16BigEndian(query), BinaryPrimitives.ReadUInt16BigEndian(response));
        Assert.Equal(0x8400, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4, 2)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6, 2)));

        var offset = DnsMessageParser.HeaderLength;
        _ = DnsMessageParser.ReadName(response, ref offset);
        offset += 4;
        Assert.Equal(0xC00C, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset, 2)));
        Assert.Equal(DnsReadyProbeProtocol.QuestionType, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 2, 2)));
        Assert.Equal(DnsReadyProbeProtocol.QuestionClass, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 4, 2)));
        Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(offset + 6, 4)));
        Assert.Equal(65, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 10, 2)));
        Assert.Equal(64, response[offset + 12]);
        Assert.Equal(
            "02e96d8cf4bc8e7e06e4d1e7997190957e36a21e208c22250f7221ef58b7326a",
            Encoding.ASCII.GetString(response.AsSpan(offset + 13, 64)));
    }

    [Fact]
    public async Task Sentinel_with_any_other_type_never_receives_the_token_derived_answer()
    {
        var upstreamResponse = CreateResponseHeader();
        var upstream = new CountingUpstreamClient(upstreamResponse);
        var processor = CreateProcessor(upstream, new CountingObserver(), new byte[32]);

        var response = await processor
            .ProcessAsync(CreateQuery(DnsReadyProbeProtocol.QuestionName, type: 1), CancellationToken.None)
            .ConfigureAwait(true);

        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2)) & 0x000F);
        Assert.Equal(0, upstream.CallCount);
    }

    private static DnsQueryProcessor CreateProcessor(
        IDnsUpstreamClient upstream,
        ITargetAddressObserver observer,
        byte[] token) => new(
            new TargetMatcher([CreateTarget()]),
            [new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53)],
            observer,
            TimeSpan.FromSeconds(1),
            upstream,
            new DnsReadinessResponder(token));

    private static TargetDefinition CreateTarget() => new()
    {
        StableId = "ready-test",
        DisplayName = "Ready test",
        CatalogVersion = "1.0.0",
        ExactHosts = [],
        SuffixHosts = ["youtube.com"],
        CnameSuffixes = ["youtube.com"],
        BrowserUrlPatterns = [],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.Disabled,
        },
    };

    private static byte[] CreateQuery(string name, ushort type)
    {
        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[DnsMessageParser.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(header[..2], 0xA55A);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);
        stream.Write(header);
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte(checked((byte)bytes.Length));
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        Span<byte> tail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(tail[..2], type);
        BinaryPrimitives.WriteUInt16BigEndian(tail[2..], DnsReadyProbeProtocol.QuestionClass);
        stream.Write(tail);
        return stream.ToArray();
    }

    private static byte[] CreateResponseHeader()
    {
        var response = new byte[DnsMessageParser.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(0, 2), 0xA55A);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), 0x8180);
        return response;
    }

    private sealed class CountingUpstreamClient(byte[] response) : IDnsUpstreamClient
    {
        public int CallCount { get; private set; }

        public Task<byte[]> QueryAsync(
            byte[] query,
            IPEndPoint upstream,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(response);
        }
    }

    private sealed class CountingObserver : ITargetAddressObserver
    {
        public int CallCount { get; private set; }

        public ValueTask ObserveAsync(
            IReadOnlyList<DnsObservedAddress> addresses,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return ValueTask.CompletedTask;
        }
    }
}

public sealed class DnsObservationStoreContractTests
{
    [Fact]
    public async Task Observer_adapter_passes_lease_context_addresses_and_ttls_unchanged()
    {
        var context = new DnsObservationContext(
            Guid.Parse("3a778ca3-8be5-409a-943f-f674a0bac777"),
            new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero),
            Path.Combine(Path.GetTempPath(), "observed-addresses.json"));
        DnsObservedAddress[] addresses =
        [
            new(IPAddress.Parse("192.0.2.10"), 30),
            new(IPAddress.Parse("2001:db8::10"), 90),
        ];
        var store = new RecordingObservationStore();
        var observer = new ObservationStoreTargetAddressObserver(store, context);

        await observer.ObserveAsync(addresses, CancellationToken.None).ConfigureAwait(true);

        var append = Assert.Single(store.Appends);
        Assert.Equal(context, append.Context);
        Assert.Equal(addresses, append.Addresses);
    }

    private sealed class RecordingObservationStore : IDnsObservationStore
    {
        public ConcurrentQueue<AppendCall> Appends { get; } = new();

        public ValueTask AppendAsync(
            DnsObservationContext context,
            IReadOnlyList<DnsObservedAddress> addresses,
            CancellationToken cancellationToken)
        {
            Appends.Enqueue(new AppendCall(context, addresses.ToArray()));
            return ValueTask.CompletedTask;
        }
    }

    private sealed record AppendCall(
        DnsObservationContext Context,
        IReadOnlyList<DnsObservedAddress> Addresses);
}

public sealed class DnsFilterDeadlineTests
{
    private static readonly DateTimeOffset ReferenceTime =
        new(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public async Task Deadline_disposes_server_and_a_stale_restart_never_reacquires_the_port()
    {
        var directory = Path.Combine(Path.GetTempPath(), "df-dns-deadline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var snapshotPath = Path.Combine(directory, "targets.json");
            await File.WriteAllTextAsync(snapshotPath, TargetSnapshotJson).ConfigureAwait(true);
            var timeProvider = new ManualDeadlineTimeProvider(ReferenceTime);
            var expiration = ReferenceTime.AddMinutes(5);
            var args = DnsFilterOptionsTests.CreateValidArguments(expiration);
            ReplaceValue(args, "--target-snapshot", snapshotPath);
            ReplaceValue(args, "--observation-store", Path.Combine(directory, "observations.json"));
            var options = DnsFilterOptions.Parse(args, timeProvider);
            var serverFactory = new ExclusivePortServerFactory();
            var host = new DnsFilterHost(
                new RecordingObserverFactory(),
                serverFactory,
                timeProvider);

            var run = host.RunAsync(options, CancellationToken.None);
            await WaitForSignalOrRunFailureAsync(serverFactory.Started.Task, run).ConfigureAwait(true);
            Assert.True(serverFactory.PortHeld);

            await WaitForSignalOrRunFailureAsync(timeProvider.TimerScheduled.Task, run).ConfigureAwait(true);
            timeProvider.AdvanceTo(expiration);
            await run.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
            Assert.False(serverFactory.PortHeld);
            Assert.Equal(1, serverFactory.DisposeCount);

            await host.RunAsync(options, CancellationToken.None).ConfigureAwait(true);
            Assert.False(serverFactory.PortHeld);
            Assert.Equal(1, serverFactory.CreateCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task WaitForSignalOrRunFailureAsync(Task signal, Task run)
    {
        var completed = await Task.WhenAny(signal, run)
            .WaitAsync(TimeSpan.FromSeconds(5))
            .ConfigureAwait(true);
        if (ReferenceEquals(completed, run))
        {
            await run.ConfigureAwait(true);
            throw new InvalidOperationException("The DNS filter stopped before reaching the expected synchronization point.");
        }

        await signal.ConfigureAwait(true);
    }

    private static void ReplaceValue(string[] args, string option, string replacement)
    {
        var optionIndex = Array.IndexOf(args, option);
        Assert.True(optionIndex >= 0);
        args[optionIndex + 1] = replacement;
    }

    private sealed class RecordingObserverFactory : ITargetAddressObserverFactory
    {
        public ITargetAddressObserver Create(DnsObservationContext context) => new NullTargetAddressObserver();
    }

    private sealed class ExclusivePortServerFactory : IDnsFilterServerFactory
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool PortHeld { get; private set; }

        public int CreateCount { get; private set; }

        public int DisposeCount { get; private set; }

        public IDnsFilterServer Create(DnsQueryProcessor processor)
        {
            Assert.NotNull(processor);
            CreateCount++;
            return new ExclusivePortServer(this);
        }

        private sealed class ExclusivePortServer(ExclusivePortServerFactory owner) : IDnsFilterServer
        {
            private bool _started;

            public void Start()
            {
                Assert.False(owner.PortHeld);
                owner.PortHeld = true;
                _started = true;
                owner.Started.TrySetResult();
            }

            public ValueTask DisposeAsync()
            {
                if (_started)
                {
                    owner.PortHeld = false;
                }

                owner.DisposeCount++;
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class ManualDeadlineTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private readonly object _sync = new();
        private DateTimeOffset _utcNow = utcNow;
        private ManualTimer? _timer;

        public TaskCompletionSource TimerScheduled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override DateTimeOffset GetUtcNow()
        {
            lock (_sync)
            {
                return _utcNow;
            }
        }

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            ArgumentNullException.ThrowIfNull(callback);
            if (dueTime < TimeSpan.Zero && dueTime != Timeout.InfiniteTimeSpan)
            {
                throw new ArgumentOutOfRangeException(nameof(dueTime));
            }
            if (period != Timeout.InfiniteTimeSpan)
            {
                throw new NotSupportedException("The deadline test only supports one-shot timers.");
            }

            ManualTimer timer;
            lock (_sync)
            {
                if (_timer is not null)
                {
                    throw new InvalidOperationException("The deadline test only supports one active timer.");
                }

                var dueAtUtc = dueTime == Timeout.InfiniteTimeSpan
                    ? DateTimeOffset.MaxValue
                    : _utcNow + dueTime;
                timer = new ManualTimer(this, callback, state, dueAtUtc);
                _timer = timer;
            }

            TimerScheduled.TrySetResult();
            return timer;
        }

        public void AdvanceTo(DateTimeOffset utcNow)
        {
            ManualTimer? dueTimer = null;
            lock (_sync)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(utcNow, _utcNow);

                _utcNow = utcNow;
                if (_timer is not null && _timer.DueAtUtc <= utcNow)
                {
                    dueTimer = _timer;
                    _timer = null;
                }
            }

            dueTimer?.Fire();
        }

        private void Remove(ManualTimer timer)
        {
            lock (_sync)
            {
                if (ReferenceEquals(_timer, timer))
                {
                    _timer = null;
                }
            }
        }

        private sealed class ManualTimer(
            ManualDeadlineTimeProvider owner,
            TimerCallback callback,
            object? state,
            DateTimeOffset dueAtUtc) : ITimer
        {
            private int _completed;

            public DateTimeOffset DueAtUtc { get; } = dueAtUtc;

            public bool Change(TimeSpan dueTime, TimeSpan period) =>
                throw new NotSupportedException("The deadline test timer cannot be rescheduled.");

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _completed, 1) == 0)
                {
                    owner.Remove(this);
                }
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }

            public void Fire()
            {
                if (Interlocked.Exchange(ref _completed, 1) == 0)
                {
                    callback(state);
                }
            }
        }
    }

    private const string TargetSnapshotJson = """
        [
          {
            "stable_id": "youtube",
            "display_name": "YouTube",
            "catalog_version": "1.0.0",
            "exact_hosts": [],
            "suffix_hosts": ["youtube.com"],
            "cname_suffixes": ["youtube.com"],
            "browser_url_patterns": [],
            "ip_block_policy": {
              "mode": "disabled"
            },
            "known_collateral": [],
            "coverage": []
          }
        ]
        """;
}
