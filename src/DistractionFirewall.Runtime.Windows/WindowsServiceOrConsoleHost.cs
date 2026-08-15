using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DistractionFirewall.Runtime.Windows;

public static class WindowsServiceOrConsoleHost
{
    public static Task<int> RunAsync(
        string serviceName,
        bool serviceMode,
        Func<CancellationToken, Task> runAsync,
        TextWriter? diagnosticWriter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        ArgumentNullException.ThrowIfNull(runAsync);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The runtime host requires Windows.");
        }

        return serviceMode
            ? Task.FromResult(RunService(
                serviceName,
                runAsync,
                diagnosticWriter ?? TextWriter.Null))
            : RunConsoleAsync(runAsync, diagnosticWriter ?? Console.Error);
    }

    private static int RunService(
        string serviceName,
        Func<CancellationToken, Task> runAsync,
        TextWriter diagnosticWriter)
    {
        using var runner = new NativeWindowsServiceRunner(serviceName, runAsync, diagnosticWriter);
        return runner.Run();
    }

    private static async Task<int> RunConsoleAsync(
        Func<CancellationToken, Task> runAsync,
        TextWriter diagnosticWriter)
    {
        using var shutdown = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            shutdown.Cancel();
        };
        EventHandler exitHandler = (_, _) => shutdown.Cancel();
        Console.CancelKeyPress += cancelHandler;
        AppDomain.CurrentDomain.ProcessExit += exitHandler;
        try
        {
            await runAsync(shutdown.Token).ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception exception)
        {
            await diagnosticWriter.WriteLineAsync(
                $"Runtime console host failed: {exception.GetType().Name}: {exception.Message}")
                .ConfigureAwait(false);
            return 1;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            AppDomain.CurrentDomain.ProcessExit -= exitHandler;
        }
    }

    private sealed class NativeWindowsServiceRunner : IDisposable
    {
        private const uint ErrorFailedServiceControllerConnect = 1063;
        private const uint ErrorServiceSpecificError = 1066;
        private readonly string _serviceName;
        private readonly Func<CancellationToken, Task> _runAsync;
        private readonly TextWriter _diagnosticWriter;
        private readonly ServiceMainDelegate _serviceMain;
        private readonly ServiceControlHandlerDelegate _controlHandler;
        private readonly CancellationTokenSource _shutdown = new();
        private nint _statusHandle;
        private uint _checkpoint;
        private int _exitCode;

        public NativeWindowsServiceRunner(
            string serviceName,
            Func<CancellationToken, Task> runAsync,
            TextWriter diagnosticWriter)
        {
            _serviceName = serviceName;
            _runAsync = runAsync;
            _diagnosticWriter = diagnosticWriter;
            _serviceMain = ServiceMain;
            _controlHandler = HandleControl;
        }

        public int Run()
        {
            ServiceTableEntry[] table =
            [
                new ServiceTableEntry(_serviceName, _serviceMain),
                new ServiceTableEntry(null, null),
            ];
            if (!StartServiceCtrlDispatcher(table))
            {
                var error = (uint)Marshal.GetLastPInvokeError();
                var message = error == ErrorFailedServiceControllerConnect
                    ? "The --service mode must be launched by the Windows Service Control Manager."
                    : new Win32Exception((int)error).Message;
                throw new InvalidOperationException(message);
            }

            return _exitCode;
        }

        public void Dispose()
        {
            _shutdown.Dispose();
        }

        private void ServiceMain(uint argumentCount, nint arguments)
        {
            _statusHandle = RegisterServiceCtrlHandlerEx(_serviceName, _controlHandler, nint.Zero);
            if (_statusHandle == nint.Zero)
            {
                _exitCode = 1;
                return;
            }

            SetStatus(ServiceState.StartPending, controlsAccepted: 0, waitHint: 30_000);
            try
            {
                SetStatus(
                    ServiceState.Running,
                    ServiceAccept.Stop | ServiceAccept.Shutdown,
                    waitHint: 0);
                _runAsync(_shutdown.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
                // Normal SCM stop/shutdown path.
            }
            catch (Exception exception)
            {
                _exitCode = 1;
                try
                {
                    _diagnosticWriter.WriteLine(
                        $"Windows Service host failed: {exception.GetType().Name}: {exception.Message}");
                }
                catch (ObjectDisposedException)
                {
                    // A service must still report STOPPED if its diagnostic sink is unavailable.
                }
            }
            finally
            {
                SetStatus(ServiceState.Stopped, controlsAccepted: 0, waitHint: 0);
            }
        }

        private uint HandleControl(uint control, uint eventType, nint eventData, nint context)
        {
            if (control is (uint)ServiceControl.Stop or (uint)ServiceControl.Shutdown)
            {
                SetStatus(ServiceState.StopPending, controlsAccepted: 0, waitHint: 30_000);
                _shutdown.Cancel();
            }

            return 0;
        }

        private void SetStatus(ServiceState state, ServiceAccept controlsAccepted, uint waitHint)
        {
            if (_statusHandle == nint.Zero)
            {
                return;
            }

            var pending = state is ServiceState.StartPending or ServiceState.StopPending;
            var status = new ServiceStatus
            {
                ServiceType = ServiceType.Win32OwnProcess,
                CurrentState = state,
                ControlsAccepted = controlsAccepted,
                Win32ExitCode = _exitCode == 0 ? 0u : ErrorServiceSpecificError,
                ServiceSpecificExitCode = (uint)_exitCode,
                CheckPoint = pending ? ++_checkpoint : 0,
                WaitHint = waitHint,
            };
            if (!SetServiceStatus(_statusHandle, ref status))
            {
                _exitCode = 1;
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void ServiceMainDelegate(uint argumentCount, nint arguments);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint ServiceControlHandlerDelegate(
            uint control,
            uint eventType,
            nint eventData,
            nint context);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private readonly struct ServiceTableEntry
        {
            public ServiceTableEntry(string? serviceName, ServiceMainDelegate? serviceMain)
            {
                ServiceName = serviceName;
                ServiceMain = serviceMain;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public readonly string? ServiceName;

            [MarshalAs(UnmanagedType.FunctionPtr)]
            public readonly ServiceMainDelegate? ServiceMain;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatus
        {
            public ServiceType ServiceType;
            public ServiceState CurrentState;
            public ServiceAccept ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
        }

        [Flags]
        private enum ServiceAccept : uint
        {
            Stop = 0x00000001,
            Shutdown = 0x00000004,
        }

        private enum ServiceControl : uint
        {
            Stop = 1,
            Shutdown = 5,
        }

        private enum ServiceState : uint
        {
            Stopped = 1,
            StartPending = 2,
            StopPending = 3,
            Running = 4,
        }

        private enum ServiceType : uint
        {
            Win32OwnProcess = 0x00000010,
        }

        [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool StartServiceCtrlDispatcher(
            [In] ServiceTableEntry[] serviceStartTable);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "RegisterServiceCtrlHandlerExW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern nint RegisterServiceCtrlHandlerEx(
            string serviceName,
            ServiceControlHandlerDelegate handler,
            nint context);

        [DllImport("advapi32.dll", EntryPoint = "SetServiceStatus", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetServiceStatus(nint statusHandle, ref ServiceStatus serviceStatus);
    }
}
