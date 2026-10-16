using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class CaptureControlServiceTests
{
    [TestMethod]
    public void SwitchTo_StartFails_RestoresPreviousDevice()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devA");
        capture.AddDevice("devB");
        var service = Create(capture, out _);
        Assert.IsTrue(service.SwitchTo("devA").Success);

        capture.FailStartWithNotFound("devB");
        var result = service.SwitchTo("devB");

        Assert.AreEqual(CaptureSwitchStatus.DeviceNotFound, result.Status);
        Assert.AreEqual("devA", service.CurrentDevice);
        Assert.AreEqual("devA", capture.RunningDevice);
    }
    [TestMethod]
    public void SwitchTo_Success_PersistsChoice()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devA");
        var service = Create(capture, out var store);

        Assert.IsTrue(service.SwitchTo("devA").Success);

        Assert.AreEqual("devA", service.CurrentDevice);
        Assert.AreEqual("devA", store.Settings.CaptureDevice);
    }
    [TestMethod]
    public void GetDefaultDeviceName_SkipsLoopbackAndAddresslessAdapters()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("loopback", isLoopback: true);
        capture.AddDevice("noIp");
        capture.AddDevice("real", ip: "10.0.0.5");
        var service = Create(capture, out _);
        var devices = capture.GetAvailableDevices().ToList();

        Assert.AreEqual("real", service.GetDefaultDeviceName(devices));
    }
    private static CaptureControlService Create(FakeTrafficCaptureService capture, out FakeUserSettingsStore store)
    {
        store = new FakeUserSettingsStore();
        return new CaptureControlService(capture, NullLogger<CaptureControlService>.Instance, store);
    }

    private sealed class FakeUserSettingsStore : IUserSettingsStore
    {
        public UserSettings Settings { get; } = new();

        public UserSettings Read() => Settings;

        public void Update(Action<UserSettings> mutate) => mutate(Settings);
    }

    private sealed class FakeTrafficCaptureService : ITrafficCaptureService
    {
        private readonly List<NetworkInterfaceInfo> _devices = new();
        private readonly HashSet<string> _notFound = new();
        private readonly HashSet<string> _errors = new();

        public List<string> StartCalls { get; } = new();
        public int StopCalls { get; private set; }
        public string? RunningDevice { get; private set; }

        public event EventHandler<FlowFeatureVector>? OnFlowCompleted { add { } remove { } }
        public event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary { add { } remove { } }

        public void AddDevice(string name, string? displayName = null, string? ip = null, bool isLoopback = false) =>
            _devices.Add(new NetworkInterfaceInfo
            {
                DeviceName = name,
                DisplayName = displayName ?? name,
                IpAddress = ip,
                IsLoopback = isLoopback
            });

        public void FailStartWithNotFound(string name) => _notFound.Add(name);

        public void FailStartWithError(string name) => _errors.Add(name);

        public IEnumerable<NetworkInterfaceInfo> GetAvailableDevices() => _devices;

        public void Start(string deviceName)
        {
            StartCalls.Add(deviceName);
            if (_notFound.Contains(deviceName))
                throw new InvalidOperationException($"No capture device found with name '{deviceName}'.");
            if (_errors.Contains(deviceName))
                throw new IOException("device open failed");

            RunningDevice = deviceName;
        }

        public void Stop()
        {
            StopCalls++;
            RunningDevice = null;
        }
    }
}
