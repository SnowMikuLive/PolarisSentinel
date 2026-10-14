using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject;

// Interface-selection logic: an unknown device must not tear down a working capture, and a
// failed switch must not leave the service reporting a device it is not actually capturing.
[TestClass]
public class CaptureControlServiceTests
{
    [TestMethod]
    public void SwitchTo_UnknownDevice_DoesNotStopCurrentCapture()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devA");
        capture.AddDevice("devB");
        var service = Create(capture, out _);

        Assert.IsTrue(service.SwitchTo("devA").Success);

        var result = service.SwitchTo("missing");

        Assert.AreEqual(CaptureSwitchStatus.DeviceNotFound, result.Status);
        Assert.AreEqual("devA", service.CurrentDevice);
        Assert.AreEqual("devA", capture.RunningDevice);
        Assert.AreEqual(1, capture.StopCalls);
    }

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
    public void SwitchTo_StartErrorWithNoPrevious_ReportsStopped()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devX");
        capture.FailStartWithError("devX");
        var service = Create(capture, out _);

        var result = service.SwitchTo("devX");

        Assert.AreEqual(CaptureSwitchStatus.Failed, result.Status);
        Assert.IsNull(service.CurrentDevice);
        Assert.IsNull(capture.RunningDevice);
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
    public void AutoStart_DoesNotPersist_ButPrefersSavedDevice()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devA");
        capture.AddDevice("devB");
        var service = Create(capture, out var store);
        store.Settings.CaptureDevice = "devB";

        service.AutoStart();

        Assert.AreEqual("devB", service.CurrentDevice);
        Assert.AreEqual("devB", store.Settings.CaptureDevice);
    }

    [TestMethod]
    public void GetDefaultDeviceName_PrefersSavedThenFirst()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devA");
        capture.AddDevice("devB");
        var service = Create(capture, out var store);
        var devices = capture.GetAvailableDevices().ToList();

        Assert.AreEqual("devA", service.GetDefaultDeviceName(devices));

        store.Settings.CaptureDevice = "devB";
        Assert.AreEqual("devB", service.GetDefaultDeviceName(devices));
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

    [TestMethod]
    public void GetDefaultDeviceName_SavedDisplayName_ResolvesToDeviceName()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("\\Device\\NPF_{AAA}", displayName: "Ethernet");
        capture.AddDevice("\\Device\\NPF_{BBB}", displayName: "Wi-Fi");
        var service = Create(capture, out var store);
        store.Settings.CaptureDevice = "wi-fi";
        var devices = capture.GetAvailableDevices().ToList();

        Assert.AreEqual("\\Device\\NPF_{BBB}", service.GetDefaultDeviceName(devices));
    }

    [TestMethod]
    public void SwitchTo_MatchesByDeviceName_CaseInsensitive_AndNormalises()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("\\Device\\NPF_{AAA}", displayName: "Ethernet");
        var service = Create(capture, out _);

        var result = service.SwitchTo("\\device\\npf_{aaa}");

        Assert.IsTrue(result.Success);
        Assert.AreEqual("\\Device\\NPF_{AAA}", service.CurrentDevice);
        Assert.AreEqual("\\Device\\NPF_{AAA}", capture.RunningDevice);
    }

    [TestMethod]
    public void SwitchTo_UnknownDevice_DoesNotEnumerateThenStop()
    {
        var capture = new FakeTrafficCaptureService();
        capture.AddDevice("devA");
        var service = Create(capture, out _);
        Assert.IsTrue(service.SwitchTo("devA").Success);

        var result = service.SwitchTo("devB");

        Assert.AreEqual(CaptureSwitchStatus.DeviceNotFound, result.Status);
        Assert.AreEqual("devA", service.CurrentDevice);
        Assert.AreEqual("devA", capture.RunningDevice);
        Assert.AreEqual(1, capture.StopCalls);
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
