using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    // Isolated settings page: timezone + monitored NIC + policy settings.
    [Authorize]
    public class SettingsController : Controller
    {
        private readonly SettingsService _settings;
        private readonly CaptureControlService _capture;
        private readonly IOptionsMonitor<Policy> _policySettings;
        private readonly IOptionsMonitor<FirewallOptions> _firewallOptions;

        public SettingsController(
            SettingsService settings,
            CaptureControlService capture,
            IOptionsMonitor<Policy> policySettings,
            IOptionsMonitor<FirewallOptions> firewallOptions)
        {
            _settings = settings;
            _capture = capture;
            _policySettings = policySettings;
            _firewallOptions = firewallOptions;
        }

        public IActionResult Index()
        {
            ViewBag.TimeZones = SettingsService.AvailableTimeZones;
            ViewBag.CurrentTimeZone = _settings.TimeZoneId;
            ViewBag.Devices = _capture.GetDevices().ToList();
            ViewBag.CurrentDevice = _capture.CurrentDevice;
            ViewBag.Firewall = _firewallOptions.CurrentValue;
            return View(_policySettings.CurrentValue);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Save(string timeZoneId, string deviceName, Policy policy, FirewallOptions firewall)
        {
            if (!_settings.SetTimeZone(timeZoneId))
            {
                TempData["error"] = "Invalid time zone.";
                return RedirectToAction(nameof(Index));
            }

            if (!string.IsNullOrWhiteSpace(deviceName))
            {
                _capture.SwitchTo(deviceName);
            }

            _settings.SavePolicySettings(policy);
            _settings.SaveFirewallOptions(firewall);
            TempData["success"] = "Settings saved.";
            return RedirectToAction(nameof(Index));
        }
    }
}
