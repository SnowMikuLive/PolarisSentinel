using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    // Isolated settings page: monitored NIC + detection thresholds + firewall.
    [Authorize]
    public class SettingsController : Controller
    {
        private readonly SettingsService _settings;
        private readonly CaptureControlService _capture;

        public SettingsController(SettingsService settings, CaptureControlService capture)
        {
            _settings = settings;
            _capture = capture;
        }

        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var settings = await _settings.GetForCurrentUserAsync(cancellationToken);

            ViewBag.Devices = _capture.GetDevices().ToList();
            ViewBag.CurrentDevice = _capture.CurrentDevice;
            ViewBag.UserId = _settings.CurrentUserId;
            return View(settings);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(
            UserSettings settings,
            string? deviceName,
            CancellationToken cancellationToken)
        {
            // 表单留空时模型绑定会把字符串置为 null，但列不允许为 null
            // Model binding sets empty text inputs to null, but the column is NOT NULL
            settings.Allowlist = settings.Allowlist?.Trim() ?? string.Empty;

            // Owner always comes from the signed-in user, never from the posted form.
            settings.UserId = _settings.CurrentUserId;

            if (!string.IsNullOrWhiteSpace(deviceName))
            {
                _capture.SwitchTo(deviceName);
            }

            await _settings.SaveForCurrentUserAsync(settings, cancellationToken);
            TempData["success"] = "Settings saved.";
            return RedirectToAction(nameof(Index));
        }
    }
}
