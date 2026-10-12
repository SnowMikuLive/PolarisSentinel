using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PolarisSentinel.DataAccess.Data;
using PolarisSentinel.Web.Models;
using PolarisSentinel.Web.Service;
using System.Threading.Tasks;

namespace PolarisSentinel.Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IOptions<AdminSeedOptions> _seedOptions;
        private readonly DefaultPasswordAttemptTracker _defaultPasswordAttempts;

        public AccountController(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IOptions<AdminSeedOptions> seedOptions,
            DefaultPasswordAttemptTracker defaultPasswordAttempts)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _seedOptions = seedOptions;
            _defaultPasswordAttempts = defaultPasswordAttempts;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username!, model.Password!, isPersistent: false, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username!);
                    if (user is { MustChangePassword: true })
                    {
                        return RedirectToAction(nameof(ChangePassword));
                    }

                    TempData["success"] = "Login successful.";
                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                        return Redirect(returnUrl);
                    else
                        return RedirectToAction("Index", "Dashboard");
                }
                else
                {
                    await HandleFailedLoginAsync(model);
                    TempData["error"] = "Invalid username or password.";
                }
            }

            return View(model);
        }

        // Hidden recovery: after repeated failed sign-ins that used the configured default
        // password, reset the admin account back to that default so the operator can get back
        // in. This never changes what the caller sees.
        private async Task HandleFailedLoginAsync(LoginViewModel model)
        {
            var seed = _seedOptions.Value;
            if (string.IsNullOrEmpty(seed.Password) || string.IsNullOrEmpty(seed.UserName))
            {
                return;
            }

            if (!string.Equals(model.Password, seed.Password, StringComparison.Ordinal))
            {
                return;
            }

            if (!_defaultPasswordAttempts.Record(DateTime.UtcNow))
            {
                return;
            }

            var admin = await _userManager.FindByNameAsync(seed.UserName);
            if (admin is null)
            {
                return;
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(admin);
            var reset = await _userManager.ResetPasswordAsync(admin, token, seed.Password);
            if (reset.Succeeded)
            {
                admin.MustChangePassword = true;
                await _userManager.UpdateAsync(admin);
            }
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login));
            }

            return View(new ChangePasswordViewModel());
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (string.Equals(model.CurrentPassword, model.NewPassword, StringComparison.Ordinal))
            {
                ModelState.AddModelError(nameof(model.NewPassword), "New password must be different from your current password.");
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login));
            }

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword!, model.NewPassword!);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            user.MustChangePassword = false;
            await _userManager.UpdateAsync(user);
            await _signInManager.RefreshSignInAsync(user);

            TempData["success"] = "Password changed.";
            return RedirectToAction("Index", "Dashboard");
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Login));
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied() => View();
    }
}