using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using PolarisSentinel.DataAccess.Data;
using PolarisSentinel.Web.Models;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace PolarisSentinel.Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
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
                    // A seeded account must change its password before anything else.
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
                    TempData["error"] = "Invalid username or password.";
                }
            }

            return View(model);
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

        //1. Post /Account /ForgotPassword
        //Receive email/username from the login-page modal, gengerates a reset token,
        //and passes it to the confirmation page via TempData (prototype: no e-mail is sent).
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                //if Validation failed: send back to the conformation page with an error hint
                TempData["error"] = "Please enter a valid email or username.";
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            //look up by e-mail first, fall back to username
            var user = await _userManager.FindByEmailAsync(model.EmailOrUserName!)
                    ?? await _userManager.FindByNameAsync(model.EmailOrUserName!);

            //User missing or email not confirmed: avoid account enumeration, go to confirmation
            if (user == null)
            {
                TempData["error"] = "No matching account found.";
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            //Generate the Identity password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            //The token conatains Url-unsafe characters(+ / =), so Base64Url-encode it, and change them to safe characters.
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            //Build the reset link and stash it in TempData (visible only on the next request)
            var resetLink = Url.Action(
                "ResetPassword",
                "Account",
                new { email = user.Email, code = encodedToken },
                Request.Scheme);

            TempData["ResetLink"] = resetLink;
            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        //2. Get /Account /ForgotPasswordConfirmation
        //Shows the reset link (prototype only; production should deliver it by email.
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //3. Get /Account/ResetPassword
        //The user lands here after clicking the reset link, to enter a new password
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string? email, string? code)
        {
            if (string.IsNullOrEmpty(email)||string.IsNullOrEmpty(code))
            {
                return BadRequest("Invalid password reset request.");
            }

            var model = new ResetPasswordViewModel
            {
                Email=email,
                Code=code
            };
            return View(model);
        }

        //4. POST /Account/ResetPassword
        // Submit the new password and call Identity's reset API
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email!);
            if (user==null)
            {
                //Do not reveal whether the account exists; go straight to confirmation
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }

            //Decode the Base64Url token
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Code!));

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword!);
            if(result.Succeeded)
            {
                //After a self-service reset, the forced first-login change is no Longer needed
                user.MustChangePassword = false;
                await _userManager.UpdateAsync(user);

                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        //5. Get /Account/ResetPasswordConfirmation
        // Confirmation page shown after a successful reset.
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }








        //[HttpGet]
        //[AllowAnonymous]
        //public IActionResult AccessDenied()
        //{
        //    return View();
        //}
    }
}
