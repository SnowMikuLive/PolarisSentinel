using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using PolarisSentinel.Web.Models;
using System.Threading.Tasks;

namespace PolarisSentinel.Web.Controllers
{
    public class AccountController : Controller
    {
        //Sign in manager for handling user authentication
        private readonly SignInManager<IdentityUser> _signInManager;

        //User manager for handling user management
        private readonly UserManager<IdentityUser> _userManager;

        public AccountController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        //Display the login page
        [HttpGet]
        //Allow Anonymous access to the login page
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        { 

            //Save the return URL in the ViewData dictionary to redirect the user after successful login
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        //Handle the login form submission
        [HttpPost]
        [AllowAnonymous]
        //Prevent Cross-Site Request Forgery (CSRF)
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            //Check model state
            if (ModelState.IsValid)
            {
                //Attempt to sign in,put '!' after model.Username and model.Password to avoid null reference exception
                var result = await _signInManager.PasswordSignInAsync(model.Username!, model.Password!, isPersistent: false, lockoutOnFailure: false);

                //successful
                if(result.Succeeded)
                {
                    TempData["success"] = "Login successful.";
                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                        return Redirect(returnUrl);
                    else
                        return RedirectToAction("Index", "Dashboard");
                }
                else
                {
                    //if login fails, the error message will be shown.
                    TempData["error"] = "Invalid username or password.";
                }

            }
            //Return Login view with the validation errors
            return View(model);
        }

        //Logout
        [HttpPost]
        //logout only can happen after login, anonymous access do not needed
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            //Sign out
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Dashboard");
        }
        
    }
}
