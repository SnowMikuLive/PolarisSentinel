using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using PolarisSentinel.DataAccess.Data;
using PolarisSentinel.Web.Controllers;
using PolarisSentinel.Web.Models;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class AccountPasswordTests
{
    [TestMethod]
    public async Task ChangePassword_ReusingCurrentPassword_ShouldReturnFormBeforeAccessingIdentity()
    {
        // Identity is deliberately unavailable: a rejected request must not change
        // the password or clear the account's MustChangePassword flag.
        var controller = new AccountController(
            null!,
            null!,
            Options.Create(new AdminSeedOptions()),
            new DefaultPasswordAttemptTracker());
        var model = new ChangePasswordViewModel
        {
            CurrentPassword = "Initial123!",
            NewPassword = "Initial123!",
            ConfirmPassword = "Initial123!"
        };

        var result = await controller.ChangePassword(model);

        Assert.IsInstanceOfType<ViewResult>(result);
        Assert.AreSame(model, ((ViewResult)result).Model);
        Assert.IsFalse(controller.ModelState.IsValid);
        Assert.HasCount(1, controller.ModelState[nameof(model.NewPassword)]!.Errors);
    }
}