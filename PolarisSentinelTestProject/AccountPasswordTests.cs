using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Web.Controllers;
using PolarisSentinel.Web.Models;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class AccountPasswordTests
{
    [TestMethod]
    public async Task ChangePassword_ReusingCurrentPassword_ShouldReturnFormBeforeAccessingIdentity()
    {

        var controller = new AccountController(
            null!,
            null!);
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
