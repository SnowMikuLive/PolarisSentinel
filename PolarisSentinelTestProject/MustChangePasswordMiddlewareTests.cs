using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PolarisSentinel.DataAccess.Data;
using PolarisSentinel.Web.Middleware;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class MustChangePasswordMiddlewareTests
{
    [TestMethod]
    [DataRow("/api/detections/state", "GET")]
    [DataRow("/api/dashboard/model", "POST")]
    [DataRow("/api/dashboard/dryrun", "POST")]
    [DataRow("/API/capture/select", "POST")]
    [DataRow("/trafficHub/negotiate", "POST")]
    [DataRow("/trafficHub", "GET")]
    public async Task RequiredPasswordChange_BlocksApisAndHub(string path, string method)
    {
        using var users = new Users();
        using var services = new ServiceCollection().AddSingleton<UserManager<ApplicationUser>>(users).BuildServiceProvider();
        var context = Context(path, services);
        context.Request.Method = method;
        bool called = false;
        var middleware = new MustChangePasswordMiddleware(_ => { called = true; return Task.CompletedTask; });

        await middleware.InvokeAsync(context);

        Assert.IsFalse(called);
        Assert.AreEqual(403, context.Response.StatusCode);
        Assert.AreEqual(1, users.Reads);
        context.Response.Body.Position = 0;
        using var json = await System.Text.Json.JsonDocument.ParseAsync(context.Response.Body);
        Assert.AreEqual("password_change_required", json.RootElement.GetProperty("error").GetString());
        users.User.MustChangePassword = false;
        await middleware.InvokeAsync(Context(path, services));
        Assert.IsTrue(called, "The middleware must read the current flag after a successful change.");
    }

    [TestMethod]
    [DataRow("/Account/ChangePassword")]
    [DataRow("/Account/ChangePassword/example")]
    [DataRow("/Account/Logout")]
    [DataRow("/lib/jquery/jquery.min.js")]
    [DataRow("/css/site.css")]
    public async Task RequiredPasswordChange_PreservesAccountAndAssets(string path)
    {
        bool called = false;
        var middleware = new MustChangePasswordMiddleware(_ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(Context(path, new ServiceCollection().BuildServiceProvider()));
        Assert.IsTrue(called);
    }

    [TestMethod]
    [DataRow("/Dashboard")]
    [DataRow("/Account/ChangePasswordExtra")]
    public async Task RequiredPasswordChange_RedirectsPagesAndRejectsPrefixLookalikes(string path)
    {
        using var users = new Users();
        using var services = new ServiceCollection().AddSingleton<UserManager<ApplicationUser>>(users).BuildServiceProvider();
        var context = Context(path, services);
        bool called = false;
        await new MustChangePasswordMiddleware(_ => { called = true; return Task.CompletedTask; }).InvokeAsync(context);
        Assert.IsFalse(called);
        Assert.AreEqual(302, context.Response.StatusCode);
        Assert.AreEqual("/Account/ChangePassword", context.Response.Headers.Location.ToString());
    }

    [TestMethod]
    public async Task AnonymousLogin_RemainsAvailable()
    {
        bool called = false;
        var context = new DefaultHttpContext();
        context.Request.Path = "/Account/Login";
        await new MustChangePasswordMiddleware(_ => { called = true; return Task.CompletedTask; }).InvokeAsync(context);
        Assert.IsTrue(called);
    }

    private static DefaultHttpContext Context(string path, IServiceProvider services)
    {
        var context = new DefaultHttpContext { RequestServices = services,
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "admin") }, "test")) };
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private sealed class Users : UserManager<ApplicationUser>
    {
        public ApplicationUser User { get; } = new() { MustChangePassword = true };
        public int Reads { get; private set; }
        public Users() : base(new Store(), Microsoft.Extensions.Options.Options.Create(new IdentityOptions()), new PasswordHasher<ApplicationUser>(),
            Array.Empty<IUserValidator<ApplicationUser>>(), Array.Empty<IPasswordValidator<ApplicationUser>>(),
            new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!, NullLogger<UserManager<ApplicationUser>>.Instance) { }
        public override Task<ApplicationUser?> GetUserAsync(ClaimsPrincipal principal) { Reads++; return Task.FromResult<ApplicationUser?>(User); }
    }

    private sealed class Store : IUserStore<ApplicationUser>
    {
        public void Dispose() { }
        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(user.Id);
        public Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(user.UserName);
        public Task SetUserNameAsync(ApplicationUser user, string? name, CancellationToken ct) { user.UserName = name; return Task.CompletedTask; }
        public Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(user.NormalizedUserName);
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string? name, CancellationToken ct) { user.NormalizedUserName = name; return Task.CompletedTask; }
        public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(IdentityResult.Success);
        public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(IdentityResult.Success);
        public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(IdentityResult.Success);
        public Task<ApplicationUser?> FindByIdAsync(string id, CancellationToken ct) => Task.FromResult<ApplicationUser?>(null);
        public Task<ApplicationUser?> FindByNameAsync(string name, CancellationToken ct) => Task.FromResult<ApplicationUser?>(null);
    }
}
