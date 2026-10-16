using Microsoft.AspNetCore.Identity;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.Web.Middleware;

public sealed class MustChangePasswordMiddleware
{
    private readonly RequestDelegate _next;

    public MustChangePasswordMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated == true && !IsAllowedPath(context.Request.Path))
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.GetUserAsync(context.User);
            if (user is { MustChangePassword: true })
            {
                context.Response.Redirect("/Account/ChangePassword");
                return;
            }
        }

        await _next(context);
    }

    private static bool IsAllowedPath(PathString path)
    {
        string value = path.Value ?? string.Empty;
        return value.StartsWith("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/Account/Logout", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/api", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/lib", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/css", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/js", StringComparison.OrdinalIgnoreCase);
    }
}
