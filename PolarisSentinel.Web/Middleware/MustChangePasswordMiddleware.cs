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
                if (context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase) ||
                    context.Request.Path.StartsWithSegments("/trafficHub", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsJsonAsync(new { error = "password_change_required", changePasswordUrl = "/Account/ChangePassword" });
                }
                else
                {
                    context.Response.Redirect("/Account/ChangePassword");
                }
                return;
            }
        }

        await _next(context);
    }

    private static bool IsAllowedPath(PathString path)
    {
        return path.StartsWithSegments("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/Account/Logout", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/lib", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/css", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/js", StringComparison.OrdinalIgnoreCase);
    }
}
