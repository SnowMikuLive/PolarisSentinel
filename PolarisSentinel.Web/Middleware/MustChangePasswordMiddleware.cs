using Microsoft.AspNetCore.Identity;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.Web.Middleware;

// Redirects an authenticated user who must change their password to the change-password
// page before any other page is reachable. Extracted from Program.cs so the composition
// root stays wiring-only and this security policy is testable in isolation.
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

    // Paths that must stay reachable so the user can actually change the password.
    private static bool IsAllowedPath(PathString path)
    {
        string value = path.Value ?? string.Empty;
        return value.StartsWith("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/Account/Logout", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/lib", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/css", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/js", StringComparison.OrdinalIgnoreCase);
    }
}
