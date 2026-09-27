using Microsoft.AspNetCore.Identity;

namespace PolarisSentinel.DataAccess.Data;

// Application user. Adds a forced password change flag on top of ASP.NET Identity.
public class ApplicationUser : IdentityUser
{
    // When true, the user must change the password before using the application.
    public bool MustChangePassword { get; set; }
}
