using Microsoft.AspNetCore.Identity;

namespace PolarisSentinel.DataAccess.Data;

// Application user. Adds a forced password change flag on top of ASP.NET Identity.
public class ApplicationUser : IdentityUser
{
    public bool MustChangePassword { get; set; }
}
