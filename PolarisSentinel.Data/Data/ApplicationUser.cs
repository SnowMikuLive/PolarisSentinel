using Microsoft.AspNetCore.Identity;

namespace PolarisSentinel.DataAccess.Data;

public class ApplicationUser : IdentityUser
{
    public bool MustChangePassword { get; set; }
}
