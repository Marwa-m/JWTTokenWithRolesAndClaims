using Microsoft.AspNetCore.Identity;

namespace JWTRefreshTokenDemo.Models;

public class ApplicationUser : IdentityUser
{
    public virtual ICollection<UserRefreshTokens> UserRefreshTokens { get; set; } = new List<UserRefreshTokens>();

}
