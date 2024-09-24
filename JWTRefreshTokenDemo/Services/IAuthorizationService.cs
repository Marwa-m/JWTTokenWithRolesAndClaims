using JWTRefreshTokenDemo.Helper;
using System.Security.Claims;

namespace JWTRefreshTokenDemo.Services
{
    public interface IAuthorizationService
    {
        Task<Result> AddRoleAsync(string roleName);
        Task<Result> DeleteRoleAsync(string roleName);
        Task<List<string>> GetRolesAsync();
        Task<Result> AddRoleToUserAsync(string userName, string roleName);
        Task<Result<List<string>>> GetUserRolesAsync(string userName);
        Task<Result> DeleteRoleFromUserAsync(string userName, string roleName);

        Task<Result<List<Claim>>> GetUserClaimsAsync(string userName);
        Task<Result> AddOrUpdateClaimToUserAsync(string userName, string claimType, string claimValue);
        Task<Result> DeleteClaimAsync(string username, string claimType);
    }
}
