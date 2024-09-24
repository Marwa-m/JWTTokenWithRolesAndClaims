using JWTRefreshTokenDemo.Helper;
using JWTRefreshTokenDemo.Models;
using JWTRefreshTokenDemo.ViewModels;

namespace JWTRefreshTokenDemo.Services
{
    public interface IUserService
    {
        Task<Result> AddUserAsync(ApplicationUser user, string password);
        Task<Dictionary<string, object>> GetClaimsAsync(string id);
        Task<bool> IsValidUserAsync(string email, string password);
        Task<ApplicationUser> GetUserByEmail(string email);
        Task<ApplicationUser> GetUserById(string id);
        Task<List<GetUserViewModel>> GetUsersAsync();
    }
}
