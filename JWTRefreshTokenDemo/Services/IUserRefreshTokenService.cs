using JWTRefreshTokenDemo.Models;

namespace JWTRefreshTokenDemo.Services
{
    public interface IUserRefreshTokenService
    {
        Task<UserRefreshTokens> GetSavedRefreshTokens(string userId, Tokens token);
        Task UpdateUserRefreshTokens(UserRefreshTokens userRefreshTokens);
    }
}
