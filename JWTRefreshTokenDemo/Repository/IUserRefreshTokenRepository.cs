using JWTRefreshTokenDemo.Models;

namespace JWTRefreshTokenDemo.Repository;

public interface IUserRefreshTokenRepository
{

    Task AddUserRefreshTokenAsync(UserRefreshTokens user);

    Task UpdateUserRefreshTokenAsync(UserRefreshTokens userRefreshToken);
    Task DeleteUserRefreshTokensAsync(string id, string refreshToken);
    Task<UserRefreshTokens> GetSavedRefreshTokenAsync(string userId, Tokens token);
}
