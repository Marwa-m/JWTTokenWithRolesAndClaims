using JWTRefreshTokenDemo.Models;
using JWTRefreshTokenDemo.Repository;

namespace JWTRefreshTokenDemo.Services
{
    public class UserRefreshTokenService : IUserRefreshTokenService
    {
        private readonly IUserRefreshTokenRepository _userRefreshTokenRepository;

        public UserRefreshTokenService(IUserRefreshTokenRepository userRefreshTokenRepository)
        {
            _userRefreshTokenRepository = userRefreshTokenRepository;
        }
        public async Task<UserRefreshTokens> GetSavedRefreshTokens(string userId, Tokens token)
        {
            return await _userRefreshTokenRepository.GetSavedRefreshTokenAsync(userId, token);
        }

        public async Task UpdateUserRefreshTokens(UserRefreshTokens userRefreshTokens)
        {
            await _userRefreshTokenRepository.UpdateUserRefreshTokenAsync(userRefreshTokens);
        }
    }
}
